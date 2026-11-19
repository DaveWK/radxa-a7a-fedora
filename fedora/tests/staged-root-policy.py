#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Staged root policy tests; only a tiny synthetic ext4 is packed."""

import hashlib
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

FEDORA = Path(__file__).resolve().parent.parent
CHECK = [sys.executable, "-I", str(FEDORA / "staged-root-policy.py")]
UUID = "11111111-2222-3333-4444-555555555555"
ESP = "1234-ABCD"
PASSWORD = "$6$synthetic$fixture"
BASE = f"root=UUID={UUID} ro"


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def require(args, code, diagnostic="", *, data=None):
    proc = subprocess.run(args, text=True, capture_output=True, input=data)
    assert PASSWORD not in proc.stderr + proc.stdout, "password output"
    assert proc.returncode == code and diagnostic in proc.stderr, (
        args,
        proc.returncode,
        proc.stdout,
        proc.stderr,
    )


def fixtures(root):
    write(root, "etc/machine-id", "")
    extra = "cubie_a7a.hat=0 systemd.volatile=overlay rootflags=noload"
    grub = write(root, "etc/default/grub", f'GRUB_CMDLINE_LINUX="{extra}"\n')
    cmdline = write(root, "etc/kernel/cmdline", f"{BASE} {extra}\n")
    now = grub.stat().st_mtime_ns + 1_000_000_000
    os.utime(cmdline, ns=(now, now))
    helper = write(root, "usr/local/bin/cubie-a7a-bootmode", "#!/bin/sh\n")
    helper.chmod(0o755)
    plugin = write(
        root,
        "etc/kernel/install.d/96-cubie-a7a-bootmodes.install",
        f"/{helper.relative_to(root)} sync\n",
    )
    plugin.chmod(0o755)
    for mode, action in (("ro", "boot"), ("next", "consume-next")):
        name = f"cubie-a7a-bootmode-{mode}.service"
        write(
            root,
            f"etc/systemd/system/{name}",
            f"ConditionKernelCommandLine=!systemd.volatile=overlay\nExecStart=/{helper.relative_to(root)} {action}\n",
        )
        link = root / "etc/systemd/system/sysinit.target.wants" / name
        link.parent.mkdir(exist_ok=True)
        link.symlink_to(f"../{name}")
    for unit in (
        "systemd-repart.service",
        "systemd-repart@.service",
        "systemd-growfs-root.service",
    ):
        (root / "etc/systemd/system" / unit).symlink_to("/dev/null")
    write(
        root,
        "etc/fstab",
        f"UUID={UUID} / ext4 defaults 1 1\nUUID={ESP} /boot/efi vfat defaults 0 2\n",
    )
    write(
        root,
        "etc/shadow",
        f"root:{PASSWORD}:1:0:99999:7:::\ndaemon:!*:1:0:99999:7:::\n",
    )
    write(
        root,
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:2:2:daemon:/:/sbin/nologin\n",
    )
    write(root, "boot/vmlinuz-fixture", "kernel fixture\n")
    write(root, "boot/initramfs-fixture.img", "initramfs fixture\n")
    for name in (
        "cubie-a7a-dtb.service",
        "systemd-repart.service",
        "systemd-growfs-root.service",
    ):
        write(root, "usr/lib/systemd/system/" + name, "[Unit]\n")
    (root / "usr/lib/modules/fixture").mkdir(parents=True)
    write(
        root,
        "boot/grub2/grub.cfg",
        'set default="${next_entry}"\n   save_env next_entry\n',
    )
    for mode, title, opts in (
        ("", "Fedora (protective: ro overlay, hat=0)", f"{BASE} {extra}"),
        ("~maintenance", "Fedora maintenance (rw, hat=0)", f"{BASE} cubie_a7a.hat=0"),
        ("~full", "Fedora full (rw, HAT on)", BASE),
    ):
        write(
            root,
            f"boot/loader/entries/entry{mode}.conf",
            f"title {title}\nversion fixture\nlinux /boot/vmlinuz-fixture\ninitrd /boot/initramfs-fixture.img\noptions {opts}\n",
        )
    env = root / "boot/grub2/grubenv"
    subprocess.run(["grub2-editenv", str(env), "create"], check=True)
    subprocess.run(["grub2-editenv", str(env), "set", "saved_entry=entry"], check=True)
    return extra, env


def cases(work):
    root = work / "root"
    options, env = fixtures(root)
    expected = work / "expected"
    shutil.copytree(root, expected, symlinks=True)
    kernel = root / "boot/vmlinuz-fixture"
    write(
        expected,
        "vmlinuz-fixture.sha256",
        hashlib.sha256(kernel.read_bytes()).hexdigest(),
    )
    kernels = write(work, "kernel.txt", "fixture\n")
    staged = [
        *CHECK,
        "staged",
        str(root),
        str(expected),
        str(kernels),
        UUID,
        options,
        "entry",
    ]

    def preboot(code, diagnostic=""):
        require(staged, code, diagnostic, data=PASSWORD + "\n")

    preboot(0)
    dbus_id = write(root, "var/lib/dbus/machine-id", "stale-fixture-id\n")
    preboot(1, "var/lib/dbus/machine-id")
    dbus_id.unlink()
    for target in ("/etc/machine-id", "../../../etc/machine-id"):
        dbus_id.symlink_to(target)
        preboot(0)
        dbus_id.unlink()
    dbus_id.symlink_to("/elsewhere/machine-id")
    preboot(1, "var/lib/dbus/machine-id")
    dbus_id.unlink()

    policy = runpy.run_path(str(FEDORA / "staged-root-policy.py"))
    real_scandir = os.scandir
    for relative in ("etc/ssh", "root/.ssh"):
        blocked = root / relative
        blocked.mkdir(parents=True, exist_ok=True)

        def scandir(path):
            if Path(path) == blocked:
                raise PermissionError("fixture directory scan refused")
            return real_scandir(path)

        with patch.object(os, "scandir", scandir):
            try:
                policy["first_boot"](root)
            except policy["PolicyError"] as exc:
                assert f"{relative}: cannot scan staged directory" in str(exc), exc
            else:
                raise AssertionError(f"{relative}: scan error was accepted")
    preboot(0)
    fstab = (root / "etc/fstab").read_text()
    mutations = (
        (
            "etc/fstab",
            fstab.replace("ext4 defaults", "ext4 defaults,x-systemd.growfs"),
            "etc/fstab: differs",
        ),
        ("etc/fstab", fstab.replace(UUID, "changed-root"), "etc/fstab: differs"),
        ("etc/fstab", fstab.replace("/boot/efi", "/mnt/esp"), "etc/fstab: differs"),
        (
            "etc/fstab",
            fstab.replace("ext4 defaults", "ext4 defaults,x-systemd.makefs"),
            "etc/fstab: differs",
        ),
        (
            "usr/local/lib/repart.d/50-root.conf",
            "[Partition]\nType=root\n",
            "unexpected repart.d config",
        ),
        ("etc/machine-id", "booted\n", "etc/machine-id"),
        ("etc/ssh/ssh_host_fixture_key", "synthetic", "etc/ssh/ssh_host_fixture_key"),
        ("root/.ssh/authorized_keys", "synthetic", "root/.ssh/authorized_keys"),
        (
            "etc/NetworkManager/conf.d/injected.conf",
            "managed=false\n",
            "etc/NetworkManager/conf.d/injected.conf",
        ),
        (
            "etc/udev/rules.d/89-test.rules",
            "ENV{NM_UNMANAGED}=1\n",
            "etc/udev/rules.d/89-test.rules",
        ),
        (
            "etc/NetworkManager/system-connections/test",
            "type=ethernet\n",
            "etc/NetworkManager/system-connections/test",
        ),
        (
            "etc/wpa_supplicant/wpa_supplicant.conf",
            "network = {\n}\n",
            "etc/wpa_supplicant/",
        ),
        (".autorelabel", "", ".autorelabel"),
        ("var/lib/systemd/random-seed", "synthetic", "var/lib/systemd/random-seed"),
        ("etc/shadow", "root:!:0:0:0:0:::\n", "etc/shadow"),
        (
            "etc/shadow",
            f"root:{PASSWORD}:0:0:0:0:::\nother::0:0:0:0:::\n",
            "etc/shadow",
        ),
        (
            "etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:human:/home/user:/bin/sh\n",
            "etc/passwd",
        ),
        ("boot/vmlinuz-fixture", "replacement kernel\n", "vmlinuz digest"),
        ("boot/loader/entries/extra.conf", "unexpected\n", "three entries"),
        (
            "etc/systemd/system/cubie-a7a-bootmode-next.service",
            "changed service\n",
            "changed since build staging",
        ),
    )
    for rel, content, diagnostic in mutations:
        path = root / rel
        old = path.read_bytes() if path.exists() else None
        write(root, rel, content)
        preboot(1, diagnostic)
        if old is None:
            path.unlink()
        else:
            path.write_bytes(old)
    mask = root / "etc/systemd/system/systemd-repart@.service"
    mask.unlink()
    mask.symlink_to("../../dev/null")
    preboot(1, "expected an exact /dev/null mask")
    mask.unlink()
    mask.symlink_to("/dev/null")
    for setting, diagnostic in (
        ("saved_entry=entry~maintenance", "saved_entry is not"),
        ("next_entry=entry~maintenance", "unexpected next_entry"),
        ("blsdir=/alternate/entries", "differs from the build-generated block"),
        ("other_setting=changed", "differs from the build-generated block"),
    ):
        old = env.read_bytes()
        subprocess.run(["grub2-editenv", str(env), "set", setting], check=True)
        preboot(1, diagnostic)
        env.write_bytes(old)
    bls = root / "boot/loader/entries/entry.conf"
    original = bls.read_text()
    for before, after, diagnostic in (
        ("rootflags=noload", "", "BLOCKED"),
        (f"root=UUID={UUID}", "root=UUID=wrong", "invalid protective"),
        (" ro ", " rw ", "invalid protective"),
        (
            "initramfs-fixture.img",
            "initramfs-other.img",
            "not the build kernel/initramfs",
        ),
    ):
        bls.write_text(original.replace(before, after))
        preboot(1, diagnostic)
    bls.write_text(original)
    preboot(0)
    overlay = work / "overlay"
    overlay.mkdir()
    require([*CHECK, "overlay", str(overlay)], 0)
    write(overlay, "opt/ordinary-file", "unrelated")
    require([*CHECK, "overlay", str(overlay)], 0)
    for name in (
        "etc/systemd/system.control/fixture.conf",
        "etc/cubie-a7a/bootmodes.conf",
        "usr/lib/systemd/system/fixture.timer",
        "run/systemd/transient/fixture.service",
        "usr/lib/systemd/system-generators/fixture",
        "boot/grub2/custom.cfg",
        "boot/loader/entries/fixture.conf",
        "etc/crypttab",
        "etc/fstab",
    ):
        with tempfile.TemporaryDirectory(dir=work) as tmp:
            write(Path(tmp), name, "synthetic")
            require(
                [*CHECK, "overlay", tmp],
                1,
                "protective overlay writes boot-control input",
            )

    image = work / "fixture.ext4"
    caproot = work / "caps"
    write(caproot, "usr/sbin/arping", "synthetic\n")
    if image.exists():
        raise AssertionError("non-fresh ext4 fixture")
    subprocess.run(
        ["mkfs.ext4", "-q", "-d", str(caproot), str(image), "4M"],
        check=True,
        capture_output=True,
    )
    require([*CHECK, "packed", str(image)], 1, "version-2 security.capability")
    with image.open("wb") as stream:
        stream.truncate(0)
    subprocess.run(
        [
            "unshare",
            "--map-root-user",
            "--",
            "sh",
            "-ec",
            'setcap cap_net_raw+p "$1/usr/sbin/arping"; mkfs.ext4 -q -d "$1" "$2" 4M',
            "sh",
            str(caproot),
            str(image),
        ],
        check=True,
        capture_output=True,
    )
    require([*CHECK, "packed", str(image)], 0)
    stage = (FEDORA / "mkdevcard.sh").read_text()
    assert (
        stage.index('cp -a --no-preserve=ownership "$OVERLAY"')
        < stage.index('check-sshd.sh" "$ROOT"')
        < stage.index("\nSTAGE1\n")
    )
    assert stage.index('check-sshd.sh" "$ROOT"') < stage.index(
        'staged-root-policy.py" staged'
    )
    assert stage.index("mkfs.ext4 -q") < stage.index('staged-root-policy.py" packed')
    ssh = (FEDORA / "check-sshd.sh").read_text()
    assert "sshd -h" in ssh and "-T -C" in ssh and "passwd-sole-root" in ssh
    print(
        "final root policy, protective state, capability and build-path checks passed"
    )


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="a7a-root-policy-") as tmp:
        cases(Path(tmp))
