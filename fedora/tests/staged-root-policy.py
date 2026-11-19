#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Staged root policy tests; only a tiny synthetic ext4 is packed."""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

FEDORA = Path(__file__).resolve().parent.parent
CHECK = [sys.executable, "-I", str(FEDORA / "staged-root-policy.py")]


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def require(args, code, diagnostic=""):
    proc = subprocess.run(args, text=True, capture_output=True)
    assert proc.returncode == code and diagnostic in proc.stderr, (
        args,
        proc.returncode,
        proc.stdout,
        proc.stderr,
    )


def fixtures(root):
    write(root, "etc/machine-id", "")
    extra = "cubie_a7a.hat=0 systemd.volatile=overlay"
    grub = write(root, "etc/default/grub", f'GRUB_CMDLINE_LINUX="{extra}"\n')
    cmdline = write(root, "etc/kernel/cmdline", extra + "\n")
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
        ("", "Fedora (protective: ro overlay, hat=0)", "ro " + extra),
        ("~maintenance", "Fedora maintenance (rw, hat=0)", "ro cubie_a7a.hat=0"),
        ("~full", "Fedora full (rw, HAT on)", "ro"),
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


def cases(work, base):
    root = work / "root"
    options, env = fixtures(root)
    staged = [*CHECK, "staged", str(root)]
    protective = [*staged, "--default-args", options]
    require(staged, 0)
    require(protective, 0)
    for rel, content in (
        ("etc/ssh/ssh_host_fixture_key", "synthetic"),
        ("root/.ssh/authorized_keys", "synthetic"),
        ("etc/NetworkManager/conf.d/injected.conf", "managed=false\n"),
        ("etc/udev/rules.d/89-test.rules", "ENV{NM_UNMANAGED}=1\n"),
        ("etc/NetworkManager/system-connections/test", "type=wifi\n"),
        (".autorelabel", ""),
        ("var/lib/systemd/random-seed", "synthetic"),
    ):
        path = write(root, rel, content)
        require(staged, 1, rel)
        path.unlink()
    machine = write(root, "etc/machine-id", "booted\n")
    require(staged, 1, "etc/machine-id")
    machine.write_text("")
    subprocess.run(
        ["grub2-editenv", str(env), "set", "next_entry=entry~maintenance"], check=True
    )
    require(protective, 1, "unexpected next_entry")
    require([*protective, "--first-boot", "maintenance"], 0)
    bls = root / "boot/loader/entries/entry~full.conf"
    bls.write_text(bls.read_text().replace("options ro", "options ro cubie_a7a.hat=0"))
    require([*protective, "--first-boot", "maintenance"], 1, "invalid protective")
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
    if base:
        original = base.read_text()
        assert (
            'check-sshd.sh" "$ROOT"' not in original
            and "security.capability" not in original
        )
        print("base staging omitted target sshd and packed capability checks")
    print(
        "final root policy, protective state, capability and build-path checks passed"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="a7a-root-policy-") as tmp:
        cases(Path(tmp), args.base)
