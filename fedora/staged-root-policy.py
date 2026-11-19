#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Final staged-root policy and two targeted checks on the packed root FS."""

import argparse
import hashlib
import hmac
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from runpy import run_path

account_policy = run_path(str(Path(__file__).with_name("devcard-policy.py")))
passwd_sole_root = account_policy["passwd_sole_root"]
shadow_fields = account_policy["shadow_fields"]
from staged_paths import physical, walk


class PolicyError(RuntimeError):
    pass


def regular(root, relative):
    path = physical(root, relative)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise PolicyError(f"{relative}: expected a regular file")
    return path


def absent_glob(root, directory, pattern):
    directory = optional_dir(root, directory)
    if directory is None:
        return
    for entry in directory.glob(pattern):
        raise PolicyError(f"unexpected staged entry: {entry.relative_to(root)}")


def absent_text(root, roots, regex, skip=None):
    for name in roots:
        path = physical(root, name, missing=True)
        if path is None:
            continue
        for entry in walk(path):
            if entry.name == skip:
                continue
            rel = entry.relative_to(root)
            if entry.is_symlink():
                raise PolicyError(f"{rel}: unexpected symlink in Wi-Fi policy")
            if stat.S_ISREG(entry.lstat().st_mode) and regex.search(
                entry.read_text(errors="replace")
            ):
                raise PolicyError(f"{rel}: forbidden Wi-Fi policy {regex.pattern!r}")


def optional_dir(root, relative):
    path = physical(root, relative, missing=True)
    if path is not None and not stat.S_ISDIR(path.lstat().st_mode):
        raise PolicyError(f"{relative}: expected a real directory")
    return path


def first_boot(root):
    # Plain initial identity state only, not the identity generated on boot.
    for directory, pattern in (
        ("etc/ssh", "ssh_host_*"),
        ("root/.ssh", "authorized_keys*"),
    ):
        absent_glob(root, directory, pattern)
    for name in (".autorelabel", "var/lib/systemd/random-seed"):
        if physical(root, name, missing=True) is not None:
            raise PolicyError(f"unexpected first-boot state: {name}")
    if regular(root, "etc/machine-id").stat().st_size:
        raise PolicyError("etc/machine-id is not empty for first boot")


def wifi(root):
    # No persisted connection profiles or wpa_supplicant network blocks; not live policy.
    absent_glob(root, "etc/NetworkManager/system-connections", "*")
    absent_text(
        root,
        ("etc/wpa_supplicant", "etc/wpa_supplicant.conf"),
        re.compile(r"^[ \t]*network[ \t]*=", re.M),
    )
    absent_text(
        root,
        ("etc/NetworkManager", "usr/lib/NetworkManager/conf.d"),
        re.compile(
            r"^[ \t]*(unmanaged-devices|managed[ \t]*=[ \t]*(0|false|no))", re.I | re.M
        ),
    )
    absent_text(
        root,
        ("etc/udev/rules.d", "usr/lib/udev/rules.d"),
        re.compile(r"NM_UNMANAGED"),
        skip="85-nm-unmanaged.rules",
    )
    # A replacement with the same basename in /etc is not the stock rule.
    absent_text(
        root, ("etc/udev/rules.d/85-nm-unmanaged.rules",), re.compile(r"NM_UNMANAGED")
    )
    absent_text(
        root,
        ("usr/lib/udev/rules.d/85-nm-unmanaged.rules",),
        re.compile(r"wlan|wifi|wlp|aic", re.I),
    )
    absent_text(
        root,
        (
            "etc/NetworkManager/system-connections",
            "usr/lib/NetworkManager/system-connections",
        ),
        re.compile(r"^[ \t]*type[ \t]*=[ \t]*(wifi|802-11-wireless)\b", re.I | re.M),
    )


def bls(path):
    result = {}
    for line in path.read_text().splitlines():
        parts = line.split(maxsplit=1)
        field, value = (parts + [""])[:2] if parts else ("", "")
        if field in ("linux", "initrd", "version", "options", "title"):
            if field in result or not value.strip():
                raise PolicyError(f"{path}: duplicate or empty BLS {field}")
            result[field] = value.strip()
    if set(result) != {"linux", "initrd", "version", "options", "title"}:
        raise PolicyError(f"{path}: incomplete protective BLS entry")
    return result


def grubenv(root, expected, saved_entry):
    # GRUB's shipped grub.cfg selects saved_entry only if next_entry is absent.
    path = regular(root, "boot/grub2/grubenv")
    data = path.read_bytes()
    if len(data) != 1024 or not data.startswith(b"# GRUB Environment Block\n"):
        raise PolicyError(f"{path}: expected one 1024-byte GRUB environment block")
    variables = {}
    for line in data.decode("ascii").splitlines():
        if line.startswith("#") or not line:
            continue
        key, sep, value = line.partition("=")
        if not sep or key in variables:
            raise PolicyError(f"{path}: invalid or duplicate GRUB setting")
        variables[key] = value
    if variables.get("saved_entry") != saved_entry:
        raise PolicyError(f"{path}: saved_entry is not the build's protective default")
    if "next_entry" in variables:
        raise PolicyError(f"{path}: unexpected next_entry")
    if data != regular(expected, "boot/grub2/grubenv").read_bytes():
        raise PolicyError("boot/grub2/grubenv: differs from the build-generated block")


BOOT_HELPER = "usr/local/bin/cubie-a7a-bootmode"
BOOT_PLUGIN = "etc/kernel/install.d/96-cubie-a7a-bootmodes.install"
BOOT_UNITS = ("cubie-a7a-bootmode-ro.service", "cubie-a7a-bootmode-next.service")


def expected_files(root, expected):
    # Match build GRUB config and owned helpers as plain files, not effective units.
    for name in ("boot/grub2/grub.cfg", "etc/default/grub", "etc/kernel/cmdline"):
        if regular(root, name).read_bytes() != regular(expected, name).read_bytes():
            raise PolicyError(f"{name}: changed since build staging")
    for name in (BOOT_HELPER, BOOT_PLUGIN):
        live = regular(root, name)
        if (
            not live.stat().st_mode & stat.S_IXUSR
            or live.read_bytes() != regular(expected, name).read_bytes()
        ):
            raise PolicyError(f"{name}: expected the build's executable")
    for unit in BOOT_UNITS:
        rel = f"etc/systemd/system/{unit}"
        link = physical(root, f"etc/systemd/system/sysinit.target.wants/{unit}")
        # Compare target strings; never let the OS resolve the unit symlink.
        if not link.is_symlink() or os.readlink(link) not in (f"../{unit}", f"/{rel}"):
            raise PolicyError(f"{link}: expected the build's boot-mode link")
        if regular(root, rel).read_bytes() != regular(expected, rel).read_bytes():
            raise PolicyError(f"{rel}: changed since build staging")
    if (
        regular(root, "etc/kernel/cmdline").stat().st_mtime_ns
        <= regular(root, "etc/default/grub").stat().st_mtime_ns
    ):
        raise PolicyError("etc/kernel/cmdline must be newer than etc/default/grub")
    for unit in (
        "cubie-a7a-dtb.service",
        "systemd-repart.service",
        "systemd-growfs-root.service",
    ):
        regular(root, "usr/lib/systemd/system/" + unit)


def bls_entries(root):
    base = optional_dir(root, "boot/loader/entries")
    if base is None:
        raise PolicyError("missing boot/loader/entries")
    return {p.stem: regular(root, p.relative_to(root)) for p in base.glob("*.conf")}


def boot_entries(root, expected, kernels, root_uuid, default_args, saved):
    # Bind BLS triples/options and their files to this build, not a boot transcript.
    files = bls_entries(root)
    built = bls_entries(expected)
    heads = {name for name in built if "~" not in name}
    if (
        not heads
        or saved not in heads
        or files.keys() != built.keys()
        or set(files)
        != {name + mode for name in heads for mode in ("", "~maintenance", "~full")}
    ):
        raise PolicyError(
            "boot/loader/entries: expected the build's three entries per kernel"
        )
    versions = []
    command_line = regular(expected, "etc/kernel/cmdline").read_text().split()
    hat = "cubie_a7a.hat=0"
    protection = set(default_args.split()) - {hat}
    for head in sorted(heads):
        default, maintenance, full = (
            bls(files[head + mode]) for mode in ("", "~maintenance", "~full")
        )
        version = default["version"]
        if version not in kernels:
            raise PolicyError(f"{head}: BLS version is not a build kernel")
        versions.append(version)
        linux = f"/boot/vmlinuz-{version}"
        initrd = f"/boot/initramfs-{version}.img"
        for entry in (default, maintenance, full):
            if (entry["version"], entry["linux"], entry["initrd"]) != (
                version,
                linux,
                initrd,
            ):
                raise PolicyError(
                    f"{head}: BLS paths are not the build kernel/initramfs"
                )
        with regular(root, linux.removeprefix("/")).open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != regular(expected, f"vmlinuz-{version}.sha256").read_text().strip():
            raise PolicyError(f"{head}: vmlinuz digest differs from build output")
        # The profile-independent digest check separately verifies this initramfs path.
        regular(root, initrd.removeprefix("/"))
        primary = default["options"].split()
        middle = [word for word in primary if word not in protection]
        root_flags = [word for word in primary if word.startswith("rootflags=")]
        if len(root_flags) != 1 or not {"noload", "norecovery"}.intersection(
            root_flags[0].split("=", 1)[1].split(",")
        ):
            raise PolicyError(
                f"{head}: BLOCKED: protective options need a journal no-replay flag"
            )
        if (
            primary != command_line
            or not protection | {hat} <= set(primary)
            or [word for word in primary if word.startswith("root=")]
            != [f"root=UUID={root_uuid}"]
            or [word for word in primary if word in ("ro", "rw")] != ["ro"]
            or middle != maintenance["options"].split()
            or [word for word in middle if word != hat] != full["options"].split()
        ):
            raise PolicyError(
                f"{head}: invalid protective, maintenance or full BLS options"
            )
        for mode, suffix in zip(
            ("", "~maintenance", "~full"),
            (
                "(protective: ro overlay, hat=0)",
                " maintenance (rw, hat=0)",
                " full (rw, HAT on)",
            ),
            strict=True,
        ):
            name = head + mode
            if (
                not bls(files[name])["title"].endswith(suffix)
                or files[name].read_bytes() != built[name].read_bytes()
            ):
                raise PolicyError(f"{name}: BLS entry differs from the build")
    if sorted(versions) != sorted(kernels):
        raise PolicyError("protective BLS versions differ from kernel.txt")
    grubenv(root, expected, saved)


def growth(root, expected):
    # Proves the mount table is unchanged and growth config/masks are as staged.
    # A runtime unit or generator's behaviour is for board acceptance.
    entries = []
    for prefix in ("etc", "usr/lib", "usr/local/lib", "run"):
        directory = optional_dir(root, prefix + "/repart.d")
        if directory is not None:
            entries.extend(
                p.relative_to(root).as_posix() for p in sorted(directory.iterdir())
            )
    if any(name.endswith(".conf") for name in entries):
        raise PolicyError(f"unexpected repart.d config: {entries}")
    print(f"protective repart.d entries: {entries}")
    if (
        regular(root, "etc/fstab").read_bytes()
        != regular(expected, "etc/fstab").read_bytes()
    ):
        raise PolicyError("etc/fstab: differs from the build-generated mount table")
    for unit in (
        "systemd-repart.service",
        "systemd-repart@.service",
        "systemd-growfs-root.service",
    ):
        rel = f"etc/systemd/system/{unit}"
        path = physical(root, rel, missing=True)
        if path is None or not path.is_symlink() or os.readlink(path) != "/dev/null":
            raise PolicyError(f"{rel}: expected an exact /dev/null mask")


def accounts(root, expected):
    # Match the build's intended root password and sole-human-account policy;
    # never emit password material or infer live NSS/sshd behaviour.
    text = regular(root, "etc/shadow").read_text()
    _, password, others = shadow_fields(text)
    rows = [line.split(":", 2) for line in text.splitlines()]
    if (
        sum(row[0] == "root" for row in rows) != 1
        or not expected.startswith("$6$")
        or not hmac.compare_digest(password.encode(), expected.encode())
        or others
        or any(
            len(row) < 2 or (row[0] != "root" and not row[1].startswith(("!", "*")))
            for row in rows
        )
    ):
        raise PolicyError("etc/shadow: expected only the build's root password")
    if not passwd_sole_root(regular(root, "etc/passwd").read_text()):
        raise PolicyError("etc/passwd: expected root as the sole human account")


BOOT_CONTROL_PATHS = (
    "boot/grub2",
    "boot/loader",
    "etc/cubie-a7a/bootmodes.conf",
    "etc/default/grub",
    "etc/default/grub.d",
    "etc/fstab",
    "etc/grub.d",
    "etc/kernel",
    "etc/crypttab",
    "usr/lib/kernel",
    "usr/local/bin/cubie-a7a-bootmode",
)
SYSTEMD_CONTROL_PATHS = (
    "system",
    "system.control",
    "system.conf",
    "system.conf.d",
    "transient",
    "generator.early",
    "generator",
    "generator.late",
    "system-generators",
    "system-environment-generators",
)


def overlay_boot_control(overlay):
    # Reject writes to these named inputs without modelling systemd unit lookup.
    paths = (
        *BOOT_CONTROL_PATHS,
        *(
            f"{prefix}/systemd/{name}"
            for prefix in ("etc", "run", "usr/local/lib", "usr/lib", "lib")
            for name in SYSTEMD_CONTROL_PATHS
        ),
    )
    for name in paths:
        if physical(overlay, name, missing=True) is not None:
            raise PolicyError(f"protective overlay writes boot-control input: {name}")


def debugfs(image, command):
    return subprocess.run(
        ["debugfs", "-R", command, str(image)],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


def packed_root(image, is_protective):
    caps = debugfs(image, "ea_get -x usr/sbin/arping security.capability")
    if not re.search(r"security\.capability \(20\) = 00 00 00 02\b", caps):
        raise PolicyError(
            "packed usr/sbin/arping lacks a version-2 security.capability"
        )
    if is_protective:
        if not re.fullmatch(r"[0-9]+", debugfs(image, "blocks /boot/grub2/grubenv")):
            raise PolicyError("packed grubenv does not occupy exactly one block")
        label = debugfs(
            image, "ea_get usr/local/bin/cubie-a7a-bootmode security.selinux"
        )
        if ":object_r:bin_t:s0" not in label:
            raise PolicyError("packed cubie-a7a-bootmode lacks bin_t label")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    staged = sub.add_parser("staged")
    staged.add_argument("root", type=Path)
    staged.add_argument("expected", type=Path)
    staged.add_argument("kernels", type=Path)
    staged.add_argument("root_uuid")
    staged.add_argument("default_args")
    staged.add_argument("saved_entry")
    overlay = sub.add_parser("overlay")
    overlay.add_argument("directory", type=Path)
    packed = sub.add_parser("packed")
    packed.add_argument("root_image", type=Path)
    packed.add_argument("--protective", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "staged":
            first_boot(args.root)
            wifi(args.root)
            growth(args.root, args.expected)
            accounts(args.root, sys.stdin.read().rstrip("\n"))
            boot_entries(
                args.root,
                args.expected,
                args.kernels.read_text().splitlines(),
                args.root_uuid,
                args.default_args,
                args.saved_entry,
            )
            expected_files(args.root, args.expected)
        elif args.command == "overlay":
            overlay_boot_control(args.directory)
        else:
            packed_root(args.root_image, args.protective)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"staged-root-policy {args.command}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
