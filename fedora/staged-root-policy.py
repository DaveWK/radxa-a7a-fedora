#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Final staged-root policy and two targeted checks on the packed root FS."""

import argparse
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from staged_paths import resolve, walk


class PolicyError(RuntimeError):
    pass


def regular(root, relative):
    path = resolve(root, relative)
    if not path.is_file() or path.is_symlink():
        raise PolicyError(f"{relative}: expected a regular file")
    return path


def absent_glob(root, directory, pattern):
    path = root / directory
    if not os.path.lexists(path):
        return
    directory = resolve(root, directory)
    for entry in directory.glob(pattern):
        raise PolicyError(f"unexpected staged entry: {entry.relative_to(root)}")


def absent_text(root, roots, regex, skip=None):
    for name in roots:
        if not os.path.lexists(root / name):
            continue
        for entry in walk(resolve(root, name)):
            if entry.name == skip:
                continue
            rel = entry.relative_to(root)
            if entry.is_symlink():
                entry = resolve(root, rel)
            if entry.is_file() and regex.search(entry.read_text(errors="replace")):
                raise PolicyError(f"{rel}: forbidden Wi-Fi policy {regex.pattern!r}")


def first_boot(root):
    for directory, pattern in (
        ("etc/ssh", "ssh_host_*"),
        ("root/.ssh", "authorized_keys*"),
    ):
        absent_glob(root, directory, pattern)
    for name in (".autorelabel", "var/lib/systemd/random-seed"):
        if os.path.lexists(root / name):
            raise PolicyError(f"unexpected first-boot state: {name}")
    if regular(root, "etc/machine-id").stat().st_size:
        raise PolicyError("etc/machine-id is not empty for first boot")


def wifi(root):
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
        field, _, value = line.partition(" ")
        if field in ("linux", "initrd", "version", "options", "title"):
            if field in result or not value.strip():
                raise PolicyError(f"{path}: duplicate or empty BLS {field}")
            result[field] = value.strip()
    if set(result) != {"linux", "initrd", "version", "options", "title"}:
        raise PolicyError(f"{path}: incomplete protective BLS entry")
    return result


def grubenv(root, defaults, first):
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
            raise PolicyError(f"{path}: invalid or duplicate GRUB setting {key}")
        variables[key] = value
    saved = variables.get("saved_entry")
    if saved not in defaults:
        raise PolicyError(f"{path}: saved_entry is not a protective default")
    if first == "maintenance":
        if variables.get("next_entry") != f"{saved}~maintenance":
            raise PolicyError(
                f"{path}: next_entry is not the one-shot maintenance entry"
            )
    elif "next_entry" in variables:
        raise PolicyError(f"{path}: unexpected next_entry")


def protective(root, default_args, first):
    hat = "cubie_a7a.hat=0"
    protection = set(default_args.split()) - {hat}
    wanted = protection | {hat}
    if not protection:
        raise PolicyError("missing protective default arguments")
    helper = "usr/local/bin/cubie-a7a-bootmode"
    plugin = "etc/kernel/install.d/96-cubie-a7a-bootmodes.install"
    for name in (helper, plugin):
        if not (regular(root, name).stat().st_mode & stat.S_IXUSR):
            raise PolicyError(f"{name}: expected an executable")
    if "/usr/local/bin/cubie-a7a-bootmode" not in regular(root, plugin).read_text():
        raise PolicyError(f"{plugin}: does not call the staged helper")
    for mode in ("ro", "next"):
        unit = f"cubie-a7a-bootmode-{mode}.service"
        rel = f"etc/systemd/system/{unit}"
        link = root / "etc/systemd/system/sysinit.target.wants" / unit
        text = regular(root, rel).read_text().splitlines()
        if not link.is_symlink() or resolve(root, link.relative_to(root)) != root / rel:
            raise PolicyError(f"{link}: expected persistent boot-mode enablement")
        if not any(
            line.startswith("ExecStart=/usr/local/bin/cubie-a7a-bootmode ")
            for line in text
        ):
            raise PolicyError(f"{rel}: does not call the staged helper")
        if mode == "next" and (
            "ConditionKernelCommandLine=!systemd.volatile=overlay" not in text
            or "ExecStart=/usr/local/bin/cubie-a7a-bootmode consume-next" not in text
        ):
            raise PolicyError(f"{rel}: invalid one-shot consumption policy")
    cmdline = regular(root, "etc/kernel/cmdline")
    defaults = regular(root, "etc/default/grub")
    match = re.search(r'^GRUB_CMDLINE_LINUX="([^"\n]*)"$', defaults.read_text(), re.M)
    if (
        not wanted <= set(cmdline.read_text().split())
        or not match
        or not wanted <= set(match[1].split())
    ):
        raise PolicyError("kernel cmdline or GRUB defaults lack protective arguments")
    if cmdline.stat().st_mtime_ns <= defaults.stat().st_mtime_ns:
        raise PolicyError("etc/kernel/cmdline must be newer than etc/default/grub")
    for name in (
        "cubie-a7a-dtb.service",
        "systemd-repart.service",
        "systemd-growfs-root.service",
    ):
        regular(root, "usr/lib/systemd/system/" + name)
    grub = regular(root, "boot/grub2/grub.cfg").read_text()
    if (
        'set default="${next_entry}"' not in grub
        or re.findall(r"(?m)^\s*save_env\s+(\S+)\s*$", grub) != ["next_entry"]
        or grub.count("save_env") != 1
    ):
        raise PolicyError(
            "boot/grub2/grub.cfg: only the one-shot next_entry may be saved"
        )
    directory = root / "boot/loader/entries"
    paths = {entry.stem: entry for entry in directory.glob("*.conf")}
    heads = {name for name in paths if "~" not in name}
    kernels = {p.name for p in (root / "usr/lib/modules").iterdir() if p.is_dir()}
    if (
        not heads
        or len(heads) != len(kernels)
        or set(paths)
        != {name + mode for name in heads for mode in ("", "~maintenance", "~full")}
    ):
        raise PolicyError(f"{directory}: expected three entries per installed kernel")
    versions = set()
    for id in sorted(heads):
        default, maintenance, full = (
            bls(regular(root, paths[id + mode].relative_to(root)))
            for mode in ("", "~maintenance", "~full")
        )
        versions.add(default["version"])
        if any(
            len({entry[field] for entry in (default, maintenance, full)}) != 1
            for field in ("linux", "initrd", "version")
        ):
            raise PolicyError(
                f"{id}: protective BLS entries boot different kernel/initramfs"
            )
        primary = default["options"].split()
        middle = maintenance["options"].split()
        last = full["options"].split()
        if (
            not wanted <= set(primary)
            or middle != [word for word in primary if word not in protection]
            or hat not in middle
            or last != [word for word in middle if word != hat]
            or any(
                word.startswith(("cubie_a7a.hat", "systemd.volatile")) for word in last
            )
        ):
            raise PolicyError(
                f"{id}: invalid protective, maintenance or full BLS options"
            )
        for entry, suffix in zip(
            (default, maintenance, full),
            (
                "(protective: ro overlay, hat=0)",
                " maintenance (rw, hat=0)",
                " full (rw, HAT on)",
            ),
            strict=True,
        ):
            if not entry["title"].endswith(suffix):
                raise PolicyError(f"{id}: BLS title does not name the boot mode")
    if versions != kernels:
        raise PolicyError("protective BLS versions differ from installed kernels")
    newest = subprocess.run(
        ["sort", "-rV"],
        input="\n".join(paths) + "\n",
        text=True,
        capture_output=True,
        check=True,
    ).stdout.splitlines()[0]
    if newest not in heads:
        raise PolicyError("protective BLS default must sort ahead of its alternates")
    grubenv(root, heads, first)


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
    staged.add_argument("--default-args")
    staged.add_argument("--first-boot", choices=("", "maintenance"), default="")
    packed = sub.add_parser("packed")
    packed.add_argument("root_image", type=Path)
    packed.add_argument("--protective", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "staged":
            first_boot(args.root)
            wifi(args.root)
            if args.default_args is not None:
                protective(args.root, args.default_args, args.first_boot)
        else:
            packed_root(args.root_image, args.protective)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"staged-root-policy {args.command}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
