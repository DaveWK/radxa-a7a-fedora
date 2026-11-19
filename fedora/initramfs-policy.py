#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Native, complete admission of the final staged initramfs."""

import argparse
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from staged_paths import RUNTIME_LINKS, resolve, walk

MAGIC = bytes.fromhex("28 b5 2f fd")
DEVICES = {
    "dev/null": (1, 3),
    "dev/kmsg": (1, 11),
    "dev/console": (5, 1),
    "dev/random": (1, 8),
    "dev/urandom": (1, 9),
}
LISTING = re.compile(
    r"(?P<mode>.{10})\s+\d+\s+\d+\s+\d+\s+"
    r"(?P<size>\d+(?:,\s*\d+)?)\s+\S+\s+\d+\s+\S+\s+(?P<entry>.+)"
)
MODULE = re.compile(r"(.+)\.ko(?:\.(?:xz|zst|gz))?")


class PolicyError(RuntimeError):
    pass


def native_cpio(image, arguments, cwd=None):
    env = {**os.environ, "LC_ALL": "C", "TZ": "UTC"}
    with subprocess.Popen(
        ["zstd", "-dc", "--check", str(image)],
        stdout=subprocess.PIPE,
        env=env,
    ) as decoder:
        try:
            output = subprocess.run(
                ["cpio", *arguments],
                stdin=decoder.stdout,
                capture_output=True,
                cwd=cwd,
                env=env,
            )
        finally:
            decoder.stdout.close()
        status = decoder.wait()
    if status or output.returncode:
        stderr = output.stderr.decode("utf-8", errors="replace").strip()
        raise PolicyError(
            f"{image}: zstd exit {status}, cpio exit {output.returncode}: {stderr}"
        )
    return output.stdout.decode("utf-8")


def listing(image):
    output = native_cpio(image, ["-itv", "--quiet", "--numeric-uid-gid"])
    members = {}
    devices = []
    for line in output.splitlines():
        row = LISTING.fullmatch(line)
        if row is None:
            raise PolicyError(f"{image}: unexpected cpio inventory line: {line!r}")
        mode, entry = row["mode"], row["entry"]
        kind = mode[0]
        raw, sep, target = entry.partition(" -> ") if kind == "l" else (entry, "", "")
        path = PurePosixPath(raw)
        name = path.as_posix()
        canonical = name if name != "." else "."
        if (
            path.is_absolute()
            or ".." in path.parts
            or raw not in (canonical, "./" + canonical)
            or any(ord(c) < 32 or ord(c) == 127 for c in raw + target)
            or name in members
            or (kind == "l" and (not sep or not target or " -> " in target))
            or (name == "." and kind != "d")
        ):
            raise PolicyError(
                f"{image}: invalid or duplicate archive member: {entry!r}"
            )
        if kind not in ("-", "d", "l"):
            known = DEVICES.get(name)
            match = re.fullmatch(r"(\d+),\s*(\d+)", row["size"])
            if (
                kind != "c"
                or known is None
                or match is None
                or tuple(map(int, match.groups())) != known
            ):
                raise PolicyError(
                    f"{image}: unapproved archive member {name}: {mode} {row['size']}"
                )
            devices.append(raw)
            print(
                f"{image.name}: archive device {name} {mode} {known[0]},{known[1]} (not extracted)"
            )
        members[name] = (kind, target)
    if not members:
        raise PolicyError(f"{image}: empty archive member inventory")
    for name in members:
        for parent in PurePosixPath(name).parents:
            key = parent.as_posix()
            if key != "." and members.get(key, (None,))[0] != "d":
                raise PolicyError(
                    f"{image}: {name} has an unlisted or non-directory parent {key}"
                )
    if not devices:
        print(f"{image.name}: archive device inventory empty")
    return members, devices


def unpack(image, destination):
    if image.is_symlink() or not image.is_file():
        raise PolicyError(f"{image}: initramfs entry is not a regular file")
    with image.open("rb") as stream:
        if stream.read(4) != MAGIC:
            raise PolicyError(f"{image}: expected zstd magic, no early CPIO")
    members, devices = listing(image)
    if not image.is_absolute():
        image = image.absolute()
    destination.mkdir()
    selection = ["--nonmatching", "--", *devices] if devices else []
    native_cpio(
        image,
        ["-idm", "--no-absolute-filenames", "--quiet", *selection],
        cwd=destination,
    )
    expected = {
        path: data for path, data in members.items() if data[0] != "c" and path != "."
    }
    actual = {}
    for path in walk(destination):
        if path == destination:
            continue
        name = path.relative_to(destination).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            actual[name] = ("d", "")
        elif stat.S_ISREG(mode):
            actual[name] = ("-", "")
        elif stat.S_ISLNK(mode):
            actual[name] = ("l", os.readlink(path))
        else:
            raise PolicyError(f"{image}: unexpected extracted member type: {name}")
    for name in sorted(expected.keys() | actual.keys()):
        if expected.get(name) != actual.get(name):
            raise PolicyError(
                f"{image}: extracted inventory differs at {name}: expected {expected.get(name)}, got {actual.get(name)}"
            )
    for name, (kind, target) in actual.items():
        if kind != "l":
            continue
        if name in RUNTIME_LINKS:
            if RUNTIME_LINKS[name] != target:
                raise PolicyError(
                    f"{image}: wrong runtime symlink target: {name} -> {target}"
                )
            continue
        resolved = resolve(destination, name)
        if resolved.relative_to(destination).as_posix() not in actual:
            raise PolicyError(
                f"{image}: {name} does not resolve to an extracted archive member"
            )


def overlay(path):
    boot = path / "boot"
    if not os.path.lexists(boot):
        return
    if boot.is_symlink() or not boot.is_dir():
        raise PolicyError(f"overlay replaces the initramfs parent: {boot}")
    for entry in sorted(boot.glob("initramfs-*")):
        raise PolicyError(f"overlay writes an initramfs entry: {entry}")


def forbidden_modules(base, board):
    forbidden = {"aic_btusb"}
    if "pinctrl-sun60i-a733" not in board:
        forbidden.add("pinctrl_sun60i_a733")
    for path in walk(base):
        match = MODULE.fullmatch(path.name)
        if match and match[1].replace("-", "_") in forbidden:
            raise PolicyError(f"forbidden module: {path}")


def modules(root, kernel, board, stock, protective):
    base = root / "usr/lib/modules" / kernel
    if base.is_symlink() or not base.is_dir():
        raise PolicyError(f"{base}: missing unpacked kernel module directory")
    forbidden_modules(base, board)
    found = {}
    for path in walk(base):
        matches = MODULE.fullmatch(path.name)
        if matches and (path.is_symlink() or not path.is_dir()):
            found.setdefault(matches[1].replace("-", "_"), []).append(
                path.relative_to(base)
            )
    for name in board:
        if not any(
            path.parts[0] == "extra" for path in found.get(name.replace("-", "_"), ())
        ):
            raise PolicyError(f"{base}: missing required extra/{name}.ko")
    for name in stock:
        if not found.get(name.replace("-", "_")):
            raise PolicyError(f"{base}: missing required {name}.ko")
    pin_builtin = "pinctrl-sun60i-a733" not in board
    force = root / "etc/cmdline.d/20-force_drivers.conf"
    if not force.is_file() or force.is_symlink():
        raise PolicyError(f"{force}: expected the dracut force-driver configuration")
    text = force.read_text().replace("-", "_")
    if "sun60i_a733_ccu" not in text or (pin_builtin and "pinctrl" in text):
        raise PolicyError(f"{force}: wrong forced A733 drivers")
    if protective and (
        not found.get("overlay")
        or not (root / "usr/lib/systemd/systemd-volatile-root").is_file()
    ):
        raise PolicyError(
            "protective initramfs needs overlay.ko and systemd-volatile-root"
        )


def final_set(root, kernels):
    names = kernels.read_text().splitlines()
    if (
        not names
        or len(names) != len(set(names))
        or any(not re.fullmatch(r"[A-Za-z0-9_.+-]+", name) for name in names)
    ):
        raise PolicyError(f"{kernels}: invalid kernel inventory")
    boot = root / "boot"
    if boot.is_symlink() or not boot.is_dir():
        raise PolicyError(f"{boot}: expected a staged boot directory")
    entries = {p.name: p for p in boot.glob("initramfs-*")}
    for entry in entries.values():
        if entry.is_symlink() or not entry.is_file():
            raise PolicyError(f"{entry}: initramfs entry is not a regular file")
    expected = {f"initramfs-{name}.img" for name in names}
    if entries.keys() != expected:
        raise PolicyError(
            f"{boot}: initramfs set differs; extra={sorted(entries.keys() - expected)} missing={sorted(expected - entries.keys())}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("unpack")
    p.add_argument("img", type=Path)
    p.add_argument("directory", type=Path)
    p = sub.add_parser("overlay")
    p.add_argument("directory", type=Path)
    p = sub.add_parser("set")
    p.add_argument("root", type=Path)
    p.add_argument("kernels", type=Path)
    p = sub.add_parser("modules")
    p.add_argument("root", type=Path)
    p.add_argument("kernel")
    p.add_argument("--board", required=True)
    p.add_argument("--stock", required=True)
    p.add_argument("--protective", action="store_true")
    p = sub.add_parser("root-modules")
    p.add_argument("root", type=Path)
    p.add_argument("kernel")
    p.add_argument("--board", required=True)
    args = parser.parse_args()
    try:
        if args.command == "unpack":
            unpack(args.img, args.directory)
        elif args.command == "overlay":
            overlay(args.directory)
        elif args.command == "set":
            final_set(args.root, args.kernels)
        elif args.command == "root-modules":
            extra = resolve(args.root, f"usr/lib/modules/{args.kernel}/extra")
            forbidden_modules(extra, args.board.split())
        else:
            modules(
                args.root,
                args.kernel,
                args.board.split(),
                args.stock.split(),
                args.protective,
            )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"initramfs-policy {args.command}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
