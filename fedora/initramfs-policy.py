#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Integrity checks for the staged initramfs file, not its contents."""

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from staged_paths import physical, walk

MODULE = re.compile(r"(.+)\.ko(?:\.(?:xz|zst|gz))?")


class PolicyError(RuntimeError):
    pass


def overlay(path):
    # Proves the overlay cannot replace these paths; not firmware provenance.
    boot = physical(path, "boot", missing=True)
    if boot is not None:
        if not stat.S_ISDIR(boot.lstat().st_mode):
            raise PolicyError(f"overlay replaces the initramfs parent: {boot}")
        for entry in sorted(boot.glob("initramfs-*")):
            raise PolicyError(f"overlay writes an initramfs entry: {entry}")
    for name in ("usr/lib/firmware", "lib/firmware"):
        if physical(path, name, missing=True) is not None:
            raise PolicyError(f"overlay writes firmware: {name}")


def forbidden_modules(base, board):
    forbidden = {"aic_btusb"}
    if "pinctrl-sun60i-a733" not in board:
        forbidden.add("pinctrl_sun60i_a733")
    for path in walk(base):
        match = MODULE.fullmatch(path.name)
        if match and match[1].replace("-", "_") in forbidden:
            raise PolicyError(f"forbidden module: {path}")


def final_set(root, kernels):
    names = kernels.read_text().splitlines()
    if (
        not names
        or len(names) != len(set(names))
        or any(not re.fullmatch(r"[A-Za-z0-9_.+-]+", name) for name in names)
    ):
        raise PolicyError(f"{kernels}: invalid kernel inventory")
    boot = physical(root, "boot")
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
    return [entries[name] for name in sorted(expected)]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def image_digests(root, kernels, output, *, verify):
    # Proves final bytes equal dracut output; not content or boot selection.
    actual = {p.name: digest(p) for p in final_set(root, kernels)}
    if verify:
        if actual != json.loads(output.read_text()):
            raise PolicyError("final initramfs digest differs from dracut output")
    else:
        with output.open("x") as stream:
            json.dump(actual, stream, sort_keys=True)
            stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("overlay")
    p.add_argument("directory", type=Path)
    p = sub.add_parser("set")
    p.add_argument("root", type=Path)
    p.add_argument("kernels", type=Path)
    for name in ("capture-digest", "verify-digest"):
        p = sub.add_parser(name)
        p.add_argument("root", type=Path)
        p.add_argument("kernels", type=Path)
        p.add_argument("digests", type=Path)
    p = sub.add_parser("root-modules")
    p.add_argument("root", type=Path)
    p.add_argument("kernel")
    p.add_argument("--board", required=True)
    args = parser.parse_args()
    try:
        if args.command == "overlay":
            overlay(args.directory)
        elif args.command == "set":
            final_set(args.root, args.kernels)
        elif args.command in ("capture-digest", "verify-digest"):
            image_digests(
                args.root,
                args.kernels,
                args.digests,
                verify=args.command == "verify-digest",
            )
        elif args.command == "root-modules":
            extra = physical(args.root, f"usr/lib/modules/{args.kernel}/extra")
            if not stat.S_ISDIR(extra.lstat().st_mode):
                raise PolicyError(f"{extra}: expected a real staged directory")
            forbidden_modules(extra, args.board.split())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"initramfs-policy {args.command}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
