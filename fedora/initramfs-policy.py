#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Integrity checks for the staged initramfs file, not its contents."""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from staged_paths import resolve, walk

MODULE = re.compile(r"(.+)\.ko(?:\.(?:xz|zst|gz))?")


class PolicyError(RuntimeError):
    pass


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
    p = sub.add_parser("overlay")
    p.add_argument("directory", type=Path)
    p = sub.add_parser("set")
    p.add_argument("root", type=Path)
    p.add_argument("kernels", type=Path)
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
        elif args.command == "root-modules":
            extra = resolve(args.root, f"usr/lib/modules/{args.kernel}/extra")
            forbidden_modules(extra, args.board.split())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"initramfs-policy {args.command}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
