#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-only extraction of partitions and root trees from a disk image.

Used by fedora/verify-devcard.sh so every filesystem, package and initramfs
check reads IMG itself, never a staging directory that could have changed
after the build (and, with GROW_ROOT=no, checks the post-overlay image).

Commands:
  partitions IMG
      Print one line per partition: ``index type start_sector sector_count``.
  extract-partition IMG OUT TYPE
      Copy the bytes of the first partition whose GPT type starts with TYPE
      to OUT (TYPE is case-insensitive).
  extract-root PARTITION_IMG DEST
      Extract an ext4 partition image's contents into DEST with debugfs,
      preserving modes and symlinks.

Reads only; never mounts and never modifies IMG.
"""

import argparse
import json
import os
import re
import stat
import shutil
import subprocess
import sys
from pathlib import Path

SECTOR_BYTES = 512
CHUNK_BYTES = 1024 * 1024


def _sfdisk(img):
    result = subprocess.run(
        ["sfdisk", "-J", str(img)], capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)["partitiontable"]["partitions"]


def partitions(img):
    for index, part in enumerate(_sfdisk(img)):
        print(f"{index} {part['type']} {int(part['start'])} {int(part['size'])}")
    return 0


def _find(rows, wanted_type):
    wanted = wanted_type.upper()
    for part in rows:
        if str(part["type"]).upper().startswith(wanted):
            return int(part["start"]), int(part["size"])
    raise SystemExit(f"image has no partition of type {wanted_type}")


def extract_partition(img, out, wanted_type):
    rows = _sfdisk(img)
    start, size = _find(rows, wanted_type)
    offset = start * SECTOR_BYTES
    remaining = size * SECTOR_BYTES
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(img, "rb") as src, open(out, "wb") as dst:
        src.seek(offset)
        while remaining > 0:
            chunk = src.read(min(CHUNK_BYTES, remaining))
            if not chunk:
                raise SystemExit(
                    f"short read extracting {wanted_type} from {img} "
                    f"({remaining} bytes left)"
                )
            dst.write(chunk)
            remaining -= len(chunk)
    return 0


def _debugfs(image, command, cwd=None):
    result = subprocess.run(
        ["debugfs", "-R", command, str(image)],
        cwd=cwd,
        capture_output=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    # The normal version banner is on stderr. Any other diagnostic matters:
    # e2fsprogs can return success even after an inode read/rdump failure.
    diagnostics = result.stderr.splitlines()
    if diagnostics and re.fullmatch(rb"debugfs [0-9.]+ \([^()]+\)", diagnostics[0]):
        diagnostics.pop(0)
    if result.returncode or diagnostics:
        raise ValueError(
            os.fsdecode(b"\n".join(diagnostics)) or f"debugfs exit {result.returncode}"
        )
    return result.stdout


def _inventory(image):
    # ls -l -p is slash-delimited. Traverse by inode number, never by
    # interpolating untrusted filenames into debugfs commands.
    directories = [(2, Path())]
    seen = set()
    entries = {}
    while directories:
        ino, parent = directories.pop()
        if ino in seen:
            raise ValueError(f"repeated directory inode {ino}")
        seen.add(ino)
        rows = _debugfs(image, f"ls -l -p <{ino}>").splitlines()
        self_seen = False
        for row in filter(None, rows):
            fields = row.split(b"/")
            if len(fields) != 8 or fields[0] or fields[-1]:
                raise ValueError(f"incomplete directory listing at {parent}: {row!r}")
            child, mode, _, _, name, size = fields[1:-1]
            if child == b"0" and not name:
                continue  # unused directory record
            if not name or int(child) < 1:
                raise ValueError(f"invalid directory record: {row!r}")
            if name == b".":
                self_seen = int(child) == ino
                continue
            if name == b"..":
                continue
            path = parent / os.fsdecode(name)
            if path in entries:
                raise ValueError(f"duplicate directory entry {path}")
            kind = stat.S_IFMT(int(mode, 8))
            entries[path] = (
                kind,
                int(size) if kind in (stat.S_IFREG, stat.S_IFLNK) else None,
            )
            if kind == stat.S_IFDIR:
                directories.append((int(child), path))
        if not self_seen:
            raise ValueError(f"incomplete directory listing at {parent}")
    return entries


def extract_root(partition_img, dest):
    image = Path(partition_img).resolve()
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    try:
        expected = _inventory(image)
        if not expected:
            raise ValueError("empty filesystem")
        # A fixed destination token avoids quoting debugfs commands. Preserve
        # ownership in the builder's user namespace (or real root); never
        # silently accept a failed metadata operation when run outside it.
        output = _debugfs(image, "rdump / .", cwd=dest)
        if output.strip():
            raise ValueError(os.fsdecode(output))
        pending = [dest]
        while pending:
            for path in pending.pop().iterdir():
                status = path.lstat()
                kind = stat.S_IFMT(status.st_mode)
                size = status.st_size if kind in (stat.S_IFREG, stat.S_IFLNK) else None
                if expected.pop(path.relative_to(dest), None) != (kind, size):
                    raise ValueError(f"unexpected type or size at {path}")
                if kind == stat.S_IFDIR:
                    pending.append(path)
        if expected:
            raise ValueError(f"missing extracted path {next(iter(expected))}")
    except (OSError, ValueError) as exc:
        print(f"extract-root: {image}: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("partitions")
    p.add_argument("img", type=Path)
    p = sub.add_parser("extract-partition")
    p.add_argument("img", type=Path)
    p.add_argument("out", type=Path)
    p.add_argument("type")
    p = sub.add_parser("extract-root")
    p.add_argument("partition_img", type=Path)
    p.add_argument("dest", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "partitions":
        return partitions(a.img)
    if a.cmd == "extract-partition":
        return extract_partition(a.img, a.out, a.type)
    if a.cmd == "extract-root":
        return extract_root(a.partition_img, a.dest)
    return 2


if __name__ == "__main__":
    sys.exit(main())
