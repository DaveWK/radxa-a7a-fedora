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


def extract_root(partition_img, dest):
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    result = subprocess.run(
        ["debugfs", "-R", f"rdump / {dest}", str(partition_img)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return result.returncode
    if not any(dest.iterdir()):
        sys.stderr.write(f"extract-root: {partition_img} yielded an empty tree\n")
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
