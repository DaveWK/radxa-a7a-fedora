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
import shutil
import stat
import struct
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


def _check_banner_stderr(tool, result):
    # The normal version banner is on stderr. Any other diagnostic matters:
    # e2fsprogs can return success even after an inode read/rdump failure.
    diagnostics = result.stderr.splitlines()
    banner = re.compile(rf"^{re.escape(tool)} [0-9.]+ \([^()]+\)$".encode())
    if diagnostics and banner.fullmatch(diagnostics[0]):
        diagnostics.pop(0)
    if result.returncode or diagnostics:
        raise ValueError(
            os.fsdecode(b"\n".join(diagnostics)) or f"{tool} exit {result.returncode}"
        )


def _debugfs(image, command, cwd=None):
    result = subprocess.run(
        ["debugfs", "-R", command, str(image)],
        cwd=cwd,
        capture_output=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    _check_banner_stderr("debugfs", result)
    return result.stdout


def _debugfs_batch(image, script, cwd=None):
    result = subprocess.run(
        ["debugfs", "-f", "-", str(image)],
        input=script.encode(),
        cwd=cwd,
        capture_output=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    _check_banner_stderr("debugfs", result)
    return result.stdout


_SUPERBLOCK_SPECIAL_OFFSETS = (0xE0, 0x190, 0x194, 0x19C, 0x1E0, 0x280)
_DUMPE2FS_SPECIAL_KEYS = (
    "Journal inode",
    "Orphan file inode",
    "User quota inode",
    "Group quota inode",
    "Project quota inode",
    "Snapshot inode",
)


def _expected_user_inodes(image):
    """Independent ground-truth count of allocated user inodes (>= first_ino).

    Reads the ext4 superblock directly at offset 1024 and cross-checks against
    `dumpe2fs -h` so a silently truncated debugfs listing cannot hide inodes.
    """
    with open(image, "rb") as fh:
        fh.seek(1024)
        sb = fh.read(1024)
    if len(sb) != 1024 or struct.unpack_from("<H", sb, 0x38)[0] != 0xEF53:
        raise ValueError("not an ext4 filesystem superblock")
    inodes_count = struct.unpack_from("<I", sb, 0x00)[0]
    free_inodes = struct.unpack_from("<I", sb, 0x10)[0]
    first_ino = struct.unpack_from("<I", sb, 0x54)[0]
    if first_ino < 2 or free_inodes > inodes_count:
        raise ValueError("invalid ext4 superblock inode counts")
    sb_special = {
        val
        for off in _SUPERBLOCK_SPECIAL_OFFSETS
        if (val := struct.unpack_from("<I", sb, off)[0]) >= first_ino
    }
    sb_user = inodes_count - free_inodes - (first_ino - 1) - len(sb_special)
    if sb_user < 0:
        raise ValueError("inconsistent ext4 superblock inode accounting")

    res = subprocess.run(
        ["dumpe2fs", "-h", str(image)],
        capture_output=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    _check_banner_stderr("dumpe2fs", res)
    fields = {}
    for raw in res.stdout.decode("utf-8", errors="replace").splitlines():
        if ":" in raw:
            key, val = raw.split(":", 1)
            fields[key.strip()] = val.strip()
    try:
        d_count = int(fields["Inode count"])
        d_free = int(fields["Free inodes"])
        d_first = int(fields["First inode"])
    except (KeyError, ValueError) as exc:
        raise ValueError("incomplete dumpe2fs -h output") from exc
    d_special = {
        int(fields[k])
        for k in _DUMPE2FS_SPECIAL_KEYS
        if k in fields and fields[k].isdigit() and int(fields[k]) >= d_first
    }
    d_user = d_count - d_free - (d_first - 1) - len(d_special)
    if (d_count, d_free, d_first, d_user) != (
        inodes_count,
        free_inodes,
        first_ino,
        sb_user,
    ):
        raise ValueError(
            f"superblock/dumpe2fs inode mismatch: sb={sb_user}, dumpe2fs={d_user}"
        )
    return sb_user, first_ino


def _inventory(image):
    # ls -l -p is slash-delimited. Traverse by inode number, never by
    # interpolating untrusted filenames into debugfs commands. Pair each
    # listing with a trailing `stat <ino>` sentinel and cross-check directory
    # link counts and total allocated inodes against the ext4 superblock.
    expected_user_inodes, first_ino = _expected_user_inodes(image)
    directories = [(2, Path())]
    seen_dirs = set()
    seen_inodes = {2}
    entries = {}
    while directories:
        ino, parent = directories.pop()
        if ino in seen_dirs:
            raise ValueError(f"repeated directory inode {ino}")
        seen_dirs.add(ino)
        out = _debugfs_batch(image, f"ls -l -p <{ino}>\nstat <{ino}>\n")
        ls_rows = []
        stat_lines = []
        in_stat = False
        ls_header_seen = False
        for line in out.splitlines():
            if not in_stat:
                if line.startswith(b"debugfs: ls -l -p "):
                    ls_header_seen = True
                    continue
                if line.startswith(b"debugfs: stat "):
                    in_stat = True
                    continue
                if line:
                    ls_rows.append(line)
            else:
                stat_lines.append(line)
        if not ls_header_seen or not in_stat:
            raise ValueError(
                f"incomplete directory listing at {parent}: missing stat sentinel"
            )
        stat_text = os.fsdecode(b"\n".join(stat_lines))
        m_ino = re.search(r"Inode:\s+(\d+)\s+Type:\s+(\S+)", stat_text)
        m_links = re.search(r"Links:\s+(\d+)", stat_text)
        if (
            not m_ino
            or int(m_ino.group(1)) != ino
            or m_ino.group(2) != "directory"
            or not m_links
        ):
            raise ValueError(
                f"incomplete directory listing at {parent}: invalid stat sentinel"
            )
        stat_links = int(m_links.group(1))

        self_seen = False
        parent_seen = False
        child_dirs = 0
        for row in ls_rows:
            fields = row.split(b"/")
            if len(fields) != 8 or fields[0] or fields[-1]:
                raise ValueError(f"incomplete directory listing at {parent}: {row!r}")
            child, mode, _, _, name, size = fields[1:-1]
            if child == b"0" and not name:
                continue  # unused directory record
            if not name or int(child) < 1:
                raise ValueError(f"invalid directory record: {row!r}")
            child_ino = int(child)
            if name == b".":
                self_seen = child_ino == ino
                continue
            if name == b"..":
                parent_seen = True
                continue
            path = parent / os.fsdecode(name)
            if path in entries:
                raise ValueError(f"duplicate directory entry {path}")
            kind = stat.S_IFMT(int(mode, 8))
            entries[path] = (
                kind,
                int(size) if kind in (stat.S_IFREG, stat.S_IFLNK) else None,
            )
            seen_inodes.add(child_ino)
            if kind == stat.S_IFDIR:
                child_dirs += 1
                directories.append((child_ino, path))
        if not self_seen or not parent_seen:
            raise ValueError(f"incomplete directory listing at {parent}")
        if stat_links >= 2 and child_dirs + 2 != stat_links:
            raise ValueError(
                f"incomplete directory listing at {parent}: "
                f"saw {child_dirs} subdirectories, inode Links={stat_links}"
            )
    discovered_user = len({i for i in seen_inodes if i >= first_ino})
    if discovered_user != expected_user_inodes:
        raise ValueError(
            f"incomplete filesystem inventory: discovered {discovered_user} user inodes, "
            f"ext4 superblock allocates {expected_user_inodes}"
        )
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
