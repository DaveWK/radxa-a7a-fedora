#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Audit, check or strip the firmware files of a Cubie A7A image.

Every file and symlink under the kernel's firmware directories (by default
usr/lib/firmware, lib/firmware, usr/local/lib/firmware) is classified
against an allow-list of firmware reviewed as open
(fedora/image-firmware.allow): allowed, Realtek (never allowed, whatever the
allow-list says) or unlisted (closed or not reviewed yet).

  audit   list allowed, Realtek and unlisted files; always exits 0. This is
          what the image build runs (mkdevcard.sh, a report next to the
          build log) and what "make audit-firmware IMG=..." runs; also for
          wider audits of closed files with --scan-dir/--allow
  check   the same, exit 1 when a Realtek or unlisted file is present
          (manual use only; nothing in the build calls it)
  strip   manual tool, not used by the image build or any package: remove
          every Realtek or unlisted file from one --root tree (for example a
          scratch copy), log path, owning package and sha256 to stdout and
          append them to a manifest inside that root
          (usr/share/doc/cubie-a7a/removed-firmware.txt); with --list, only
          the listed paths. The image keeps its firmware packages: a closed
          file goes only once an open replacement reaches parity

Inputs (audit/check), any number of each:
  --root DIR        a root filesystem tree (mkdevcard's $W/root, / on the board)
  --list FILE       a listing of paths (- for stdin): one path per line, or lsinitrd /
                    ls -l output (directories skipped, "a -> b" counts as a)
  --image IMG       a raw disk image: its root partition is read with debugfs
                    (read-only, no mount)
  --initramfs       also list every boot/initramfs-*.img of each --root or
                    --image with lsinitrd (an image's is copied to TMPDIR)

Exit 0: clean (or audit/strip done). Exit 1: check found files. Exit 2: usage
or input error.
"""

import argparse
import datetime
import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

FIRMWARE_DIRS = ("usr/lib/firmware", "lib/firmware", "usr/local/lib/firmware")
COMPRESSION = (".xz", ".zst")
# A path component that names Realtek firmware: the linux-firmware
# directories rtl_nic, rtl_bt, rtlwifi, rtw88, rtw89 and realtek, and file or
# directory names starting rtl, rtw or rtk (rtl8125b-2.fw, rtw8822c_fw.bin).
REALTEK = re.compile(r"(^|/)(rt[lwk][^/]*|realtek)(/|$)", re.IGNORECASE)
# GPT partition types searched for the root filesystem, in this order.
ROOT_TYPES = (
    "B921B045-1DF0-41C3-AF44-4C6F280D3FAE",  # root, arm64
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709",  # root, x86-64
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4",  # Linux filesystem data
)
LS_LINE = re.compile(r"^([dlcbps-])[rwxsStT-]{9}[.+@]?\s")


class InputError(Exception):
    pass


def strip_compression(path):
    for ext in COMPRESSION:
        if path.endswith(ext):
            return path[: -len(ext)]
    return path


def load_allow(paths):
    rules = []
    for path in paths:
        try:
            lines = open(path, encoding="utf-8").read().splitlines()
        except OSError as e:
            raise InputError(f"allow-list {path}: {e.strerror}") from e
        for n, line in enumerate(lines, 1):
            pattern = line.split("#", 1)[0].strip()
            if not pattern:
                continue
            if REALTEK.search(pattern):
                raise InputError(
                    f"{path}:{n}: {pattern!r} names Realtek firmware, which is never allowed"
                )
            rules.append((pattern, f"{path}:{n}"))
    return rules


def allowed_by(rel, rules):
    plain = strip_compression(rel)
    for pattern, where in rules:
        if fnmatch.fnmatchcase(rel, pattern) or fnmatch.fnmatchcase(plain, pattern):
            return where
    return None


def under(path, scan_dirs):
    """(scan dir, path relative to it) for a root-relative path, or None."""
    path = path.lstrip("/")
    while path.startswith("./"):
        path = path[2:]
    for d in scan_dirs:
        if path.startswith(d + "/") and len(path) > len(d) + 1:
            return d, path[len(d) + 1 :]
    return None


# --- inputs --------------------------------------------------------------


def scan_root(root, scan_dirs, notes):
    """Entries under each scan dir of a root tree; symlinked dirs are not followed."""
    entries = []
    for d in scan_dirs:
        parts = d.split("/")
        link = next(
            (
                "/".join(parts[: i + 1])
                for i in range(len(parts))
                if os.path.islink(os.path.join(root, *parts[: i + 1]))
            ),
            None,
        )
        if link:
            notes.append(
                f"{root}: /{d} not scanned, /{link} is a symlink ({os.readlink(os.path.join(root, link))})"
            )
            continue
        top = os.path.join(root, d)
        if not os.path.isdir(top):
            continue

        def fail(e):
            raise InputError(f"{e.filename}: {e.strerror}")

        for cur, dirs, files in os.walk(top, onerror=fail):
            for name in sorted(dirs):
                if os.path.islink(os.path.join(cur, name)):
                    files.append(name)
            for name in sorted(files):
                rel = os.path.relpath(os.path.join(cur, name), top)
                entries.append((d, rel.replace(os.sep, "/")))
    return entries


def parse_listing(lines, scan_dirs):
    entries = []
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        m = LS_LINE.match(line)
        if m:
            if m.group(1) == "d":
                continue
            line = line.split(" -> ", 1)[0]
            path = line.split()[-1]
        else:
            path = line.strip()
            if path.endswith("/"):
                continue
        hit = under(path, scan_dirs)
        if hit:
            entries.append(hit)
    return entries


def _load_policy():
    policy_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "devcard-policy.py"
    )
    if not os.path.isfile(policy_path):
        raise InputError(f"cannot locate {policy_path} for initramfs verification")
    prev = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location("devcard_policy_fw", policy_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.dont_write_bytecode = prev


def list_initramfs(path):
    if not shutil.which("lsinitrd"):
        raise InputError("lsinitrd (dracut) is needed to list an initramfs")
    policy_mod = _load_policy()
    try:
        records = policy_mod.inspect_initramfs(path)
    except policy_mod.PolicyError as exc:
        raise InputError(f"lsinitrd {path}: {exc}") from exc
    return [rec[1] for rec in records if rec[0] in ("file", "symlink")]


class Debugfs:
    """Read-only view of an ext4 filesystem inside a disk image."""

    _BANNER_RE = re.compile(r"^debugfs [0-9.]+ \([^()]+\)$")
    _EXT4_INCOMPAT_FILETYPE = 0x0002
    _EXT4_INCOMPAT_EXTENTS = 0x0040
    _EXT4_INCOMPAT_INLINE_DATA = 0x8000
    _EXT4_INCOMPAT_ENCRYPT = 0x10000
    _EXT4_FL_EXTENTS = 0x80000
    _EXT4_FL_ENCRYPT = 0x00800
    _EXT4_FL_INLINE_DATA = 0x10000000
    _EXT4_FT_CSUM = 0xDE
    _ROOT_INO = 2
    _MODE_TO_FT = {
        stat.S_IFREG: 1,
        stat.S_IFDIR: 2,
        stat.S_IFCHR: 3,
        stat.S_IFBLK: 4,
        stat.S_IFIFO: 5,
        stat.S_IFSOCK: 6,
        stat.S_IFLNK: 7,
    }

    def __init__(self, image, partition):
        if not shutil.which("debugfs") or not shutil.which("sfdisk"):
            raise InputError(
                "debugfs (e2fsprogs) and sfdisk (util-linux) are needed for --image"
            )
        r = subprocess.run(["sfdisk", "-J", image], capture_output=True, text=True)
        if r.returncode != 0:
            raise InputError(f"sfdisk -J {image}: {r.stderr.strip()}")
        try:
            parts = json.loads(r.stdout)["partitiontable"]["partitions"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise InputError(
                f"sfdisk -J {image}: corrupt partition table: {exc}"
            ) from exc
        if partition:
            if not 1 <= partition <= len(parts):
                raise InputError(f"{image}: no partition {partition}")
            part = parts[partition - 1]
        else:
            part = next(
                (p for t in ROOT_TYPES for p in parts if p["type"].upper() == t), None
            )
            if part is None:
                raise InputError(f"{image}: no root partition (use --partition)")
        self.image = image
        self.part_offset = part["start"] * 512
        self.part_size = part["size"] * 512
        self.dev = f"{image}?offset={self.part_offset}"
        self.label = f"{image} partition {parts.index(part) + 1}"
        self.block_size = self._read_ext4_superblock()
        self.cache = {}

    def _read_ext4_superblock(self):
        """Pin to mkfs.ext4 extent+filetype ext4 without inline_data or encrypt."""
        try:
            with open(self.image, "rb") as fh:
                fh.seek(self.part_offset + 1024)
                sb = fh.read(1024)
        except OSError as exc:
            raise InputError(
                f"{self.label}: cannot read ext4 superblock: {exc}"
            ) from exc
        if len(sb) != 1024 or struct.unpack_from("<H", sb, 0x38)[0] != 0xEF53:
            raise InputError(f"{self.label}: not an ext4 filesystem superblock")
        log_bs = struct.unpack_from("<I", sb, 0x18)[0]
        if log_bs > 2:
            raise InputError(
                f"{self.label}: unsupported ext4 block size (log={log_bs}); "
                "expected 1024, 2048 or 4096"
            )
        block_size = 1024 << log_bs
        incompat = struct.unpack_from("<I", sb, 0x60)[0]
        if not (incompat & self._EXT4_INCOMPAT_FILETYPE) or not (
            incompat & self._EXT4_INCOMPAT_EXTENTS
        ):
            raise InputError(
                f"{self.label}: refused ext4 without filetype+extents (incompat={hex(incompat)})"
            )
        if incompat & (self._EXT4_INCOMPAT_INLINE_DATA | self._EXT4_INCOMPAT_ENCRYPT):
            raise InputError(
                f"{self.label}: refused ext4 with inline_data or encrypt (incompat={hex(incompat)})"
            )
        return block_size

    def _raw_dir_entries(self, stat_ino, stat_text, path):
        """Independently parse raw ext4 directory blocks from the image file."""
        m_flags = re.search(r"Flags:\s+0x([0-9a-fA-F]+)", stat_text)
        m_size = re.search(r"Size:\s+(\d+)", stat_text)
        if not m_flags or not m_size:
            raise InputError(
                f"{self.label}: incomplete debugfs stat for {path} (missing Flags or Size)"
            )
        flags = int(m_flags.group(1), 16)
        size = int(m_size.group(1))
        if not (flags & self._EXT4_FL_EXTENTS):
            raise InputError(
                f"{self.label}: refused non-extent directory {path} (flags={hex(flags)})"
            )
        if flags & (self._EXT4_FL_INLINE_DATA | self._EXT4_FL_ENCRYPT):
            raise InputError(
                f"{self.label}: refused inline_data or encrypted directory {path} (flags={hex(flags)})"
            )
        if size == 0 or size % self.block_size != 0:
            raise InputError(f"{self.label}: invalid directory size {size} for {path}")
        m_ext = re.search(r"EXTENTS:\n(.*)", stat_text, re.S)
        if not m_ext:
            raise InputError(
                f"{self.label}: missing EXTENTS in debugfs stat for {path}"
            )
        blks = {}
        for token in m_ext.group(1).replace("\n", " ").split(","):
            token = token.strip()
            if not token or token.startswith("(ETB"):
                continue
            m = re.fullmatch(r"\((\d+)(?:-(\d+))?\):(\d+)(?:-(\d+))?", token)
            if not m:
                raise InputError(
                    f"{self.label}: unrecognized extent {token!r} in {path}"
                )
            l0 = int(m.group(1))
            l1 = int(m.group(2)) if m.group(2) else l0
            p0 = int(m.group(3))
            p1 = int(m.group(4)) if m.group(4) else p0
            if (l1 - l0) != (p1 - p0):
                raise InputError(f"{self.label}: mismatched extent {token!r} in {path}")
            for off in range(l1 - l0 + 1):
                lidx = l0 + off
                pidx = p0 + off
                if lidx in blks or (pidx + 1) * self.block_size > self.part_size:
                    raise InputError(
                        f"{self.label}: out-of-range or duplicate extent in {path}"
                    )
                blks[lidx] = pidx
        num_blks = size // self.block_size
        if len(blks) != num_blks or any(i not in blks for i in range(num_blks)):
            raise InputError(
                f"{self.label}: incomplete extent map for {path} "
                f"(got {len(blks)}, expected {num_blks})"
            )
        raw_entries = {}
        self_seen = False
        parent_seen = False
        try:
            with open(self.image, "rb") as fh:
                for lidx in range(num_blks):
                    fh.seek(self.part_offset + blks[lidx] * self.block_size)
                    buf = fh.read(self.block_size)
                    if len(buf) != self.block_size:
                        raise InputError(
                            f"{self.label}: short read on directory block of {path}"
                        )
                    pos = 0
                    while pos < self.block_size:
                        if pos + 8 > self.block_size:
                            raise InputError(
                                f"{self.label}: corrupt ext4 dir record in {path}"
                            )
                        ino, rec_len, name_len, ftype = struct.unpack_from(
                            "<IHBB", buf, pos
                        )
                        if (
                            rec_len < 8
                            or rec_len % 4 != 0
                            or pos + rec_len > self.block_size
                        ):
                            raise InputError(
                                f"{self.label}: corrupt ext4 dir rec_len={rec_len} in {path}"
                            )
                        if ino != 0 and name_len > 0 and ftype != self._EXT4_FT_CSUM:
                            if 8 + name_len > rec_len:
                                raise InputError(
                                    f"{self.label}: corrupt ext4 dir name_len in {path}"
                                )
                            name = buf[pos + 8 : pos + 8 + name_len].decode(
                                "utf-8", errors="surrogateescape"
                            )
                            if name == ".":
                                self_seen = ino == stat_ino
                            elif name == "..":
                                parent_seen = True
                            else:
                                if name in raw_entries:
                                    raise InputError(
                                        f"{self.label}: duplicate raw dir entry {name!r} in {path}"
                                    )
                                raw_entries[name] = (ino, ftype)
                        pos += rec_len
        except OSError as exc:
            raise InputError(
                f"{self.label}: cannot read raw directory blocks for {path}: {exc}"
            ) from exc
        if not self_seen or not parent_seen:
            raise InputError(f"{self.label}: raw ext4 directory {path} missing . or ..")
        return raw_entries

    def _stderr_diagnostics(self, stderr):
        lines = [line for line in stderr.splitlines() if line.strip()]
        if lines and self._BANNER_RE.fullmatch(lines[0]):
            lines.pop(0)
        return lines

    def _check_result(self, r, what):
        diags = self._stderr_diagnostics(r.stderr)
        if r.returncode != 0 or diags:
            msg = "; ".join(diags) or f"exit {r.returncode}"
            raise InputError(f"{self.label}: debugfs {what} failed: {msg}")

    def run(self, request):
        # No -w: debugfs opens the filesystem read-only.
        r = subprocess.run(
            ["debugfs", "-R", request, self.dev],
            capture_output=True,
            text=True,
            env={**os.environ, "LC_ALL": "C"},
        )
        self._check_result(r, request)
        return r.stdout

    def _ls_ino(self, ino, path):
        """{name: (mode, size, ino)} of directory inode INO (PATH for messages).

        Listed by inode (`ls -l -p <INO>`, `stat <INO>`), so no name lookup
        happens here; the listing must carry its stat sentinel, `.` naming INO
        itself, `..`, the inode's link count of subdirectories, and match the
        raw ext4 directory blocks.  Any debugfs error fails.
        """
        if ino in self.cache:
            return self.cache[ino]
        script = f"ls -l -p <{ino}>\nstat <{ino}>\n"
        r = subprocess.run(
            ["debugfs", "-f", "-", self.dev],
            input=script,
            capture_output=True,
            text=True,
            env={**os.environ, "LC_ALL": "C"},
        )
        self._check_result(r, f"ls -l -p <{ino}> ({path})")
        ls_rows = []
        stat_lines = []
        ls_seen = False
        in_stat = False
        for line in r.stdout.splitlines():
            if not in_stat:
                if line.startswith("debugfs: ls -l -p "):
                    ls_seen = True
                    continue
                if line.startswith("debugfs: stat "):
                    in_stat = True
                    continue
                if line:
                    ls_rows.append(line)
            else:
                stat_lines.append(line)
        if not ls_seen or not in_stat:
            raise InputError(
                f"{self.label}: incomplete debugfs listing for {path} (missing stat sentinel)"
            )
        stat_text = "\n".join(stat_lines)
        m_type = re.search(r"Inode:\s+(\d+)\s+Type:\s+(\S+)", stat_text)
        m_links = re.search(r"Links:\s+(\d+)", stat_text)
        if (
            not m_type
            or int(m_type.group(1)) != ino
            or m_type.group(2) != "directory"
            or not m_links
        ):
            raise InputError(f"{self.label}: invalid debugfs stat sentinel for {path}")
        stat_links = int(m_links.group(1))

        entries = {}
        ls_check = {}
        self_seen = False
        parent_seen = False
        child_dirs = 0
        for line in ls_rows:
            f = line.split("/")
            # /inode/mode/uid/gid/name/size/
            if len(f) != 8 or f[0] != "" or f[-1] != "" or not f[1].isdigit():
                raise InputError(
                    f"{self.label}: malformed debugfs listing row at {path}: {line!r}"
                )
            if f[1] == "0" and f[5] == "":
                continue
            if f[5] == ".":
                self_seen = int(f[1]) == ino
                continue
            if f[5] == "..":
                parent_seen = True
                continue
            child_ino = int(f[1])
            mode = int(f[2], 8)
            size = int(f[6]) if f[6].isdigit() else 0
            ft = self._MODE_TO_FT.get(stat.S_IFMT(mode))
            if ft is None:
                raise InputError(
                    f"{self.label}: unsupported mode {oct(mode)} for {path}/{f[5]}"
                )
            if f[5] in entries:
                raise InputError(
                    f"{self.label}: duplicate debugfs listing row {f[5]!r} in {path}"
                )
            entries[f[5]] = (mode, size, child_ino)
            ls_check[f[5]] = (child_ino, ft)
            if stat.S_ISDIR(mode):
                child_dirs += 1
        if not self_seen or not parent_seen:
            raise InputError(
                f"{self.label}: incomplete debugfs listing for {path} (missing . or ..)"
            )
        if stat_links >= 2 and child_dirs + 2 != stat_links:
            raise InputError(
                f"{self.label}: incomplete debugfs listing for {path} "
                f"(saw {child_dirs} subdirs, inode Links={stat_links})"
            )
        raw_entries = self._raw_dir_entries(ino, stat_text, path)
        if ls_check != raw_entries:
            raise InputError(
                f"{self.label}: debugfs listing mismatch for {path} "
                f"(ls={len(ls_check)} entries, raw ext4 dir={len(raw_entries)})"
            )
        self.cache[ino] = entries
        return entries

    def lookup(self, path):
        """(mode, size, ino) of PATH, walking inode by inode from the root.

        None only when a reconciled parent listing lacks the name; a name the
        parent lists is always read by its inode, so a lookup error fails
        instead of reading as absence.  Symlinks are not followed: a symlink
        ancestor is returned as itself (its mode tells the caller).
        """
        if path.strip("/") == "":
            return (stat.S_IFDIR | 0o755, 0, self._ROOT_INO)
        listing = self._ls_ino(self._ROOT_INO, "/")
        cur = ""
        parts = [p for p in path.strip("/").split("/") if p]
        for i, name in enumerate(parts):
            cur += "/" + name
            if name not in listing:
                return None
            mode, size, child = listing[name]
            if i == len(parts) - 1 or not stat.S_ISDIR(mode):
                if i != len(parts) - 1:
                    if stat.S_ISLNK(mode):
                        return (mode, size, child)
                    raise InputError(f"{self.label}: {cur} is not a directory")
                return (mode, size, child)
            listing = self._ls_ino(child, cur)
        raise InputError(f"{self.label}: cannot look up {path}")

    def ls(self, path):
        """{name: (mode, size)} of a directory, None when its parent lacks it."""
        found = self.lookup(path)
        if found is None:
            return None
        mode, _size, ino = found
        if not stat.S_ISDIR(mode):
            raise InputError(f"{self.label}: {path} is not a directory")
        listing = self._ls_ino(ino, path)
        return {name: (m, sz) for name, (m, sz, _i) in listing.items()}

    def mode(self, path):
        found = self.lookup(path)
        return None if found is None else found[0]

    def walk(self, scan_dirs, notes):
        entries = []
        for d in scan_dirs:
            found = self.lookup("/" + d)
            if found is None:
                continue
            cur = ""
            symlink = False
            for name in d.split("/"):
                cur += "/" + name
                m = self.mode(cur)
                if m is None:
                    break
                if stat.S_ISLNK(m):
                    notes.append(f"{self.label}: /{d} not scanned, {cur} is a symlink")
                    symlink = True
                    break
            if symlink:
                continue
            mode, _size, ino = found
            if not stat.S_ISDIR(mode):
                raise InputError(f"{self.label}: /{d} is not a directory")
            todo = [("", ino)]
            while todo:
                rel, dino = todo.pop()
                listing = self._ls_ino(dino, f"/{d}/{rel}".rstrip("/"))
                for name, (m, _sz, cino) in sorted(listing.items()):
                    child = f"{rel}/{name}".lstrip("/")
                    if stat.S_ISDIR(m):
                        todo.append((child, cino))
                    else:
                        entries.append((d, child))
        return entries

    def dump(self, path, dest):
        found = self.lookup(path)
        if found is None or not stat.S_ISREG(found[0]):
            raise InputError(f"{self.label}: cannot locate regular file {path}")
        expected_size = found[1]
        self.run(f'dump <{found[2]}> "{dest}"')
        if not os.path.isfile(dest) or os.path.getsize(dest) != expected_size:
            raise InputError(
                f"{self.label}: incomplete dump of {path} "
                f"(expected {expected_size} bytes)"
            )


# --- classify, report, strip -------------------------------------------------


def classify(found, rules):
    realtek, unlisted, allowed = [], [], []
    for source, d, rel in found:
        item = {"source": source, "path": f"/{d}/{rel}"}
        if REALTEK.search(rel):
            realtek.append(dict(item, reason="realtek"))
        else:
            where = allowed_by(rel, rules)
            if where:
                allowed.append(dict(item, allowed_by=where))
            else:
                unlisted.append(dict(item, reason="unlisted"))
    return realtek, unlisted, allowed


def owner(root, path):
    """Owning package of a path in root, or 'none' / 'unknown'."""
    if not shutil.which("rpm"):
        return "unknown"
    cmd = ["rpm", "-qf", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n", path]
    if os.path.realpath(root) != "/":
        cmd[1:1] = ["--root", root]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return "none" if "not owned" in r.stdout + r.stderr else "unknown"
    return ",".join(sorted(set(r.stdout.split())))


def digest(path):
    if os.path.islink(path):
        return "symlink->" + os.readlink(path)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def strip(root, items, manifest_rel, scan_dirs):
    """Remove items (from scan_root of root); append them to the manifest."""
    removed = []
    for i in items:
        full = os.path.join(root, i["path"].lstrip("/"))
        if not os.path.lexists(full):
            continue
        rec = dict(
            i,
            package=owner(root, i["path"]),
            sha256=digest(full),
            size=0 if os.path.islink(full) else os.path.getsize(full),
        )
        os.unlink(full)
        removed.append(rec)
    # Directories the removal emptied (deepest first), inside the scan dirs.
    for d in scan_dirs:
        top = os.path.join(root, d)
        if not os.path.isdir(top) or os.path.islink(top):
            continue
        for cur, dirs, files in os.walk(top, topdown=False):
            if cur != top and not os.listdir(cur):
                os.rmdir(cur)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [f"# {stamp} image-firmware strip: {len(removed)} file(s) removed"]
    lines += [
        f"{r['sha256']}\t{r['size']}\t{r['package']}\t{r['reason']}\t{r['path']}"
        for r in removed
    ]
    man = os.path.join(root, manifest_rel.lstrip("/"))
    os.makedirs(os.path.dirname(man), exist_ok=True)
    new = not os.path.exists(man)
    with open(man, "a", encoding="utf-8") as f:
        if new:
            f.write(
                "# Firmware removed from this tree by hand: Realtek firmware and every\n"
                "# file not on the allow-list (image-firmware.py strip). One section per run.\n"
                "# sha256\tbytes\tpackage\treason\tpath\n"
            )
        f.write("\n".join(lines) + "\n")
    return removed, lines


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_allow = os.path.join(here, "image-firmware.allow")
    if not os.path.exists(default_allow):
        default_allow = "/usr/share/cubie-a7a/image-firmware.allow"
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=("audit", "check", "strip"))
    ap.add_argument("--root", action="append", default=[], help="root filesystem tree")
    ap.add_argument("--list", action="append", default=[], help="path listing file")
    ap.add_argument(
        "--image", action="append", default=[], help="raw disk image (read-only)"
    )
    ap.add_argument(
        "--partition", type=int, default=0, help="with --image: partition number"
    )
    ap.add_argument(
        "--initramfs", action="store_true", help="also list boot/initramfs-*.img"
    )
    ap.add_argument(
        "--allow",
        action="append",
        default=None,
        help=f"allow-list (default {default_allow})",
    )
    ap.add_argument(
        "--scan-dir",
        action="append",
        default=None,
        help="directory to check, relative to the root (default: %s)"
        % ", ".join(FIRMWARE_DIRS),
    )
    ap.add_argument(
        "--manifest",
        default="usr/share/doc/cubie-a7a/removed-firmware.txt",
        help="strip: manifest path inside the root",
    )
    ap.add_argument("--json", help="also write the result as JSON")
    ap.add_argument("--quiet", action="store_true", help="do not print allowed files")
    a = ap.parse_args()
    if not (a.root or a.list or a.image):
        ap.error("give at least one --root, --list or --image")
    if a.mode == "strip" and (a.image or a.initramfs or len(a.root) != 1):
        ap.error("strip works on exactly one --root (no --image or --initramfs)")
    if a.mode == "check" and a.list:
        print(
            "image-firmware: check --list cannot certify absence: an unframed "
            "path listing has no positive completeness signal; use --root or --image",
            file=sys.stderr,
        )
        return 2
    scan_dirs = tuple(d.strip("/") for d in (a.scan_dir or FIRMWARE_DIRS))

    notes = []
    found = []  # (source, scan dir, path below it)
    try:
        rules = load_allow(a.allow or [default_allow])
        for root in a.root:
            if not os.path.isdir(root):
                raise InputError(f"--root {root}: not a directory")
            found += [(root, d, rel) for d, rel in scan_root(root, scan_dirs, notes)]
            if a.initramfs:
                boot = os.path.join(root, "boot")
                for name in sorted(os.listdir(boot)) if os.path.isdir(boot) else []:
                    if name.startswith("initramfs-") and name.endswith(".img"):
                        p = os.path.join(boot, name)
                        found += [
                            (f"{p} (initramfs)", d, rel)
                            for d, rel in parse_listing(list_initramfs(p), scan_dirs)
                        ]
        listed = []
        for path in a.list:
            try:
                if path == "-":
                    lines = sys.stdin.read().splitlines()
                else:
                    lines = (
                        open(path, encoding="utf-8", errors="replace")
                        .read()
                        .splitlines()
                    )
            except OSError as e:
                raise InputError(f"--list {path}: {e.strerror}") from e
            listed += [(path, d, rel) for d, rel in parse_listing(lines, scan_dirs)]
        if a.mode == "strip" and a.list:
            # strip --list: only the listed paths that are in the root (the
            # board's rpm file trigger passes the files a transaction installed,
            # so files the user put there are left alone).
            keep = {(d, rel) for _, d, rel in listed}
            found = [f for f in found if (f[1], f[2]) in keep]
        else:
            found += listed
        for image in a.image:
            fs = Debugfs(image, a.partition)
            found += [(fs.label, d, rel) for d, rel in fs.walk(scan_dirs, notes)]
            if a.initramfs:
                with tempfile.TemporaryDirectory(prefix="image-firmware-") as tmp:
                    for name in sorted(fs.ls("/boot") or {}):
                        if name.startswith("initramfs-") and name.endswith(".img"):
                            dest = os.path.join(tmp, name)
                            fs.dump(f"/boot/{name}", dest)
                            found += [
                                (f"{fs.label}:/boot/{name} (initramfs)", d, rel)
                                for d, rel in parse_listing(
                                    list_initramfs(dest), scan_dirs
                                )
                            ]
                            os.unlink(dest)
    except InputError as e:
        print(f"image-firmware: {e}", file=sys.stderr)
        return 2

    realtek, unlisted, allowed = classify(found, rules)
    result = {
        "mode": a.mode,
        "scan_dirs": scan_dirs,
        "allow_lists": a.allow or [default_allow],
        "sources": sorted(
            {s for s, _, _ in found} | set(a.root) | set(a.list) | set(a.image)
        ),
        "notes": notes,
        "realtek": realtek,
        "unlisted": unlisted,
        "allowed": allowed,
    }
    for n in notes:
        print(f"note      {n}")
    if not a.quiet:
        for i in allowed:
            print(f"allowed   {i['path']}  [{i['source']}; {i['allowed_by']}]")

    if a.mode == "strip":
        removed, lines = strip(a.root[0], realtek + unlisted, a.manifest, scan_dirs)
        for r in removed:
            print(
                f"removed   {r['path']}  package={r['package']} sha256={r['sha256']} "
                f"({r['reason']}, {r['size']} bytes)"
            )
        result["removed"] = removed
        print(
            f"image-firmware: removed {len(removed)} file(s) "
            f"({len(realtek)} Realtek, {len(unlisted)} not on the allow-list), "
            f"{len(allowed)} allowed kept; manifest /{a.manifest.lstrip('/')}"
        )
    else:
        tag = "REALTEK " if a.mode == "check" else "realtek "
        for i in realtek:
            print(f"{tag}  {i['path']}  [{i['source']}]")
        tag = "UNLISTED" if a.mode == "check" else "unlisted"
        for i in unlisted:
            print(f"{tag}  {i['path']}  [{i['source']}]")
        print(
            f"image-firmware: {len(found)} firmware entries in {len(result['sources'])} "
            f"source(s): {len(realtek)} Realtek, {len(unlisted)} not on the allow-list, "
            f"{len(allowed)} allowed"
        )
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=1)
            f.write("\n")
    if a.mode == "check":
        if realtek or unlisted:
            print("image-firmware: FAIL (Realtek or unlisted firmware present)")
            return 1
        print("image-firmware: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
