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
import json
import os
import re
import shutil
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
            notes.append(f"{root}: /{d} not scanned, /{link} is a symlink ({os.readlink(os.path.join(root, link))})")
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


def list_initramfs(path):
    if not shutil.which("lsinitrd"):
        raise InputError("lsinitrd (dracut) is needed to list an initramfs")
    r = subprocess.run(["lsinitrd", path], capture_output=True, text=True)
    if r.returncode != 0:
        raise InputError(f"lsinitrd {path}: {r.stderr.strip()}")
    return r.stdout.splitlines()


class Debugfs:
    """Read-only view of an ext4 filesystem inside a disk image."""

    def __init__(self, image, partition):
        if not shutil.which("debugfs") or not shutil.which("sfdisk"):
            raise InputError("debugfs (e2fsprogs) and sfdisk (util-linux) are needed for --image")
        r = subprocess.run(["sfdisk", "-J", image], capture_output=True, text=True)
        if r.returncode != 0:
            raise InputError(f"sfdisk -J {image}: {r.stderr.strip()}")
        parts = json.loads(r.stdout)["partitiontable"]["partitions"]
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
        self.dev = f"{image}?offset={part['start'] * 512}"
        self.label = f"{image} partition {parts.index(part) + 1}"
        self.cache = {}

    def run(self, request):
        # No -w: debugfs opens the filesystem read-only.
        r = subprocess.run(["debugfs", "-R", request, self.dev], capture_output=True, text=True)
        return r.stdout

    def ls(self, path):
        """{name: mode} of a directory, None when it does not exist."""
        if path not in self.cache:
            out = self.run(f'ls -p "{path}"')
            entries = {}
            for line in out.splitlines():
                f = line.split("/")
                # /inode/mode/uid/gid/name/size/
                if len(f) >= 7 and f[0] == "" and f[2].isdigit():
                    if f[5] not in (".", ".."):
                        entries[f[5]] = int(f[2], 8)
            self.cache[path] = entries if out.strip() else None
        return self.cache[path]

    def mode(self, path):
        parent, name = path.rsplit("/", 1)
        listing = self.ls(parent or "/")
        return None if listing is None else listing.get(name)

    def walk(self, scan_dirs, notes):
        entries = []
        for d in scan_dirs:
            parts = d.split("/")
            skip = False
            for i in range(len(parts)):
                sub = "/" + "/".join(parts[: i + 1])
                m = self.mode(sub)
                if m is None:
                    skip = True
                    break
                if (m & 0o170000) == 0o120000:
                    notes.append(f"{self.label}: /{d} not scanned, {sub} is a symlink")
                    skip = True
                    break
            if skip:
                continue
            todo = [""]
            while todo:
                rel = todo.pop()
                listing = self.ls(f"/{d}/{rel}".rstrip("/")) or {}
                for name, m in sorted(listing.items()):
                    child = f"{rel}/{name}".lstrip("/")
                    if (m & 0o170000) == 0o040000:
                        todo.append(child)
                    else:
                        entries.append((d, child))
        return entries

    def dump(self, path, dest):
        self.run(f'dump "{path}" "{dest}"')
        if not os.path.isfile(dest):
            raise InputError(f"{self.label}: cannot read {path}")


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
        rec = dict(i, package=owner(root, i["path"]), sha256=digest(full),
                   size=0 if os.path.islink(full) else os.path.getsize(full))
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
    lines += [f"{r['sha256']}\t{r['size']}\t{r['package']}\t{r['reason']}\t{r['path']}" for r in removed]
    man = os.path.join(root, manifest_rel.lstrip("/"))
    os.makedirs(os.path.dirname(man), exist_ok=True)
    new = not os.path.exists(man)
    with open(man, "a", encoding="utf-8") as f:
        if new:
            f.write("# Firmware removed from this tree by hand: Realtek firmware and every\n"
                    "# file not on the allow-list (image-firmware.py strip). One section per run.\n"
                    "# sha256\tbytes\tpackage\treason\tpath\n")
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
    ap.add_argument("--image", action="append", default=[], help="raw disk image (read-only)")
    ap.add_argument("--partition", type=int, default=0, help="with --image: partition number")
    ap.add_argument("--initramfs", action="store_true", help="also list boot/initramfs-*.img")
    ap.add_argument("--allow", action="append", default=None, help=f"allow-list (default {default_allow})")
    ap.add_argument("--scan-dir", action="append", default=None,
                    help="directory to check, relative to the root (default: %s)" % ", ".join(FIRMWARE_DIRS))
    ap.add_argument("--manifest", default="usr/share/doc/cubie-a7a/removed-firmware.txt",
                    help="strip: manifest path inside the root")
    ap.add_argument("--json", help="also write the result as JSON")
    ap.add_argument("--quiet", action="store_true", help="do not print allowed files")
    a = ap.parse_args()
    if not (a.root or a.list or a.image):
        ap.error("give at least one --root, --list or --image")
    if a.mode == "strip" and (a.image or a.initramfs or len(a.root) != 1):
        ap.error("strip works on exactly one --root (no --image or --initramfs)")
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
                        found += [(f"{p} (initramfs)", d, rel)
                                  for d, rel in parse_listing(list_initramfs(p), scan_dirs)]
        listed = []
        for path in a.list:
            try:
                if path == "-":
                    lines = sys.stdin.read().splitlines()
                else:
                    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
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
                            found += [(f"{fs.label}:/boot/{name} (initramfs)", d, rel)
                                      for d, rel in parse_listing(list_initramfs(dest), scan_dirs)]
                            os.unlink(dest)
    except InputError as e:
        print(f"image-firmware: {e}", file=sys.stderr)
        return 2

    realtek, unlisted, allowed = classify(found, rules)
    result = {"mode": a.mode, "scan_dirs": scan_dirs, "allow_lists": a.allow or [default_allow],
              "sources": sorted({s for s, _, _ in found} | set(a.root) | set(a.list) | set(a.image)),
              "notes": notes, "realtek": realtek, "unlisted": unlisted, "allowed": allowed}
    for n in notes:
        print(f"note      {n}")
    if not a.quiet:
        for i in allowed:
            print(f"allowed   {i['path']}  [{i['source']}; {i['allowed_by']}]")

    if a.mode == "strip":
        removed, lines = strip(a.root[0], realtek + unlisted, a.manifest, scan_dirs)
        for r in removed:
            print(f"removed   {r['path']}  package={r['package']} sha256={r['sha256']} "
                  f"({r['reason']}, {r['size']} bytes)")
        result["removed"] = removed
        print(f"image-firmware: removed {len(removed)} file(s) "
              f"({len(realtek)} Realtek, {len(unlisted)} not on the allow-list), "
              f"{len(allowed)} allowed kept; manifest /{a.manifest.lstrip('/')}")
    else:
        tag = "REALTEK " if a.mode == "check" else "realtek "
        for i in realtek:
            print(f"{tag}  {i['path']}  [{i['source']}]")
        tag = "UNLISTED" if a.mode == "check" else "unlisted"
        for i in unlisted:
            print(f"{tag}  {i['path']}  [{i['source']}]")
        print(f"image-firmware: {len(found)} firmware entries in {len(result['sources'])} "
              f"source(s): {len(realtek)} Realtek, {len(unlisted)} not on the allow-list, "
              f"{len(allowed)} allowed")
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
