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
          build log) and what "make audit-firmware" runs; also for wider
          audits of closed files with --scan-dir/--allow
  check   the same, exit 1 when a Realtek or unlisted file is present
          (manual use only; nothing in the build calls it)
  strip   manual tool, not used by the image build or any package: remove
          every Realtek or unlisted file from one --root tree (for example a
          scratch copy), log path, owning package and sha256 to stdout and
          append them to a manifest inside that root
          (usr/share/doc/cubie-a7a/removed-firmware.txt); with --list, only
          the listed paths. The image keeps its firmware packages: a closed
          file goes only once an open replacement reaches parity

Inputs (audit/check/strip), any number of each:
  --root DIR        a root filesystem tree (mkdevcard's $W/root, / on the board)
  --list FILE       a listing of paths (- for stdin): one path per line, or lsinitrd /
                    ls -l output (directories skipped, "a -> b" counts as a)

This tool walks plain directory trees and supplied path listings only. The
build audits the staged root and does not capture an initramfs listing. This
tool reads no archive or filesystem image format.

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

FIRMWARE_DIRS = ("usr/lib/firmware", "lib/firmware", "usr/local/lib/firmware")
COMPRESSION = (".xz", ".zst")
# A path component that names Realtek firmware: the linux-firmware
# directories rtl_nic, rtl_bt, rtlwifi, rtw88, rtw89 and realtek, and file or
# directory names starting rtl, rtw or rtk (rtl8125b-2.fw, rtw8822c_fw.bin).
REALTEK = re.compile(r"(^|/)(rt[lwk][^/]*|realtek)(/|$)", re.IGNORECASE)
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
    if not (a.root or a.list):
        ap.error("give at least one --root or --list")
    if a.mode == "strip" and (len(a.root) != 1):
        ap.error("strip works on exactly one --root")
    if a.mode == "check" and a.list:
        print(
            "image-firmware: check --list cannot certify absence: an unframed "
            "path listing has no positive completeness signal; use --root",
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
    except InputError as e:
        print(f"image-firmware: {e}", file=sys.stderr)
        return 2

    realtek, unlisted, allowed = classify(found, rules)
    result = {
        "mode": a.mode,
        "scan_dirs": scan_dirs,
        "allow_lists": a.allow or [default_allow],
        "sources": sorted({s for s, _, _ in found} | set(a.root) | set(a.list)),
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
