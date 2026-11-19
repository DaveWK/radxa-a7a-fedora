#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Image-policy checks shared by fedora/mkdevcard.sh and
fedora/verify-devcard.sh.

Python 3, run with -I by the shell scripts; the host tests import it.  Every
command prints a stable, shell-friendly result and exits nonzero on a policy
violation, so a caller can use it directly as a check.

Commands:
  aic-find ROOT       AIC8800 firmware our own paths put in ROOT: anything
                      under the user-override directory aic8800_fw (the
                      OVERLAY / AIC_OVERRIDE path) and any manifest-named
                      file outside Fedora's standard linux-firmware path
                      aic/aic8800d80 (DECISIONS 2026-11-11; Dave 2026-11-19:
                      the standard linux-firmware package is fine).
                      Prints one path per line; exit 1 when any is found.
  repart-root ROOT    every effective systemd-repart unit carries the
                      --discard=no drop-in; exit 1 with a diagnostic otherwise.
  repart-initramfs-listing
                      stdin is an lsinitrd listing: no systemd-repart, or one
                      with the --discard=no drop-in; exit 1 otherwise.
"""

import argparse
import re
import sys
from pathlib import Path

AIC_PATTERN = re.compile(r"aic8800", re.IGNORECASE)
MANIFEST = "usr/share/cubie-a7a/aic8800-d80-usb.manifest"
FIRMWARE = "usr/lib/firmware"
# Fedora's standard linux-firmware package installs the D80 files here; Dave
# 2026-11-19: that package is fine and must not be rejected.  Our own
# OVERLAY / AIC_OVERRIDE path is aic8800_fw, which the image must not carry.
LINUX_FIRMWARE_AIC = "aic/aic8800d80"
OVERRIDE_DIR = "aic8800_fw"
REPART_UNITS = ("systemd-repart.service", "systemd-repart@.service")
REPART_DROPIN = "10-cubie-a7a-no-discard.conf"
REPART_REPARTD = ("etc/repart.d", "usr/lib/repart.d", "usr/local/lib/repart.d")


def aic_manifest_names(root):
    """File names recorded in the driver package's manifest, in order."""
    man = Path(root) / MANIFEST
    if not man.is_file():
        return []
    names = []
    for line in man.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts:
            names.append(parts[0])
    return names


def _under_firmware(root):
    fw = Path(root) / FIRMWARE
    if not fw.is_dir():
        return []
    return [p for p in fw.rglob("*") if p.is_file() or p.is_symlink()]


def _from_linux_firmware(rel):
    return rel == LINUX_FIRMWARE_AIC or rel.startswith(LINUX_FIRMWARE_AIC + "/")


def aic_find(root):
    """Every AIC8800 file our own paths put in the image's firmware tree.

    Fedora's standard linux-firmware files (aic/aic8800d80) are allowed.
    Two tests catch ours: anything under the user-override directory
    aic8800_fw (what OVERLAY / AIC_OVERRIDE would populate) and any other
    path naming aic8800, plus each manifest name with its optional
    .xz/.zst suffix outside linux-firmware's directory (a copy under an
    unrelated directory).
    """
    fw = Path(root) / FIRMWARE
    hits = []
    for path in _under_firmware(root):
        rel = str(path.relative_to(fw))
        if _from_linux_firmware(rel):
            continue
        if rel == OVERRIDE_DIR or rel.startswith(OVERRIDE_DIR + "/"):
            hits.append(str(path))
        elif AIC_PATTERN.search(rel):
            hits.append(str(path))
    names = aic_manifest_names(root)
    if names:
        wanted = set()
        for name in names:
            wanted.update((name, name + ".xz", name + ".zst"))
        for path in _under_firmware(root):
            rel = str(path.relative_to(fw))
            if _from_linux_firmware(rel):
                continue
            if path.name in wanted and str(path) not in hits:
                hits.append(str(path))
    return sorted(hits)


def _exec_start_lines(path):
    if not path.is_file():
        return []
    return [
        line[len("ExecStart=") :]
        for line in path.read_text().splitlines()
        if line.startswith("ExecStart=")
    ]


def repart_unit_ok(root, unit):
    """True when UNIT carries the no-discard protection.

    The drop-in repeats the unit's own ExecStart with --discard=no, no other
    drop-in sets ExecStart, and /etc does not replace the unit with a regular
    file.  A masked unit (a /dev/null symlink) is left alone: it cannot run.
    """
    root = Path(root)
    lib = root / "usr/lib/systemd/system" / unit
    etc = root / "etc/systemd/system" / unit
    if etc.is_symlink():
        try:
            if etc.resolve() == Path("/dev/null"):
                return True
        except OSError:
            pass
    if etc.exists() and not etc.is_symlink():
        return False
    if not lib.is_file():
        return False
    stock = _exec_start_lines(lib)
    if len(stock) != 1 or not stock[0]:
        return False
    dropin = root / "etc/systemd/system" / (unit + ".d") / REPART_DROPIN
    if not dropin.is_file():
        return False
    lines = [
        line
        for line in dropin.read_text().splitlines()
        if line and not line.startswith("#")
    ]
    if lines != ["[Service]", "ExecStart=", f"ExecStart={stock[0]} --discard=no"]:
        return False
    for directory in (dropin.parent, lib.parent / (unit + ".d")):
        if not directory.is_dir():
            continue
        for conf in sorted(directory.glob("*.conf")):
            if conf == dropin:
                continue
            if any(
                line.startswith("ExecStart") for line in conf.read_text().splitlines()
            ):
                return False
    return True


def repart_root_ok(root):
    """Every effective systemd-repart unit carries the protection."""
    root = Path(root)
    problems = []
    for unit in REPART_UNITS:
        lib = root / "usr/lib/systemd/system" / unit
        etc = root / "etc/systemd/system" / unit
        if not lib.exists() and not etc.exists() and not etc.is_symlink():
            continue
        if not repart_unit_ok(root, unit):
            problems.append(f"{unit} lacks the --discard=no drop-in")
    configs = []
    for rel in REPART_REPARTD:
        directory = root / rel
        if directory.is_dir():
            configs += [c for c in directory.glob("*.conf") if c.is_file()]
    if (
        configs
        and not (root / "usr/lib/systemd/system/systemd-repart.service").is_file()
    ):
        problems.append("repart.d configuration without systemd-repart.service")
    return (not problems, problems)


def repart_initramfs_ok(listing):
    """An initramfs listing: no systemd-repart, or one with the drop-in."""
    if "systemd-repart" not in listing:
        return True, ""
    if f"systemd-repart.service.d/{REPART_DROPIN}" not in listing:
        return (
            False,
            "initramfs carries systemd-repart without the --discard=no drop-in",
        )
    return True, ""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("aic-find")
    p.add_argument("root", type=Path)
    p = sub.add_parser("repart-root")
    p.add_argument("root", type=Path)
    p = sub.add_parser("repart-initramfs-listing")
    a = ap.parse_args(argv)
    if a.cmd == "aic-find":
        hits = aic_find(a.root)
        for hit in hits:
            print(hit)
        return 1 if hits else 0
    if a.cmd == "repart-root":
        ok, problems = repart_root_ok(a.root)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 0 if ok else 1
    if a.cmd == "repart-initramfs-listing":
        ok, problem = repart_initramfs_ok(sys.stdin.read())
        if problem:
            print(problem, file=sys.stderr)
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
