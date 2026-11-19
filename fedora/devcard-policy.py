#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Image-policy checks shared by fedora/mkdevcard.sh and
fedora/verify-devcard.sh.

Python 3, run with -I by the shell scripts; the host tests import it.  Every
command prints a stable, shell-friendly result and exits nonzero on a policy
violation, so a caller can use it directly as a check.

Commands:
  aic-find ROOT       AIC8800 firmware files in ROOT's firmware tree, by path
                      pattern and by the driver package's manifest names
                      (DECISIONS 2026-11-11: user opt-in only, never an image).
                      Prints one path per line; exit 1 when any is found.
"""

import argparse
import re
import sys
from pathlib import Path

AIC_PATTERN = re.compile(r"aic8800", re.IGNORECASE)
MANIFEST = "usr/share/cubie-a7a/aic8800-d80-usb.manifest"
FIRMWARE = "usr/lib/firmware"


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


def aic_find(root):
    """Every AIC8800 file in the image's firmware tree.

    Two independent tests, as the decision requires: the path pattern
    (``aic8800`` anywhere under /usr/lib/firmware, which catches both
    linux-firmware's aic/aic8800d80 and an overlay's aic8800_fw) and each
    manifest name with its optional .xz/.zst suffix (which catches a copy
    under an unrelated directory).
    """
    fw = Path(root) / FIRMWARE
    hits = []
    for path in _under_firmware(root):
        if AIC_PATTERN.search(str(path.relative_to(fw))):
            hits.append(str(path))
    names = aic_manifest_names(root)
    if names:
        wanted = set()
        for name in names:
            wanted.update((name, name + ".xz", name + ".zst"))
        for path in _under_firmware(root):
            if path.name in wanted and str(path) not in hits:
                hits.append(str(path))
    return sorted(hits)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("aic-find")
    p.add_argument("root", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "aic-find":
        hits = aic_find(a.root)
        for hit in hits:
            print(hit)
        return 1 if hits else 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
