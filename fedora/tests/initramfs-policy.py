#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic staged-tree integrity fixtures."""

import subprocess
import sys
import tempfile
from pathlib import Path

FEDORA = Path(__file__).resolve().parent.parent
SCRIPT = [sys.executable, "-I", str(FEDORA / "initramfs-policy.py")]


def check(args, rc, want=None):
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == rc, (result.returncode, result.stdout, result.stderr)
    if want:
        assert want in result.stderr, result.stderr
    return result.stdout


def cases(work):
    root = work / "root"
    bootdir = root / "boot"
    bootdir.mkdir(parents=True)
    kernels = work / "kernel.txt"
    kernels.write_text("fixture\n")
    good = bootdir / "initramfs-fixture.img"
    good.write_bytes(b"fixture initramfs bytes")
    check([*SCRIPT, "set", str(root), str(kernels)], 0)
    record = work / "digests.json"
    args = [str(root), str(kernels), str(record)]
    check([*SCRIPT, "capture-digest", *args], 0)
    check([*SCRIPT, "verify-digest", *args], 0)
    good.write_bytes(b"replacement initramfs bytes")
    check([*SCRIPT, "verify-digest", *args], 1, "digest differs")
    extra = bootdir / "initramfs-extra.img"
    extra.write_bytes(b"extra")
    check([*SCRIPT, "set", str(root), str(kernels)], 1, "initramfs-extra.img")
    check([*SCRIPT, "overlay", str(root)], 1, "overlay writes an initramfs entry")
    extra.unlink()
    good.unlink()
    good.symlink_to("absent")
    check([*SCRIPT, "set", str(root), str(kernels)], 1, "not a regular file")

    overlay = work / "overlay"
    overlay.mkdir()
    check([*SCRIPT, "overlay", str(overlay)], 0)
    firmware = overlay / "usr/lib/firmware"
    firmware.mkdir(parents=True)
    (firmware / "replacement.bin").touch()
    check([*SCRIPT, "overlay", str(overlay)], 1, "overlay writes firmware")
    link_overlay = work / "link-overlay"
    link_overlay.mkdir()
    (link_overlay / "usr").symlink_to(overlay / "usr")
    check(
        [*SCRIPT, "overlay", str(link_overlay)], 1, "expected a real staged directory"
    )

    extra = root / "usr/lib/modules/fixture/extra"
    extra.mkdir(parents=True)
    args = [*SCRIPT, "root-modules", str(root), "fixture", "--board", "sun60i-a733-ccu"]
    check(args, 0)
    for name in ("pinctrl-sun60i-a733.ko", "aic-btusb.ko.zst"):
        bad = extra / name
        bad.touch()
        check(args, 1, "forbidden module")
        bad.unlink()
    stage = (FEDORA / "mkdevcard.sh").read_text()
    order = [
        'devcard-policy.py" aic-provenance',
        'chroot "$ROOT" dracut --force',
        'initramfs-policy.py" capture-digest',
        'initramfs-policy.py" overlay',
        'cp -a --no-preserve=ownership "$OVERLAY"',
        'initramfs-policy.py" verify-digest',
        "zstd -t --check --",
        "mkfs.ext4 -q",
    ]
    indexes = [stage.index(command) for command in order]
    assert indexes == sorted(indexes)
    print("staged initramfs paths, overlay veto and root module checks passed")


def main():
    with tempfile.TemporaryDirectory(prefix="a7a-initramfs-") as tmp:
        cases(Path(tmp))


if __name__ == "__main__":
    main()
