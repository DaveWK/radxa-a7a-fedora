#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Native GNU cpio/zstd regression fixtures; never creates a device node."""

import argparse
import gzip
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

FEDORA = Path(__file__).resolve().parent.parent
SCRIPT = [sys.executable, "-I", str(FEDORA / "initramfs-policy.py")]
D = stat.S_IFDIR | 0o755
F = stat.S_IFREG | 0o644
L = stat.S_IFLNK | 0o777
C = stat.S_IFCHR | 0o600
NODES = (
    ("dev/null", 1, 3),
    ("dev/kmsg", 1, 11),
    ("dev/console", 5, 1),
    ("dev/random", 1, 8),
    ("dev/urandom", 1, 9),
)


def record(name, mode, inode, data=b"", major=0, minor=0):
    encoded = name.encode() + b"\0"
    values = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0)
    header = b"070701" + "".join(f"{value:08x}" for value in values).encode() + encoded
    return header + bytes(-len(header) % 4) + data + bytes(-len(data) % 4)


def archive(entries):
    return b"".join(
        record(*row[:2], n + 1, *row[2:]) for n, row in enumerate(entries)
    ) + record("TRAILER!!!", 0, 0)


def compress(data):
    return subprocess.run(
        ["zstd", "-qc", "--check"], input=data, capture_output=True, check=True
    ).stdout


def check(args, rc, want=None):
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == rc, (result.returncode, result.stdout, result.stderr)
    if want:
        assert want in result.stderr, result.stderr
    return result.stdout


def cases(work, base):
    dirs = [("etc", D), ("dev", D), ("usr", D), ("usr/lib", D)]
    regular = dirs + [("usr/lib/x", F, b"test"), ("etc/absolute", L, b"/usr/lib/x")]
    common = regular + [("etc/mtab", L, b"/proc/self/mounts")]

    def unpack(tag, payload, err=None, *, packed=False):
        img = work / (tag + ".img")
        out = work / (tag + "-out")
        img.write_bytes(payload if packed else compress(archive(payload)))
        message = check([*SCRIPT, "unpack", str(img), str(out)], int(bool(err)), err)
        return out, message

    zero, info = unpack("zero", common)
    assert os.readlink(zero / "etc/absolute") == "/usr/lib/x"
    assert (zero / "usr/lib/x").read_text() == "test"
    assert os.readlink(zero / "etc/mtab") == "/proc/self/mounts"
    assert "device inventory empty" in info
    all_nodes = [(name, C, b"", major, minor) for name, major, minor in NODES]
    five, info = unpack("five", common + all_nodes)
    assert list((five / "dev").iterdir()) == [] and info.count("(not extracted)") == 5
    print(info.strip())
    for tag, entry in (
        ("six", ("dev/mem", C, b"", 1, 1)),
        ("wrong-dev", ("dev/null", C, b"", 9, 9)),
        ("fifo", ("dev/fifo", stat.S_IFIFO | 0o600)),
        ("socket", ("dev/socket", stat.S_IFSOCK | 0o600)),
        ("block", ("dev/null", stat.S_IFBLK | 0o600, b"", 1, 3)),
    ):
        unpack(tag, common + [entry], f"unapproved archive member {entry[0]}")
    unpack(
        "wrong-mtab",
        regular + [("etc/mtab", L, b"/proc/self/fd")],
        "wrong runtime symlink",
    )
    unpack(
        "outside",
        common + [("etc/outside", L, b"/not-an-archive-member")],
        "etc/outside",
    )
    unpack("dangling", common + [("etc/dangling", L, b"missing")], "etc/dangling")
    unpack("loop", common + [("etc/loop", L, b"loop")], "symlink loop")
    unpack(
        "bad-magic", gzip.compress(archive(common)), "expected zstd magic", packed=True
    )
    unpack(
        "early",
        archive([("early", F, b"microcode")]) + compress(archive(common)),
        "no early CPIO",
        packed=True,
    )
    unpack("truncated", compress(archive(common))[:-7], "zstd exit", packed=True)
    unpack(
        "linked-parent",
        common + [("etc/absolute/inside", F, b"unexpected")],
        "non-directory parent",
    )
    if base:
        check(
            [
                sys.executable,
                "-I",
                str(base),
                "initramfs-unpack",
                str(work / "bad-magic.img"),
                str(work / "old-gzip"),
            ],
            0,
        )
        print("F7 accepted the non-zstd fixture")

    root = work / "root"
    bootdir = root / "boot"
    bootdir.mkdir(parents=True)
    kernels = work / "kernel.txt"
    kernels.write_text("fixture\n")
    good = bootdir / "initramfs-fixture.img"
    good.write_bytes(compress(archive(common)))
    check([*SCRIPT, "set", str(root), str(kernels)], 0)
    extra = bootdir / "initramfs-extra.img"
    extra.write_bytes(b"extra")
    check([*SCRIPT, "set", str(root), str(kernels)], 1, "initramfs-extra.img")
    check([*SCRIPT, "overlay", str(root)], 1, "overlay writes an initramfs entry")
    extra.unlink()
    good.unlink()
    good.symlink_to("absent")
    check([*SCRIPT, "set", str(root), str(kernels)], 1, "not a regular file")

    extracted = work / "modules"
    modules = extracted / "usr/lib/modules/fixture"
    extra = modules / "extra"
    extra.mkdir(parents=True)
    for rel in ("extra/sun60i-a733-ccu.ko.zst", "sunxi-mmc.ko", "overlay.ko"):
        (modules / rel).write_text("fixture")
    forced = extracted / "etc/cmdline.d/20-force_drivers.conf"
    forced.parent.mkdir(parents=True)
    forced.write_text("rd.driver.pre=sun60i_a733_ccu\n")
    volatile = extracted / "usr/lib/systemd/systemd-volatile-root"
    volatile.parent.mkdir()
    volatile.write_text("fixture")
    args = [
        *SCRIPT,
        "modules",
        str(extracted),
        "fixture",
        "--board",
        "sun60i-a733-ccu",
        "--stock",
        "sunxi-mmc",
        "--protective",
    ]
    check(args, 0)
    bad = extra / "pinctrl-sun60i-a733.ko"
    bad.write_text("overlay replacement fixture")
    check(args, 1, "forbidden module")
    bad.unlink()
    forced.write_text("rd.driver.pre=pinctrl\n")
    check(args, 1, "wrong forced A733 drivers")
    stage = (FEDORA / "mkdevcard.sh").read_text()
    assert stage.index('initramfs-policy.py" overlay') < stage.index(
        'cp -a --no-preserve=ownership "$OVERLAY"'
    )
    for check_name in (
        'initramfs-policy.py" set',
        'initramfs-policy.py" unpack',
        'initramfs-policy.py" modules',
        'image-firmware.py" audit',
    ):
        assert stage.index(check_name) > stage.index("\nSTAGE1\n")
    print("native complete archive, exceptions, staged wiring and module tests passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-policy", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="a7a-initramfs-") as tmp:
        cases(Path(tmp), args.base_policy)


if __name__ == "__main__":
    main()
