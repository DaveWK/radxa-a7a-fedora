#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real loader tests and reproducible seed fixture construction."""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

FEDORA = Path(__file__).resolve().parent.parent
CHECK = [sys.executable, "-I", str(FEDORA / "staged-systemd.py")]
PINS = FEDORA / "fixtures/units"
UNIT = "systemd-repart.service"
TEMPLATE = "systemd-repart@.service"
UNIT_DIR = Path("usr/lib/systemd/system")
ADMIN = Path("etc/systemd/system")
ACTIVATE = UNIT_DIR / "sysinit.target.wants" / UNIT
ROOT_UUID = "271cd18e-2557-4afc-8828-ed8f5dac0015"
ESP_UUID = "0102-0304"


def write(root, rel, content):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def fixture(root, mode):
    root.mkdir()
    write(root, UNIT_DIR / "sysinit.target", "[Unit]\nDescription=Fixture sysinit\n")
    if mode == "initramfs":
        return
    for unit in (UNIT, TEMPLATE):
        contents = (PINS / f"root-{unit}.cat-config").read_text()
        marker = f"# /etc/systemd/system/{unit}.d/10-cubie-a7a-no-discard.conf\n"
        fragment, dropin = contents.split(marker, 1)
        fragment = fragment.split("\n", 1)[1].removesuffix("\n")
        write(root, UNIT_DIR / unit, fragment)
        write(root, ADMIN / f"{unit}.d/10-cubie-a7a-no-discard.conf", dropin)
    (root / ACTIVATE).parent.mkdir()
    (root / ACTIVATE).symlink_to(f"../{UNIT}")
    if mode == "no":
        for unit in (UNIT, TEMPLATE):
            (root / ADMIN / unit).symlink_to("/dev/null")
    else:
        write(root, "etc/repart.d/50-root.conf", "[Partition]\nType=root\n")
    grow = ",x-systemd.growfs" if mode == "yes" else ""
    write(
        root,
        "etc/fstab",
        f"UUID={ROOT_UUID} / ext4 defaults{grow} 1 1\n"
        f"UUID={ESP_UUID} /boot/efi vfat umask=0077,shortname=winnt 0 2\n",
    )


def run(root, mode, prefix=()):
    return subprocess.run(
        [
            *prefix,
            *CHECK,
            "check",
            str(root),
            str(PINS),
            mode,
            "--root-uuid",
            ROOT_UUID,
            "--esp-uuid",
            ESP_UUID,
        ],
        text=True,
        capture_output=True,
    )


def require(result, rc, diagnostic=None):
    assert result.returncode == rc, (result.returncode, result.stderr)
    if diagnostic:
        assert diagnostic in result.stderr, result.stderr


def tests(work, base):
    ctx = ["unshare", "--map-auto", "--map-root-user", "--"]
    for mode in ("yes", "no", "initramfs"):
        root = work / f"good-{mode}"
        fixture(root, mode)
        require(run(root, mode), 0)
        if mode == "yes":
            require(run(root, mode, ctx), 0)
    root = work / "good-yes"
    path = ":".join(
        str(root / part)
        for part in (
            "etc/systemd/system",
            "run/systemd/system",
            "usr/local/lib/systemd/system",
            "usr/lib/systemd/system",
        )
    )
    result = subprocess.run(
        [
            *ctx,
            "env",
            f"SYSTEMD_UNIT_PATH={path}",
            "/usr/lib/systemd/systemd",
            "--test",
            "--system",
            f"--unit={UNIT}",
            "--no-pager",
        ],
        text=True,
        capture_output=True,
    )
    require(result, 1, "Don't run test mode as root")
    scopes = (
        "service.d",
        "systemd-.service.d",
        "repart-alias.service.d",
        "systemd-repart@surprise.service.d",
    )
    for i, scope in enumerate(scopes):
        root = work / f"bad-{i}"
        fixture(root, "yes")
        if scope.startswith("repart-alias"):
            (root / UNIT_DIR / "repart-alias.service").symlink_to(UNIT)
        path = write(
            root,
            ADMIN / scope / "50-override.conf",
            "[Service]\nExecStartPre=/usr/bin/false\n",
        )
        require(run(root, "yes"), 1, scope)
        if base is not None:
            previous = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(base),
                    "unit-config",
                    str(root),
                    UNIT,
                    "--fixture",
                    str(PINS / f"root-{UNIT}.cat-config"),
                ],
                text=True,
                capture_output=True,
            )
            require(previous, 0)
            print(f"F7 accepted {scope}")
        path.unlink()
    root = work / "locked"
    fixture(root, "yes")
    unreadable = write(root, ADMIN / "service.d/60-locked.conf", "[Service]\n")
    command = [
        *ctx,
        "sh",
        "-c",
        'chown 1:1 "$1"; chmod 600 "$1"; shift; exec "$@"',
        "sh",
        str(unreadable),
        *CHECK,
        "check",
        str(root),
        str(PINS),
        "yes",
        "--root-uuid",
        ROOT_UUID,
        "--esp-uuid",
        ESP_UUID,
    ]
    require(
        subprocess.run(command, text=True, capture_output=True),
        1,
        "unreadable staged file",
    )
    root = work / "escaped"
    fixture(root, "yes")
    (root / ADMIN / "escape.service").symlink_to("/etc/escape-outside.service")
    require(run(root, "yes"), 1, "escape.service")
    root = work / "no-activate"
    fixture(root, "yes")
    (root / ACTIVATE).unlink()
    require(run(root, "yes"), 1, "does not Want")
    root = work / "bad-fstab"
    fixture(root, "no")
    (root / "etc/fstab").write_text("UUID=wrong / ext4 x-systemd.growfs 1 1\n")
    require(run(root, "no"), 1, "etc/fstab")
    root = work / "bad-repart"
    fixture(root, "yes")
    write(root, "run/repart.d/unexpected.conf", "[Partition]\n")
    require(run(root, "yes"), 1, "repart.d inventory")
    print(
        "real manager, identity, complete drop-ins, activation, fstab and repart policy passed"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-policy", type=Path)
    parser.add_argument(
        "--seed-pins", type=Path, help="generate seed pins into this existing directory"
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="a7a-staged-systemd-") as tmp:
        if args.seed_pins:
            for mode in ("yes", "no", "initramfs"):
                root = Path(tmp) / mode
                fixture(root, mode)
                subprocess.run(
                    [*CHECK, "capture", str(root), str(args.seed_pins), mode],
                    check=True,
                )
        else:
            tests(Path(tmp), args.base_policy)


if __name__ == "__main__":
    main()
