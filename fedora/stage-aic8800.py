#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Stage and check the AIC8800 driver package's inputs.

cubie-a7a-aic8800-usb is built from an external driver tree (AIC8800_SRC),
which can carry firmware or out-of-tree copies of other code.  This tool
stages only the reviewed driver inputs named in driver-inputs.list (verifying
every file's recorded SHA256), refuses any source tree that contains
firmware-looking files, and checks the built RPM's payload (rpm -qlp) to
ensure no firmware files and nothing outside the listed outputs are packaged.

Commands:
  stage SRC OUT VERSION --list FILE
      Copy every listed path from SRC into OUT/aic8800-usb-VERSION after
      verifying its SHA256, write OUT/SOURCES/aic8800-usb-VERSION.inputs.sha256,
      and tar the directory to OUT/SOURCES/aic8800-usb-VERSION.tar.gz.
      Fails when a listed file is missing, its SHA256 mismatches, a path
      escapes SRC, or SRC holds firmware.
  payload RPM --list FILE
      Print every RPM payload path that is firmware-looking, unlisted, or
      missing from the listed inputs; exit 1 when any problem is found.
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

PKG = "cubie-a7a-aic8800-usb"
STAGE_DIR = "aic8800-usb"
FIRMWARE_SUFFIXES = (".bin", ".dat", ".fw", ".hex", ".img")
FIRMWARE_PREFIXES = ("fw_", "fmacfw", "lmacfw")
FIRMWARE_DIRS = ("fw", "firmware", "aic8800_fw")
AIC_FW_DIR_RE = re.compile(r"^aic8800(?:_fw|d\d|dc|dl)", re.IGNORECASE)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SPEC_OUTPUTS = frozenset(
    {
        "/usr/bin/cubie-a7a-wifi-firmware",
        "/usr/lib/modprobe.d/cubie-a7a-aic8800.conf",
        "/usr/lib/udev/rules.d/60-cubie-a7a-aic8800.rules",
        "/usr/libexec/cubie-a7a",
        "/usr/libexec/cubie-a7a/aic-udev",
        f"/usr/libexec/cubie-a7a/dkms-{PKG}",
        "/usr/share/cubie-a7a",
        "/usr/share/cubie-a7a/WIFI-FIRMWARE.md",
        "/usr/share/cubie-a7a/aic8800-d80-usb.manifest",
        f"/usr/share/licenses/{PKG}",
        f"/usr/share/licenses/{PKG}/COPYING",
    }
)


def _strip_compression(name):
    for ext in (".xz", ".zst"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


def firmware_name(path):
    """True when PATH names a firmware file or firmware directory."""
    parts = PurePosixPath(path).parts
    if not parts:
        return False
    lower_parts = [p.lower() for p in parts]
    # Any path under /usr/lib/firmware or /lib/firmware is firmware.
    for idx in range(len(lower_parts) - 1):
        if lower_parts[idx] == "lib" and lower_parts[idx + 1] == "firmware":
            return True
    for part in lower_parts[:-1]:
        if part in FIRMWARE_DIRS or AIC_FW_DIR_RE.match(part):
            return True
    name = lower_parts[-1]
    base = _strip_compression(name)
    if base.endswith(FIRMWARE_SUFFIXES) or base.startswith(FIRMWARE_PREFIXES):
        return True
    return False


def read_list(path):
    """Parse ``<sha256>  <relpath>`` records from FILE."""
    entries = []
    seen = set()
    for number, raw in enumerate(Path(path).read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise SystemExit(
                f"{path}:{number}: expected '<sha256>  <path>', got {raw!r}"
            )
        digest, rel_str = parts[0].lower(), parts[1].strip()
        if not SHA256_RE.fullmatch(digest):
            raise SystemExit(f"{path}:{number}: invalid sha256 {digest!r}")
        rel = PurePosixPath(rel_str)
        if rel.is_absolute() or ".." in rel.parts or not rel.parts:
            raise SystemExit(f"{path}:{number}: unsafe driver input {rel_str!r}")
        if firmware_name(rel.as_posix()):
            raise SystemExit(
                f"{path}:{number}: firmware path forbidden in driver list: {rel_str!r}"
            )
        key = rel.as_posix()
        if key in seen:
            raise SystemExit(f"{path}:{number}: duplicate driver input {rel_str!r}")
        seen.add(key)
        entries.append((digest, rel))
    if not entries:
        raise SystemExit(f"{path}: no driver inputs listed")
    return entries


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def find_firmware(src):
    hits = []
    for path in sorted(Path(src).rglob("*")):
        if path.is_file() or path.is_symlink():
            if firmware_name(path.relative_to(src).as_posix()):
                hits.append(str(path))
    return hits


def stage(src, out, version, list_path):
    src = Path(src).resolve()
    out = Path(out).resolve()
    entries = read_list(list_path)
    firmware = find_firmware(src)
    if firmware:
        for path in firmware:
            print(f"refusing firmware in the driver source: {path}", file=sys.stderr)
        return 1
    root_name = f"{STAGE_DIR}-{version}"
    dest = out / root_name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    records = []
    for expected_digest, rel in entries:
        source = src / rel
        if source.is_symlink() or not source.is_file():
            print(
                f"missing or non-regular reviewed driver input: {rel}", file=sys.stderr
            )
            return 1
        actual_digest = sha256(source)
        if actual_digest != expected_digest:
            print(
                f"sha256 mismatch for reviewed driver input {rel}: "
                f"actual {actual_digest}, expected {expected_digest}",
                file=sys.stderr,
            )
            return 1
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        os.chmod(target, os.stat(source).st_mode & 0o777)
        records.append((actual_digest, rel.as_posix()))
    # Nothing outside the reviewed list may be in the staged tree.
    staged = sorted(
        p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()
    )
    expected = sorted(rel.as_posix() for _, rel in entries)
    if staged != expected:
        print(
            f"staged tree differs from the reviewed list: "
            f"extra={sorted(set(staged) - set(expected))} "
            f"missing={sorted(set(expected) - set(staged))}",
            file=sys.stderr,
        )
        return 1
    sources = out / "SOURCES"
    sources.mkdir(parents=True, exist_ok=True)
    manifest = sources / f"{root_name}.inputs.sha256"
    manifest.write_text("".join(f"{digest}  {rel}\n" for digest, rel in records))
    tarball = sources / f"{root_name}.tar.gz"

    def normalize(info):
        info.mtime = 0
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        return info

    with tarfile.open(tarball, "w:gz") as tf:
        tf.add(dest, arcname=root_name, filter=normalize, recursive=True)
    # Read back the tarball and verify it holds only the listed inputs.
    with tarfile.open(tarball, "r:gz") as tf:
        tar_files = sorted(
            PurePosixPath(m.name).relative_to(root_name).as_posix()
            for m in tf.getmembers()
            if m.isfile()
        )
    if tar_files != expected or any(firmware_name(p) for p in tar_files):
        print(f"tarball {tarball} failed read-back verification", file=sys.stderr)
        return 1
    print(f"staged {len(records)} reviewed driver inputs in {tarball}")
    print(f"recorded their SHA256 values in {manifest}")
    return 0


def dkms_ver_of(rpm):
    result = subprocess.run(
        ["rpm", "-qp", "--qf", "%{VERSION}-%{RELEASE}", str(rpm)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _allowed_payload_paths(dkms_ver, entries):
    base = PurePosixPath(f"/usr/src/{PKG}-{dkms_ver}")
    allowed_files = {str(base / rel) for _, rel in entries}
    allowed_dirs = {str(base)}
    for _, rel in entries:
        cur = base / rel
        for parent in cur.parents:
            if parent == base:
                break
            allowed_dirs.add(str(parent))
    return allowed_files, allowed_files | allowed_dirs | SPEC_OUTPUTS


def payload(rpm, list_path):
    entries = read_list(list_path)
    dkms_ver = dkms_ver_of(rpm)
    required_driver_files, allowed_all = _allowed_payload_paths(dkms_ver, entries)
    result = subprocess.run(
        ["rpm", "-qlp", str(rpm)], capture_output=True, text=True, check=True
    )
    paths = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    problems = []
    for path in paths:
        if firmware_name(path):
            problems.append(f"{path}: firmware-looking payload file")
        elif path not in allowed_all:
            if "fw" in PurePosixPath(path).name.lower():
                problems.append(f"{path}: unlisted firmware-like payload file")
            else:
                problems.append(f"{path}: not a listed package output")
    path_set = set(paths)
    for path in sorted(required_driver_files - path_set):
        problems.append(f"{path}: reviewed driver input missing from the RPM")
    for problem in problems:
        print(problem)
    if problems:
        return 1
    print(
        f"{rpm}: payload holds only the {len(entries)} reviewed driver inputs "
        f"and listed package outputs"
    )
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("stage")
    p.add_argument("src", type=Path)
    p.add_argument("out", type=Path)
    p.add_argument("version")
    p.add_argument("--list", type=Path, required=True)
    p = sub.add_parser("payload")
    p.add_argument("rpm", type=Path)
    p.add_argument("--list", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.cmd == "stage":
        return stage(a.src, a.out, a.version, a.list)
    if a.cmd == "payload":
        return payload(a.rpm, a.list)
    return 2


if __name__ == "__main__":
    sys.exit(main())
