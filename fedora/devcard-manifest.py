#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""The build manifest of a Cubie A7A dev card, and its exact verify.

mkdevcard.sh writes `devcard-manifest.json` next to the image after the build.
verify-devcard.sh recomputes the image measurements and requires exact equality.
The profile and RPM inputs are build records, not independently recovered from
the image. Neither side interprets formats beyond hashing the bytes it is
told to: the GPT comes from ``sfdisk --json``, each partition's bytes are
hashed by offset, ESP entries are read with mtools, and the initramfs files
are dumped per path with debugfs. Whether what was built is correct is proven
by the real devcard build and a board boot, not here.

Commands:
  esp-model ESP_DIR OUT
      Write {"files": [...]} of the staged ESP tree ESP_DIR (every file and
      directory with its type and sha256) to OUT, so the build can capture it
      before mtools empties the mount point.
  write IMG ROOT RPM_RECORDS MANIFEST --esp-dir DIR | --esp-model FILE
      Write MANIFEST for the built image IMG: the sfdisk GPT, the sha256 of
      every partition's bytes and of the firmware gap (LBA 256 to the first
      partition), the whole-image sha256, the ESP files (from DIR or FILE),
      the initramfs files under ROOT/boot and the DTB stamps. Record the requested
      build profile and the board RPM inputs (NEVRA, %{ARCH}, sha256) from the
      retained RPM selection. IMG and ROOT are only read.
  verify IMG MANIFEST --expect-manifest-sha256 HEX
      Load MANIFEST, check its schema, and recompute the measurements from IMG:
      the GPT, each partition's and the gap's sha256, the whole image, the
      ESP entries via mtools, and initramfs files and two DTB stamps via
      targeted debugfs reads. HEX comes from the independently retained receipt.
      Require exact equality; print and exit on the first named mismatch.
  check-fat ESP
      Check packed FAT structure read-only; not whether the ESP can boot.
  seal / check-receipt
      Seal or compare build records against the supplied build context and
      digests. Neither command interprets an on-board acceptance record.

Reads only; never mounts and never modifies IMG or MANIFEST.
"""

import argparse
import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

SCHEMA = 2
SECTOR_BYTES = 512
ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
ROOT_TYPE = "B921B045-1DF0-41C3-AF44-4C6F280D3FAE"
# The boot firmware gap: the protective MBR + GPT, then LBA 256 to the first
# partition, where mkdevcard keeps either firmware.bin or zeros.
FIRMWARE_GAP_LBA = 256
ESP_DTB = "dtb/allwinner/sun60i-a733-cubie-a7a.dtb"
FW_DTB_STAMP = "var/lib/cubie-a7a/firmware-dtb-version"
PKG_DTB_VERSION = "usr/lib/cubie-a7a/dtb/VERSION"


class ManifestError(RuntimeError):
    """A manifest could not be written or verified; callers must fail closed."""


def _sha256_path(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _sha256_region(img, offset, size):
    h = hashlib.sha256()
    with open(img, "rb") as fh:
        fh.seek(offset)
        remaining = size
        while remaining > 0:
            block = fh.read(min(1024 * 1024, remaining))
            if not block:
                raise ManifestError(
                    f"{img}: short read at {offset} ({size - remaining}/{size} bytes)"
                )
            h.update(block)
            remaining -= len(block)
    return h.hexdigest()


def _copy_region(img, offset, size, dest):
    with open(img, "rb") as src, open(dest, "wb") as dst:
        src.seek(offset)
        remaining = size
        while remaining > 0:
            block = src.read(min(1024 * 1024, remaining))
            if not block:
                raise ManifestError(
                    f"{img}: short read at {offset} ({size - remaining}/{size} bytes)"
                )
            dst.write(block)
            remaining -= len(block)


def _sfdisk(img):
    r = subprocess.run(["sfdisk", "-J", str(img)], capture_output=True, text=True)
    if r.returncode != 0:
        raise ManifestError(
            f"sfdisk -J {img}: {r.stderr.strip() or f'exit {r.returncode}'}"
        )
    try:
        table = json.loads(r.stdout)["partitiontable"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ManifestError(f"sfdisk -J {img}: corrupt partition table: {exc}") from exc
    return table


def _partition_table_model(img, table):
    """The GPT only: the partitiontable object, with every partition's byte sha256."""
    whole_size = img.stat().st_size
    if whole_size % SECTOR_BYTES:
        raise ManifestError("image: size is not aligned to 512-byte sectors")
    if (
        table.get("label") != "gpt"
        or table.get("unit") != "sectors"
        or table.get("sectorsize") != SECTOR_BYTES
    ):
        raise ManifestError("gpt: expected GPT with 512-byte sectors")
    entries = table.get("partitions")
    if not isinstance(entries, list) or len(entries) != 2:
        raise ManifestError("gpt.partitions: expected exactly two partitions")
    first = table.get("firstlba")
    last = table.get("lastlba")
    if (
        not integer(first)
        or not integer(last)
        or not 0 < first <= last < whole_size // SECTOR_BYTES
    ):
        raise ManifestError("gpt: invalid usable sectors")
    device = table.get("device")
    if not isinstance(device, str) or not device:
        raise ManifestError("gpt: missing partition table device")
    parts = []
    previous_end = first
    for index, (part, kind) in enumerate(
        zip(entries, (ESP_TYPE, ROOT_TYPE), strict=True)
    ):
        prefix = f"gpt.partitions[{index}]"
        if not isinstance(part, dict) or part.get("node") not in (
            f"{device}{index + 1}",
            f"{device}p{index + 1}",
        ):
            raise ManifestError(f"{prefix}.index: missing or unexpected GPT slot")
        start, size = part.get("start"), part.get("size")
        if (
            not integer(start)
            or not integer(size)
            or size <= 0
            or start < previous_end
            or start + size - 1 > last
        ):
            raise ManifestError(f"{prefix}: invalid partition sector range")
        if part.get("type") != kind:
            raise ManifestError(f"{prefix}.type: unexpected partition type")
        previous_end = start + size
        parts.append(
            {
                "index": index,
                "start": start,
                "size": size,
                "type": part.get("type"),
                "uuid": part.get("uuid"),
                "name": part.get("name"),
                "sha256": _sha256_region(
                    img, start * SECTOR_BYTES, size * SECTOR_BYTES
                ),
            }
        )
    # The path-dependent fields sfdisk emits (the image path and each
    # partition's /dev node) are dropped: everything here is stable for the
    # image and so recompute must be byte-identical.
    model = {"partitions": parts, "tablelength": table.get("tablelength", 128)}
    for key in (
        "label",
        "id",
        "unit",
        "firstlba",
        "lastlba",
        "sectorsize",
    ):
        if key in table:
            model[key] = table[key]
    return model


def _gap_model(img, gpt):
    start_lba = gpt["partitions"][0]["start"]
    size = (start_lba - FIRMWARE_GAP_LBA) * SECTOR_BYTES
    if size <= 0:
        raise ManifestError(
            f"{img}: the firmware gap is empty at LBA {FIRMWARE_GAP_LBA}"
        )
    data = _sha256_region(img, FIRMWARE_GAP_LBA * SECTOR_BYTES, size)
    return {
        "label": "firmware-gap",
        "offset": FIRMWARE_GAP_LBA * SECTOR_BYTES,
        "size": size,
        "sha256": data,
    }


def _esp_dir_model(esp_dir):
    """The staged ESP tree's entries: every file and dir, with type and sha256."""
    base = Path(esp_dir)
    files = []
    seen = set()
    if not base.is_dir():
        raise ManifestError(f"{esp_dir} is not a directory")

    def on_error(exc):
        raise ManifestError(f"cannot traverse {exc.filename or base}: {exc}") from exc

    for dirpath, dirnames, filenames in os.walk(base, onerror=on_error):
        cur = Path(dirpath)
        for name in sorted(dirnames) + sorted(filenames):
            path = cur / name
            rel = path.relative_to(base).as_posix()
            key = rel.lower()
            if key in seen:
                raise ManifestError(f"ESP entries collide on FAT: {rel}")
            seen.add(key)
            if path.is_dir() and not path.is_symlink():
                files.append({"path": key, "type": "dir", "sha256": None})
            elif path.is_file() and not path.is_symlink():
                files.append(
                    {"path": key, "type": "file", "sha256": _sha256_path(path)}
                )
            else:
                raise ManifestError(
                    f"ESP entry {rel} is neither a file nor a directory"
                )
    return sorted(files, key=lambda e: e["path"])


def _initramfs_model(root):
    """Every /boot/initramfs-*.img under ROOT, with sha256 (sorted by path)."""
    boot = Path(root) / "boot"
    if boot.is_symlink() or not boot.is_dir():
        raise ManifestError(f"{root}/boot is not a directory")
    files = []
    for path in sorted(boot.glob("initramfs-*.img")):
        if path.is_symlink() or not path.is_file():
            raise ManifestError(f"initramfs entry {path} is not a regular file")
        files.append(
            {
                "path": path.relative_to(Path(root)).as_posix(),
                "sha256": _sha256_path(path),
            }
        )
    if not files:
        raise ManifestError(f"no initramfs-*.img under {root}/boot")
    return files


def _rpm_model(records):
    """Rehash the DNF inputs against the records held since RPM selection."""
    if not isinstance(records, list) or not records:
        raise ManifestError("no retained RPM snapshot records")
    entries = []
    for rec in records:
        if not isinstance(rec, dict) or not all(
            isinstance(rec.get(key), str) and rec[key]
            for key in ("nevra", "arch", "path", "sha256")
        ):
            raise ManifestError(f"incomplete RPM snapshot record {rec!r}")
        target = Path(rec["path"])
        if target.is_symlink() or not target.is_file():
            raise ManifestError(f"missing or non-regular consumed RPM {target}")
        actual = _sha256_path(target)
        if actual != rec["sha256"]:
            raise ManifestError(f"sha256 mismatch for consumed RPM {target}")
        entries.append({"nevra": rec["nevra"], "arch": rec["arch"], "sha256": actual})
    return sorted(entries, key=lambda e: e["nevra"])


def write_manifest(img, root, esp_files, rpm_records, manifest, profile, firmware):
    img = Path(img)
    root = Path(root)
    gpt = _partition_table_model(img, _sfdisk(img))
    payload = {
        "schema": SCHEMA,
        "profile": profile,
        "gpt": gpt,
        "gap": _gap_model(img, gpt),
        "firmware": firmware,
        "esp": {"files": esp_files},
        "initramfs": _initramfs_model(root),
        "dtb": {
            "esp_dtb": ESP_DTB,
            "firmware_stamp_sha256": _sha256_path(root / FW_DTB_STAMP),
            "package_stamp_sha256": _sha256_path(root / PKG_DTB_VERSION),
        },
        "rpms": _rpm_model(rpm_records),
        "image_sha256": _sha256_path(img),
    }
    validate_manifest(payload)
    verify_firmware_region(img, payload)
    write_json(manifest, payload)
    return payload


def write_json(out, payload):
    out = Path(out)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{out.name}.", dir=out.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True, allow_nan=False)
            fh.write("\n")
        os.replace(tmp_name, out)
    finally:
        Path(tmp_name).unlink(missing_ok=True)


# --- strict manifest schema -------------------------------------------------

HEX = re.compile(r"[0-9a-f]{64}")
GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
INITRAMFS = re.compile(r"boot/initramfs-[A-Za-z0-9][A-Za-z0-9_.+~-]*\.img")
ESP_PATH = re.compile(r"[a-z0-9_.+-]+(?:/[a-z0-9_.+-]+)*")
STAMP = re.compile(rb"[0-9]{1,9}\n")
ESP_DTB_MARK = ESP_DTB + ".cubie-a7a-dtb"


def integer(value):
    return type(value) is int


def fields(value, wanted, label):
    if not isinstance(value, dict):
        raise ManifestError(f"{label}: expected an object")
    missing = set(wanted.split()) - value.keys()
    extra = value.keys() - set(wanted.split())
    if missing or extra:
        raise ManifestError(
            f"{label}: missing fields {sorted(missing)}, unknown fields {sorted(extra)}"
        )


def matches(value, pattern, label):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ManifestError(f"{label}: invalid value")


def digest(value, label):
    matches(value, HEX, label)


def nonempty(value, label):
    if not isinstance(value, list) or not value:
        raise ManifestError(f"{label}: expected a nonempty list")
    return value


def unique(values, value, label):
    if value in values:
        raise ManifestError(f"{label}: duplicate value {value!r}")
    values.add(value)


def validate_profile(profile):
    fields(profile, "boot_modes grow_root first_boot", "profile")
    if profile["boot_modes"] not in ("", "protective"):
        raise ManifestError("profile.boot_modes: invalid value")
    if profile["grow_root"] not in ("yes", "no"):
        raise ManifestError("profile.grow_root: invalid value")
    first = profile["first_boot"]
    if first not in ("", "maintenance") or (
        first and profile["boot_modes"] != "protective"
    ):
        raise ManifestError("profile.first_boot: invalid value for boot_modes")


def validate_manifest(data):
    fields(
        data,
        "schema profile gpt gap firmware esp initramfs dtb rpms image_sha256",
        "manifest",
    )
    if not integer(data["schema"]) or data["schema"] != SCHEMA:
        raise ManifestError("manifest.schema: unsupported version")
    validate_profile(data["profile"])
    digest(data["image_sha256"], "image_sha256")
    gpt = data["gpt"]
    fields(
        gpt, "label id unit firstlba lastlba sectorsize tablelength partitions", "gpt"
    )
    if (gpt["label"], gpt["unit"], gpt["sectorsize"]) != (
        "gpt",
        "sectors",
        SECTOR_BYTES,
    ):
        raise ManifestError("gpt: expected GPT with 512-byte sectors")
    matches(gpt["id"], GUID, "gpt.id")
    for key in ("firstlba", "lastlba", "sectorsize", "tablelength"):
        if not integer(gpt[key]) or gpt[key] <= 0:
            raise ManifestError(f"gpt.{key}: expected positive integer")
    parts = nonempty(gpt["partitions"], "gpt.partitions")
    if len(parts) != 2:
        raise ManifestError("gpt.partitions: expected exactly two partitions")
    previous_end = gpt["firstlba"]
    for index, (entry, kind) in enumerate(
        zip(parts, (ESP_TYPE, ROOT_TYPE), strict=True)
    ):
        label = f"gpt.partition[{index}]"
        fields(entry, "index start size type uuid name sha256", label)
        if not integer(entry["index"]) or entry["index"] != index:
            raise ManifestError(f"{label}.index: does not match its slot")
        start, size = entry["start"], entry["size"]
        if (
            not integer(start)
            or not integer(size)
            or size <= 0
            or start < previous_end
            or start + size - 1 > gpt["lastlba"]
        ):
            raise ManifestError(f"{label}: invalid partition sector range")
        previous_end = start + size
        if entry["type"] != kind or not isinstance(entry["name"], str):
            raise ManifestError(f"{label}: invalid type or name")
        matches(entry["uuid"], GUID, f"{label}.uuid")
        digest(entry["sha256"], f"{label}.sha256")
    gap = data["gap"]
    fields(gap, "label offset size sha256", "gap")
    if (
        gap["label"] != "firmware-gap"
        or not integer(gap["offset"])
        or gap["offset"] != FIRMWARE_GAP_LBA * SECTOR_BYTES
    ):
        raise ManifestError("gap: invalid label or offset")
    if (
        not integer(gap["size"])
        or gap["size"] <= 0
        or gap["offset"] + gap["size"] != parts[0]["start"] * SECTOR_BYTES
    ):
        raise ManifestError("gap.size: inconsistent with the GPT")
    digest(gap["sha256"], "gap.sha256")
    fw = data["firmware"]
    if fw is not None:
        fields(fw, "seek_lba size sha256", "firmware")
        if (
            not integer(fw["seek_lba"])
            or fw["seek_lba"] < FIRMWARE_GAP_LBA
            or not integer(fw["size"])
            or fw["size"] <= 0
            or fw["seek_lba"] * SECTOR_BYTES + fw["size"]
            > parts[0]["start"] * SECTOR_BYTES
        ):
            raise ManifestError("firmware: invalid seek or size for the recorded gap")
        digest(fw["sha256"], "firmware.sha256")
    fields(data["esp"], "files", "esp")
    esp_paths = set()
    for entry in nonempty(data["esp"]["files"], "esp.files"):
        label = "esp.files entry"
        fields(entry, "path type sha256", label)
        matches(entry["path"], ESP_PATH, f"{label}.path")
        if {".", ".."}.intersection(entry["path"].split("/")):
            raise ManifestError(f"{label}.path: unsafe path")
        unique(esp_paths, entry["path"], label)
        if entry["type"] == "file":
            digest(entry["sha256"], f"esp.files {entry['path']}.sha256")
        elif entry["type"] != "dir" or entry["sha256"] is not None:
            raise ManifestError(
                f"esp.files {entry['path']}: invalid entry type or digest"
            )
    stamps = data["dtb"]
    fields(stamps, "esp_dtb firmware_stamp_sha256 package_stamp_sha256", "dtb")
    if stamps["esp_dtb"] != ESP_DTB:
        raise ManifestError("dtb.esp_dtb: unexpected path")
    for key in ("firmware_stamp_sha256", "package_stamp_sha256"):
        digest(stamps[key], f"dtb.{key}")
    initramfs_paths = set()
    for entry in nonempty(data["initramfs"], "initramfs"):
        fields(entry, "path sha256", "initramfs entry")
        matches(entry["path"], INITRAMFS, "initramfs.path")
        unique(initramfs_paths, entry["path"], "initramfs.path")
        digest(entry["sha256"], f"initramfs {entry['path']}.sha256")
    packages = set()
    for entry in nonempty(data["rpms"], "rpms"):
        fields(entry, "nevra arch sha256", "rpms entry")
        nevra, arch = entry["nevra"], entry["arch"]
        if arch not in ("aarch64", "noarch"):
            raise ManifestError("rpms.arch: invalid architecture")
        if (
            not isinstance(nevra, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+~^:-]*", nevra)
            or not nevra.endswith(f".{arch}")
        ):
            raise ManifestError("rpms.nevra: invalid NEVRA for architecture")
        unique(packages, nevra, "rpms.nevra")
        digest(entry["sha256"], "rpms.sha256")


def load_json(raw, label):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ManifestError(f"{label}: duplicate JSON field {key!r}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ManifestError(f"{label}: invalid JSON constant {value}")

    try:
        return json.loads(
            raw, object_pairs_hook=object_pairs, parse_constant=invalid_constant
        )
    except (ValueError, RecursionError) as exc:
        raise ManifestError(f"{label}: invalid JSON: {exc}") from exc


def verify_firmware_region(img, data):
    firmware = data["firmware"]
    if firmware is not None:
        actual = _sha256_region(
            img, firmware["seek_lba"] * SECTOR_BYTES, firmware["size"]
        )
        _compare("firmware.sha256 at recorded seek", firmware["sha256"], actual)


# --- verify ----------------------------------------------------------------


def _mtools_esp_model(esp_file):
    """ESP entries read from a FAT image FILE with mtools: names, types, sha256."""
    esp = str(esp_file)
    r = subprocess.run(
        ["mdir", "-/", "-b", "-i", esp, "::/"], capture_output=True, text=True
    )
    if r.returncode != 0 or r.stderr.strip():
        raise ManifestError(
            f"mdir failed on {esp}: {r.stderr.strip() or f'exit {r.returncode}'}"
        )
    entries = {}
    for raw in r.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("::/"):
            raise ManifestError(f"malformed mdir row on {esp}: {raw!r}")
        kind = "dir" if line.endswith("/") else "file"
        rel = line[3:].rstrip("/").lower()
        if not rel or rel in entries:
            raise ManifestError(f"invalid or duplicate mdir entry on {esp}: {raw!r}")
        entries[rel] = kind
    files = []
    for rel in sorted(entries):
        if entries[rel] == "dir":
            files.append({"path": rel, "type": "dir", "sha256": None})
            continue
        r = subprocess.run(
            ["mcopy", "-n", "-i", esp, f"::{rel}", "-"], capture_output=True
        )
        if r.returncode != 0 or r.stderr.strip():
            raise ManifestError(f"cannot read ::{rel} from {esp}")
        files.append({"path": rel, "type": "file", "sha256": _sha256_bytes(r.stdout)})
    return files


def _debugfs_dump(root_file, path, dest):
    r = subprocess.run(
        ["debugfs", "-R", f'dump "{path}" "{dest.name}"', str(root_file)],
        cwd=dest.parent,
        capture_output=True,
        text=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    # debugfs prints its banner to stderr; an inode read failure can still
    # return success, so any other diagnostic fails. The dump's size is checked
    # against the manifest's sha256 next, so a short dump is caught there.
    diagnostics = [
        line
        for line in r.stderr.splitlines()
        if line.strip() and not line.startswith("debugfs ")
    ]
    if r.returncode != 0 or diagnostics:
        raise ManifestError(
            f"debugfs dump {path}: {'; '.join(diagnostics) or f'exit {r.returncode}'}"
        )


def _verify_initramfs(root_file, manifest_files, tmp):
    got = []
    for entry in manifest_files["initramfs"]:
        rel = entry["path"]
        dest = tmp / Path(rel).name
        _debugfs_dump(root_file, "/" + rel, dest)
        got.append({"path": rel, "sha256": _sha256_path(dest)})
        dest.unlink()
    return got


def _compare(label, expected, actual):
    if actual != expected:
        raise ManifestError(
            f"{label} mismatch: manifest and image differ "
            f"(first difference at {label})"
        )


def _compare_partitions(expected_gpt, actual_gpt):
    for key in sorted(expected_gpt.keys() - {"partitions"}):
        _compare(f"gpt.{key}", expected_gpt[key], actual_gpt[key])
    for index, (exp, got) in enumerate(
        zip(expected_gpt["partitions"], actual_gpt["partitions"], strict=True)
    ):
        for key in exp:
            _compare(f"gpt.partition[{index}].{key}", exp[key], got[key])


def _verify_stamps(root_file, tmp, stamps):
    # The shipped root stamps agree with the sealed manifest, not a DTB handoff.
    for key, rel in (
        ("firmware_stamp_sha256", FW_DTB_STAMP),
        ("package_stamp_sha256", PKG_DTB_VERSION),
    ):
        dest = tmp / "dtb-version-stamp"
        if dest.exists():
            raise ManifestError("dtb: unexpected scratch file")
        _debugfs_dump(root_file, "/" + rel, dest)
        if not dest.is_file():
            raise ManifestError(f"dtb.{key}: missing /{rel}")
        with dest.open("rb") as stream:
            raw = stream.read(11)  # Valid stamps are at most ten bytes.
        if not STAMP.fullmatch(raw):
            raise ManifestError(f"dtb.{key}: malformed /{rel}")
        _compare(f"dtb.{key} (/{rel})", stamps[key], _sha256_bytes(raw))
        dest.unlink()


def _verify_dtb_marker(files):
    by_path = {e["path"]: e for e in files}
    dtb, marker = by_path.get(ESP_DTB), by_path.get(ESP_DTB_MARK)
    if dtb is None and marker is None:
        return
    if not dtb or not marker or dtb["type"] != "file" or marker["type"] != "file":
        raise ManifestError(
            "dtb: packed ESP DTB and payload marker must occur together"
        )
    _compare(
        "dtb ESP payload marker",
        _sha256_bytes((dtb["sha256"] + "\n").encode()),
        marker["sha256"],
    )


def _compare_esp(expected, actual):
    expected = {e["path"]: e for e in expected}
    actual = {e["path"]: e for e in actual}
    for path in sorted(expected.keys() | actual.keys()):
        _compare(f"esp.files {path}", expected.get(path), actual.get(path))


def scratch_directory():
    value = os.environ.get("TMPDIR")
    if not value or not Path(value).is_absolute():
        raise ManifestError(
            "TMPDIR: set an absolute existing verifier scratch directory"
        )
    path = Path(value).resolve(strict=True)
    if not path.is_dir() or any(
        path.is_relative_to(prefix) for prefix in (Path("/tmp"), Path("/var/tmp"))
    ):
        raise ManifestError(
            "TMPDIR: verifier scratch must be outside /tmp and /var/tmp"
        )
    return path


def verify_manifest(img, manifest, expected):
    digest(expected, "--expect-manifest-sha256")
    if not manifest.is_file():
        raise ManifestError(f"manifest: missing or not a regular file: {manifest}")
    raw = manifest.read_bytes()
    # Bind the exact manifest bytes to the independently retained build receipt first.
    _compare("expected manifest sha256", expected, _sha256_bytes(raw))
    data = load_json(raw, "manifest")
    validate_manifest(data)
    if not img.is_file():
        raise ManifestError(f"image: missing or not a regular file: {img}")
    for tool in ("sfdisk", "mdir", "mcopy", "debugfs", "fsck.fat"):
        if shutil.which(tool) is None:
            raise ManifestError(f"required verifier tool missing: {tool}")
    scratch = scratch_directory()
    # One GPT read supplies geometry, hash regions and the packed filesystem offsets.
    gpt = _partition_table_model(img, _sfdisk(img))
    _compare_partitions(data["gpt"], gpt)
    _compare("gap", data["gap"], _gap_model(img, gpt))
    _compare("image_sha256", data["image_sha256"], _sha256_path(img))
    verify_firmware_region(img, data)
    # Each partition copy is dense: ROOT.size * 512 and ESP.size * 512 bytes.
    with tempfile.TemporaryDirectory(prefix="a7a-manifest-", dir=scratch) as td:
        tmp = Path(td)
        esp_file, root_file = tmp / "esp.img", tmp / "root.img"
        for partition, target in zip(
            gpt["partitions"], (esp_file, root_file), strict=True
        ):
            _copy_region(
                img,
                partition["start"] * SECTOR_BYTES,
                partition["size"] * SECTOR_BYTES,
                target,
            )
        check_fat(esp_file)
        actual_esp = _mtools_esp_model(esp_file)
        _compare_esp(data["esp"]["files"], actual_esp)
        _verify_dtb_marker(actual_esp)
        _verify_stamps(root_file, tmp, data["dtb"])
        for exp, got in zip(
            data["initramfs"], _verify_initramfs(root_file, data, tmp), strict=True
        ):
            _compare(f"initramfs {exp['path']}.sha256", exp["sha256"], got["sha256"])
    # The already sealed profile and RPM inputs describe the build, not the image.
    return data


def check_fat(path):
    # Read-only structural check; not a check of the contents or EFI boot.
    proc = subprocess.run(["fsck.fat", "-n", str(path)], capture_output=True, text=True)
    if proc.returncode:
        raise ManifestError(
            f"packed ESP fsck.fat -n: exit {proc.returncode}: {(proc.stderr or proc.stdout).strip()}"
        )


def firmware_checks(info, firmware, main_bin):
    # Bind the examined bytes to the manifest region; this is not execution proof.
    if main_bin is not None and not main_bin.is_file():
        raise ManifestError(f"MAIN_BIN: missing or not a regular file: {main_bin}")
    if firmware is None:
        if main_bin is not None:
            raise ManifestError("MAIN_BIN: --firmware is required")
        return
    if not firmware.is_file():
        raise ManifestError(f"firmware: missing or not a regular file: {firmware}")
    if info is None:
        raise ManifestError("firmware: no embedded firmware recorded in the manifest")
    with firmware.open("rb") as stream:
        blob = stream.read(info["size"] + 1)
    _compare("firmware.size", info["size"], len(blob))
    _compare("firmware.sha256 supplied", info["sha256"], _sha256_bytes(blob))
    if blob[4:12] != b"eGON.BT0":
        raise ManifestError("firmware: missing eGON header at recorded seek")
    fw = runpy.run_path(str(Path(__file__).with_name("fwcheck.py")))
    for marker in (b"A7AFWLOG", b"oreboot,firmware-log"):
        if not fw["fd_has"](blob, marker):
            raise ManifestError(f"firmware: expected log marker {marker.decode()}")
    if main_bin is not None:
        with main_bin.open("rb") as stream:
            main_bytes = stream.read(len(blob) + 1)
        if not main_bytes or main_bytes not in blob:
            raise ManifestError("MAIN_BIN: examined bytes are not embedded in firmware")
        if not fw["main_fwlog"](main_bytes):
            raise ManifestError("MAIN_BIN: firmware log handler not found")


def read_regular(path, label):
    if not path.is_file():
        raise ManifestError(f"{label}: missing or not a regular file: {path}")
    return path.read_bytes()


def _args_profile(args):
    return dict(
        boot_modes=args.boot_modes, grow_root=args.grow_root, first_boot=args.first_boot
    )


def receipt_payload(args):
    # Source/run/profile name the build inputs; they are not recovered from the image.
    matches(args.source_commit, re.compile(r"[0-9a-f]{40}"), "source_commit")
    matches(args.run_id, re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*"), "run_id")
    raw = read_regular(args.manifest, "manifest")
    digest(args.expect_manifest_sha256, "expected manifest sha256")
    _compare(
        "expected manifest sha256", args.expect_manifest_sha256, _sha256_bytes(raw)
    )
    manifest = load_json(raw, "manifest")
    validate_manifest(manifest)
    profile = _args_profile(args)
    _compare("receipt.profile", profile, manifest["profile"])
    firmware = manifest["firmware"]
    if firmware is not None:
        matches(
            args.dram_identity,
            re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,127}"),
            "profile.dram_firmware.identity",
        )
        dram = {"identity": args.dram_identity, "sha256": firmware["sha256"]}
    else:
        if args.dram_identity:
            raise ManifestError(
                "profile.dram_firmware: identity provided for a firmware-less image"
            )
        dram = None
    profile["dram_firmware"] = dram
    for label in ("started_utc", "finished_utc"):
        value = getattr(args, label)
        matches(
            value,
            re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"),
            label,
        )
        try:
            datetime.fromisoformat(value)
        except ValueError as exc:
            raise ManifestError(f"{label}: invalid UTC timestamp") from exc
    if args.finished_utc < args.started_utc:
        raise ManifestError("finished_utc: earlier than started_utc")
    # These digests bind the checked build artifacts, not whether they boot.
    snapshot_raw = read_regular(args.rpm_snapshot, "rpm snapshot")
    snapshot = _sha256_bytes(snapshot_raw)
    digest(args.expect_snapshot_sha256, "expected RPM snapshot sha256")
    _compare("rpm-snapshot.json sha256", args.expect_snapshot_sha256, snapshot)
    records = load_json(snapshot_raw, "rpm-snapshot.json")
    fields(records, "run_id rpms", "rpm-snapshot.json")
    _compare("rpm-snapshot.json.run_id", args.run_id, records["run_id"])
    snapshot_rpms = []
    for record in nonempty(records["rpms"], "rpm-snapshot.json.rpms"):
        keys = ("nevra", "arch", "sha256")
        if not isinstance(record, dict) or not all(
            isinstance(record.get(key), str) for key in keys
        ):
            raise ManifestError("rpm-snapshot.json.rpms: incomplete RPM record")
        snapshot_rpms.append({key: record[key] for key in keys})
    _compare(
        "manifest.rpms against sealed snapshot",
        sorted(snapshot_rpms, key=lambda e: e["nevra"]),
        manifest["rpms"],
    )
    bound = load_json(
        read_regular(args.initramfs_digests, "initramfs digest map"),
        "initramfs digest map",
    )
    _compare(
        "bound initramfs digest map",
        bound,
        {Path(e["path"]).name: e["sha256"] for e in manifest["initramfs"]},
    )
    if not args.img.is_file():
        raise ManifestError("image: missing or not a regular file")
    image_sha256 = _sha256_path(args.img)
    _compare("receipt.image_sha256", manifest["image_sha256"], image_sha256)
    return {
        "schema": 1,
        "source_commit": args.source_commit,
        "run_id": args.run_id,
        "profile": profile,
        "started_utc": args.started_utc,
        "finished_utc": args.finished_utc,
        "image_sha256": image_sha256,
        "manifest_sha256": args.expect_manifest_sha256,
        "rpm_snapshot_sha256": snapshot,
        "initramfs": manifest["initramfs"],
        "dtb": manifest["dtb"],
        "firmware": firmware,
    }


def check_receipt(raw, expected):
    # Build-record consistency only; the on-board acceptance schema is separate.
    actual = load_json(raw, "receipt")
    fields(actual, " ".join(expected), "receipt")
    if not integer(actual["schema"]):
        raise ManifestError("receipt.schema: expected an integer")
    for name in expected:
        _compare(f"receipt.{name}", expected[name], actual[name])


def profile_args(parser):
    parser.add_argument("--boot-modes", choices=("", "protective"), required=True)
    parser.add_argument("--grow-root", choices=("yes", "no"), required=True)
    parser.add_argument("--first-boot", choices=("", "maintenance"), required=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("esp-model")
    p.add_argument("esp_dir", type=Path)
    p.add_argument("out", type=Path)
    p = sub.add_parser("write")
    p.add_argument("img", type=Path)
    p.add_argument("root", type=Path)
    p.add_argument("rpm_records")
    p.add_argument("manifest", type=Path)
    profile_args(p)
    p.add_argument("--firmware-sha256")
    p.add_argument("--firmware-seek", type=int)
    p.add_argument("--firmware-size", type=int)
    esp = p.add_mutually_exclusive_group(required=True)
    esp.add_argument("--esp-dir", type=Path)
    esp.add_argument("--esp-model", type=Path)
    p = sub.add_parser("verify", allow_abbrev=False)
    p.add_argument("img", type=Path)
    p.add_argument("manifest", type=Path)
    p.add_argument("--expect-manifest-sha256", required=True)
    p.add_argument("--firmware", type=Path)
    p.add_argument("--main-bin", type=Path)
    p = sub.add_parser("check-fat")
    p.add_argument("esp", type=Path)
    for cmd in ("seal", "check-receipt"):
        p = sub.add_parser(cmd)
        for arg in ("img", "manifest", "receipt", "rpm_snapshot", "initramfs_digests"):
            p.add_argument(arg, type=Path)
        profile_args(p)
        for arg in (
            "source-commit",
            "run-id",
            "started-utc",
            "finished-utc",
            "expect-manifest-sha256",
            "expect-snapshot-sha256",
        ):
            p.add_argument(f"--{arg}", required=True)
        p.add_argument("--dram-identity", default="")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "esp-model":
            payload = {"files": _esp_dir_model(a.esp_dir)}
            write_json(a.out, payload)
        elif a.cmd == "write":
            if a.esp_dir is not None:
                esp_files = _esp_dir_model(a.esp_dir)
            else:
                try:
                    esp_files = json.loads(Path(a.esp_model).read_text())["files"]
                except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise ManifestError(
                        f"cannot read esp-model {a.esp_model}: {exc}"
                    ) from exc
            try:
                rpm_records = json.loads(a.rpm_records)
            except json.JSONDecodeError as exc:
                raise ManifestError(f"cannot read retained RPM records: {exc}") from exc
            firmware = None
            if any(
                value is not None
                for value in (a.firmware_sha256, a.firmware_seek, a.firmware_size)
            ):
                firmware = dict(
                    sha256=a.firmware_sha256,
                    seek_lba=a.firmware_seek,
                    size=a.firmware_size,
                )
            write_manifest(
                a.img,
                a.root,
                esp_files,
                rpm_records,
                a.manifest,
                _args_profile(a),
                firmware,
            )
            print(_sha256_path(a.manifest))
        elif a.cmd == "verify":
            data = verify_manifest(a.img, a.manifest, a.expect_manifest_sha256)
            firmware_checks(data["firmware"], a.firmware, a.main_bin)
        elif a.cmd == "check-fat":
            check_fat(a.esp)
        else:
            expected = receipt_payload(a)
            if a.cmd == "seal":
                write_json(a.receipt, expected)
            check_receipt(read_regular(a.receipt, "receipt"), expected)
        return 0
    except (ManifestError, OSError, ValueError, RecursionError) as exc:
        print(f"devcard-manifest: {a.cmd}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
