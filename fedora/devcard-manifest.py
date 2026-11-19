#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""The build manifest of a Cubie A7A dev card, and its exact verify.

mkdevcard.sh writes `devcard-manifest.json` next to the image after the build;
verify-devcard.sh recomputes every value in it from the image and requires
exact equality. Neither side interprets formats beyond hashing the bytes it is
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
      the initramfs files under ROOT/boot, the DTB stamps, and board RPMs (NEVRA, %{ARCH}, sha256) using the
       JSON records retained from RPM selection, plus the requested build
       profile. IMG and ROOT are only read.
  verify IMG MANIFEST
      Load MANIFEST, check its schema, and recompute every value from IMG:
      the GPT, each partition's and the gap's sha256, the whole image, the
      ESP entries via mtools, and the initramfs files via debugfs per path.
      Require exact equality; print and exit on the first named mismatch or a
      tampered manifest.

Reads only; never mounts and never modifies IMG or MANIFEST.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCHEMA = 1
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


def _partition_table_model(img):
    """The GPT only: the partitiontable object, with every partition's byte sha256."""
    table = _sfdisk(img)
    parts = []
    for index, part in enumerate(table["partitions"]):
        start = int(part["start"])
        size = int(part["size"])
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
    model = {"partitions": parts}
    for key in (
        "label",
        "id",
        "unit",
        "firstlba",
        "lastlba",
        "sectorsize",
        "tablelength",
    ):
        if key in table:
            model[key] = table[key]
    return model


def _first_partition_start(img):
    table = _sfdisk(img)
    parts = table.get("partitions", [])
    if not parts:
        raise ManifestError(f"{img}: no partitions in the GPT")
    return min(int(p["start"]) for p in parts)


def _gap_model(img):
    start_lba = _first_partition_start(img)
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
            if path.is_dir():
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
    if not boot.is_dir():
        raise ManifestError(f"{root}/boot is not a directory")
    files = []
    for path in sorted(boot.glob("initramfs-*.img")):
        if not path.is_file():
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


def write_manifest(img, root, esp_files, rpm_records, manifest, profile):
    img = Path(img)
    root = Path(root)
    payload = {
        "schema": SCHEMA,
        "profile": profile,
        "gpt": _partition_table_model(img),
        "gap": _gap_model(img),
        "esp": {"files": esp_files},
        "initramfs": _initramfs_model(root),
        "dtb": {
            # The ESP DTB is part of esp.files (its digest is re-read from the
            # image at verify); the two stamps that decided whether it was
            # placed on the ESP are recorded with their sha256, and are covered
            # at verify by the root partition's whole-byte sha256.
            "esp_dtb": ESP_DTB,
            "firmware_stamp_sha256": _sha256_path(root / FW_DTB_STAMP),
            "package_stamp_sha256": _sha256_path(root / PKG_DTB_VERSION),
        },
        "rpms": _rpm_model(rpm_records),
        "image_sha256": _sha256_path(img),
    }
    out = Path(manifest)
    fd, tmp_name = tempfile.mkstemp(
        prefix=".devcard-manifest.", suffix=".tmp", dir=out.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp_name, out)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return payload


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
        ["debugfs", "-R", f'dump "{path}" "{dest}"', str(root_file)],
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
    exp_parts = expected_gpt.get("partitions", [])
    got_parts = actual_gpt.get("partitions", [])
    # Normalize: the signature-proven fields, then every partition's bytes.
    for key in (
        "label",
        "id",
        "unit",
        "firstlba",
        "lastlba",
        "sectorsize",
        "tablelength",
    ):
        _compare(f"gpt.{key}", expected_gpt.get(key), actual_gpt.get(key))
    _compare("gpt.partition count", len(exp_parts), len(got_parts))
    for index, (exp, got) in enumerate(zip(exp_parts, got_parts)):
        for field in ("start", "size", "type", "uuid", "name"):
            _compare(f"gpt.partition[{index}].{field}", exp.get(field), got.get(field))
        _compare(f"gpt.partition[{index}].sha256", exp.get("sha256"), got.get("sha256"))


def verify_manifest(img, manifest):
    img = Path(img)
    mpath = Path(manifest)
    try:
        data = json.loads(mpath.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {mpath}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ManifestError(f"{mpath}: missing or wrong schema {data.get('schema')!r}")

    _compare_partitions(data.get("gpt"), _partition_table_model(img))
    _compare("gap", data.get("gap"), _gap_model(img))
    _compare("image_sha256", data.get("image_sha256"), _sha256_path(img))

    # Locate the ESP and root partitions for the per-file reads.
    table = _sfdisk(img)

    def find(ftype):
        for p in table["partitions"]:
            if str(p["type"]).upper().startswith(ftype):
                return int(p["start"]) * SECTOR_BYTES, int(p["size"]) * SECTOR_BYTES
        raise ManifestError(f"{img}: no partition of type {ftype}")

    with tempfile.TemporaryDirectory(prefix="a7a-manifest-") as td:
        tmp = Path(td)
        esp_off, esp_size = find(ESP_TYPE)
        root_off, root_size = find(ROOT_TYPE)
        esp_file = tmp / "esp.img"
        root_file = tmp / "root.img"
        _copy_region(img, esp_off, esp_size, esp_file)
        _copy_region(img, root_off, root_size, root_file)

        exp_esp = data.get("esp", {}).get("files")
        if not isinstance(exp_esp, list):
            raise ManifestError(f"{mpath}: missing esp.files")
        _compare("esp.files", exp_esp, _mtools_esp_model(esp_file))

        exp_initramfs = data.get("initramfs")
        if not isinstance(exp_initramfs, list):
            raise ManifestError(f"{mpath}: missing initramfs")
        _compare("initramfs", exp_initramfs, _verify_initramfs(root_file, data, tmp))

    # RPM files and DTB stamps are read off the image's tree
    # only through the digests already recorded: nothing more is recomputed.
    return data


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
    p.add_argument("--boot-modes", choices=("", "protective"), required=True)
    p.add_argument("--grow-root", choices=("yes", "no"), required=True)
    p.add_argument("--first-boot", choices=("", "maintenance"), required=True)
    esp = p.add_mutually_exclusive_group(required=True)
    esp.add_argument("--esp-dir", type=Path)
    esp.add_argument("--esp-model", type=Path)
    p = sub.add_parser("verify")
    p.add_argument("img", type=Path)
    p.add_argument("manifest", type=Path)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "esp-model":
            payload = {"files": _esp_dir_model(a.esp_dir)}
            out = a.out
            fd, tmp_name = tempfile.mkstemp(
                prefix=".esp-model.", suffix=".tmp", dir=out.parent
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2, sort_keys=True)
                    fh.write("\n")
                os.replace(tmp_name, out)
            except Exception:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
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
            payload = write_manifest(
                a.img,
                a.root,
                esp_files,
                rpm_records,
                a.manifest,
                {
                    "boot_modes": a.boot_modes,
                    "grow_root": a.grow_root,
                    "first_boot": a.first_boot,
                },
            )
            print(_sha256_path(a.manifest))
        else:
            verify_manifest(a.img, a.manifest)
        return 0
    except (ManifestError, OSError) as exc:
        print(f"devcard-manifest: {a.cmd}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
