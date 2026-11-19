#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check staged ESP admission against signed Fedora RPM file lists."""

import hashlib
import importlib.util
import re
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures/esp/rpm-esp-files.txt"
ESP_PREFIX = Path("/boot/efi")
PACKAGES = ("efi-filesystem", "grub2-efi-aa64", "shim-aa64")

# Additional paths created by the image builder, if any. grub.cfg is written
# by fedora/mkdevcard.sh:520, but is already listed (%ghost) by grub2-efi-aa64.
# The shim and GRUB posttrans copies also go to paths listed in their RPMs.
BUILD_ONLY_FILES = ()


def stage_rpm_entries(esp):
    sections = FIXTURE.read_text(encoding="utf-8").strip().split("\n\n")
    if len(sections) != len(PACKAGES):
        raise ValueError("expected one file list per Fedora RPM")
    for package, section in zip(PACKAGES, sections):
        header, *paths = section.splitlines()
        nevra, digest = header.split()
        if (
            not re.fullmatch(re.escape(package) + r"-\d+:\S+\.\w+", nevra)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not paths
        ):
            raise ValueError(f"invalid RPM file-list section: {header}")
        for path in paths:
            rel = Path(path).relative_to(ESP_PREFIX)
            if rel == Path(".") or ".." in rel.parts:
                raise ValueError(f"invalid ESP path: {path}")
            entry = esp / rel
            # The efi-filesystem RPM owns the ESP directories only. Keep
            # names and case as recorded; esp_staged does the FAT mapping.
            if package == "efi-filesystem":
                entry.mkdir(parents=True, exist_ok=True)
            else:
                entry.parent.mkdir(parents=True, exist_ok=True)
                entry.touch()
    for rel in BUILD_ONLY_FILES:
        entry = esp / rel
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.touch()


def main():
    spec = importlib.util.spec_from_file_location(
        "devcard_policy", HERE.parent / "devcard-policy.py"
    )
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    with TemporaryDirectory(prefix="a7a-esp-entries-") as work:
        root = Path(work)
        esp = root / "boot/efi"
        stage_rpm_entries(esp)

        # Supply matching DTB stamps and RPM metadata to select the base ESP
        # branch. Only the unrelated DTB RPM queries are mocked.
        records = {}
        for rel, data in (
            (policy.FW_DTB_STAMP, b"8\n"),
            (policy.PKG_DTB_VERSION, b"8\n"),
            (policy.PKG_DTB, b"fixture DTB"),
        ):
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            records[rel] = (hashlib.sha256(data).hexdigest(), True)
        identity = CompletedProcess([], 0, stdout=policy.PKG_DTB_PACKAGE)
        with (
            patch.object(policy.subprocess, "run", return_value=identity),
            patch.object(policy, "_rpm_dump", return_value=records),
        ):
            ok, problems = policy.esp_staged(root, esp, root / "stub-dtb.rpm")

    if not ok:
        for problem in problems:
            print(problem)
        return 1
    print("ESP entries and directories match the Fedora RPM file lists")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
