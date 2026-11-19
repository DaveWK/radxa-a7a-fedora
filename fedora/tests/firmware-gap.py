#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run mkdevcard's firmware recording and write blocks on a synthetic image."""

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main

SEEK = 256
ESP_START = 4096
SECTOR = 512
FIRMWARE = b"firmware fixture\x00" * 61  # Deliberately not sector-aligned.
SOURCE = Path(__file__).resolve().parent.parent / "mkdevcard.sh"


class FirmwareGap(TestCase):
    def run_blocks(self, mutation=":", stray_tail=False):
        source = SOURCE.read_text()
        # Keep this on the real shell blocks, without running image assembly.
        record_start = source.index("DRAM_FIRMWARE_IDENTITY=${")
        record_end = source.index("# Read the run's snapshot", record_start)
        write_start = source.index('if [ -n "$FIRMWARE" ]; then\n')
        write_end = source.index("# Read back what was written.", write_start)
        die_start = source.index("die() {\n")
        die_end = source.index("\n}\n", die_start) + len("\n}\n")
        program = "\n".join(
            [
                "set -euo pipefail",
                "FIRMWARE=$1 W=$2 OUT=$3 ESP_START=$4",
                "DRAM_FIRMWARE_IDENTITY=fixture",
                source[die_start:die_end],
                source[record_start:record_end],
                'printf "%s %s\\n" "$FW_SIZE" "${FW_SHA%% *}"',
                mutation,
                source[write_start:write_end],
            ]
        )
        with tempfile.TemporaryDirectory(prefix="a7a-firmware-gap-") as tmp:
            work = Path(tmp)
            firmware = work / "firmware.bin"
            firmware.write_bytes(FIRMWARE)
            image = work / "card.img"
            offset = SEEK * SECTOR
            with image.open("wb") as stream:
                stream.truncate((ESP_START + 1) * SECTOR)
                if stray_tail:
                    stream.seek(offset + len(FIRMWARE))
                    stream.write(b"\x01")
            result = subprocess.run(
                ["bash", "-s", "--", firmware, work / "build", image, str(ESP_START)],
                input=program,
                text=True,
                capture_output=True,
            )
            with image.open("rb") as stream:
                stream.seek(offset)
                region = stream.read(len(FIRMWARE))
                tail = stream.read(ESP_START * SECTOR - offset - len(FIRMWARE))
        return result, region, tail

    def assert_bound(self, result, region, tail):
        self.assertEqual(result.returncode, 0, result.stderr)
        size, digest = result.stdout.split()
        self.assertEqual(int(size), len(FIRMWARE))
        self.assertEqual(digest, hashlib.sha256(FIRMWARE).hexdigest())
        self.assertEqual(
            hashlib.sha256(region).hexdigest(), digest, "written firmware digest"
        )
        self.assertFalse(any(tail), "non-zero bytes in the firmware gap tail")

    def test_late_growth(self):
        self.assert_bound(
            *self.run_blocks('head -c 512 /dev/zero | tr "\\000" X >>"$FIRMWARE"')
        )

    def test_same_size_change(self):
        self.assert_bound(
            *self.run_blocks('printf X | dd of="$FIRMWARE" conv=notrunc status=none')
        )

    def test_normal_firmware(self):
        self.assert_bound(*self.run_blocks())

    def test_stray_tail_byte(self):
        result, _, _ = self.run_blocks(stray_tail=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("firmware gap tail not zero", result.stderr)


if __name__ == "__main__":
    main(verbosity=2)
