#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check a firmware.bin for the firmware-log pieces (the firmware log format).

fwcheck.py fd-has STRING FIRMWARE_BIN   STRING in the EDK2 FD's compressed FV
fwcheck.py main-fwlog MAIN_BIN          main.bin has the log magic and the
                                        SiP 0x82000002 handler returning the base
"""

import lzma
import re
import struct
import sys

LZMA_GUID = bytes.fromhex(
    "98584eee143959429d6edc7bd79403cf"
)  # EE4E5898-3914-4259-9D6E-DC7BD79403CF


def lzma_sections(blob):
    for m in re.finditer(re.escape(LZMA_GUID), blob):
        start = m.start() - 4  # EFI_GUID_DEFINED_SECTION
        if start < 0 or m.start() + 18 > len(blob):
            continue
        size = int.from_bytes(blob[start : start + 3], "little")
        if blob[start + 3] != 0x02 or size < 24:
            continue
        data_off = struct.unpack_from("<H", blob, m.start() + 16)[0]
        try:
            yield lzma.decompress(
                blob[start + data_off : start + size], format=lzma.FORMAT_ALONE
            )
        except lzma.LZMAError:
            continue


def main_fwlog(blob):
    if len(blob) % 4 or b"A7AFWLOG" not in blob:
        return False
    words = struct.unpack_from("<%dI" % (len(blob) // 4), blob)
    for i, w in enumerate(words):
        # movz wN, #2 ; movk wN, #0x8200, lsl #16  (SIP_FWLOG_BASE = 0x82000002)
        if (
            w & 0xFFFFFFE0 == 0x52800040
            and i + 1 < len(words)
            and words[i + 1] == 0x72B04000 | (w & 0x1F)
        ):
            # ... then mov wM, #0x40140000 (CUR_BASE) within a few instructions
            if any(x & 0xFFFFFFE0 == 0x52A80280 for x in words[i + 2 : i + 8]):
                return True
    return False


def fd_has(blob, needle):
    return needle in blob or any(needle in fv for fv in lzma_sections(blob))


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "fd-has":
        with open(sys.argv[3], "rb") as stream:
            sys.exit(0 if fd_has(stream.read(), sys.argv[2].encode()) else 1)
    if cmd == "main-fwlog":
        with open(sys.argv[2], "rb") as stream:
            sys.exit(0 if main_fwlog(stream.read()) else 1)
    sys.exit(2)
