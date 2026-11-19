#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Prove a dev card image is exactly what a checked fedora/mkdevcard.sh build
# produced: the manifest it wrote, recomputed byte for byte. Reads only; not a
# board test.
#
# Usage: fedora/verify-devcard.sh IMAGE MANIFEST [FIRMWARE]
#   IMAGE      the raw disk image (mkdevcard.sh's OUT)
#   MANIFEST   the build manifest (OUT.devcard-manifest.json, next to the image)
#   FIRMWARE   optional firmware.bin embedded at LBA 256; when given, its
#              read-back, eGON header and boot-log strings are checked too
#              (FWREPO=<tree> and MAIN_BIN=<path> select the boot-chain inputs,
#              as for mkdevcard.sh).
#
# The manifest holds each value mkdevcard.sh recorded from the build -- the GPT,
# the sha256 of every partition's bytes and of the firmware gap, the whole
# image, the ESP entries (via mtools) and the initramfs (via debugfs per path) --
# and every one is recomputed here and required to match exactly. The first
# mismatch is named. No CPIO, zstd, systemd, ext4-walk or FAT-listing logic:
# verify interprets no format beyond hashing the bytes it is told to.
set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
IMG=${1:?usage: verify-devcard.sh IMAGE MANIFEST [FIRMWARE]}
MANIFEST=${2:?usage: verify-devcard.sh IMAGE MANIFEST [FIRMWARE]}
FW=${3:-none}

die() {
    echo "verify-devcard: $*" >&2
    exit 1
}
for t in sfdisk mdir mcopy debugfs python3; do
    command -v $t >/dev/null || die "$t not found"
done
[ -f "$IMG" ] || die "image $IMG does not exist"
[ -f "$MANIFEST" ] || die "manifest $MANIFEST does not exist"

# The whole proof: schema check, GPT, each partition's and the gap's sha256, the
# whole image, the ESP entries (types and sha256 via mtools) and the initramfs
# files (per-path debugfs dump). Exact equality; the first difference is named.
python3 -I "$TOP/fedora/devcard-manifest.py" verify "$IMG" "$MANIFEST" ||
    die "the image is not exactly what the build manifest records"

if [ "$FW" != none ] && [ -f "$FW" ]; then
    cmp -n "$(stat -c %s "$FW")" -i 0:131072 "$FW" "$IMG" ||
        die "firmware.bin at sector 256 does not read back"
    dd if="$IMG" bs=1 skip=$((131072 + 4)) count=8 status=none | grep -q 'eGON.BT0' ||
        die "eGON header not found at 128 KiB"
    python3 -I "$TOP/fedora/fwcheck.py" fd-has A7AFWLOG "$FW" ||
        die "EDK2 FD does not log to RAM (A7AFWLOG)"
    python3 -I "$TOP/fedora/fwcheck.py" fd-has oreboot,firmware-log "$FW" ||
        die "EDK2 FD does not publish /chosen/oreboot,firmware-log"
    if [ -n "${MAIN_BIN:-}" ] && [ -f "$MAIN_BIN" ]; then
        python3 -I "$TOP/fedora/fwcheck.py" main-fwlog "$MAIN_BIN" ||
            die "main.bin lacks the firmware log handler"
    fi
fi

echo "verify-devcard: $IMG matches $MANIFEST exactly"
