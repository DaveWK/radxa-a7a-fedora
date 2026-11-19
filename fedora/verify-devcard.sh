#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Verify sealed bytes, not bootability, runtime policy or a DTB handoff.
# Usage: fedora/verify-devcard.sh IMAGE MANIFEST --expect-manifest-sha256 HEX
#        [--firmware FIRMWARE] [--main-bin MAIN_BIN]
# HEX comes from the independently retained CI receipt, never the image directory.
# TMPDIR must name approved absolute scratch: dense ESP + dense root partition
# (each partition's sector count × 512 bytes), plus one targeted dump at a time.
set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
IMG=${1:?usage: verify-devcard.sh IMAGE MANIFEST --expect-manifest-sha256 HEX [--firmware FILE]}
MANIFEST=${2:?missing manifest}
shift 2
verify_args=("$@")
# Refuse ambiguous legacy configuration instead of dropping a firmware request.
if [[ ${FW-none} != none ]]; then
    echo "verify-devcard: legacy FW is unsupported; pass --firmware FILE explicitly" >&2
    exit 2
fi
if [[ -v MAIN_BIN ]]; then
    for arg in "$@"; do
        case $arg in
        --main-bin | --main-bin=*)
            echo "verify-devcard: use either MAIN_BIN or --main-bin" >&2
            exit 2
            ;;
        esac
    done
    verify_args+=(--main-bin "$MAIN_BIN")
fi

# Expected manifest digest is checked first: a self-consistent swapped pair is not this build.
# GPT, gap, image and partitions prove byte identity; not whether the image can boot.
# FAT and ESP prove packed structure and staged file equality; not firmware execution.
# Targeted root DTB stamp and initramfs digests prove shipped bytes, not the boot handoff.
# Optional firmware and main.bin checks bind the examined bytes at the recorded seek,
# not that the board used those bytes. Profile/RPM inputs are sealed build records.
python3 -I "$TOP/fedora/devcard-manifest.py" verify "$IMG" "$MANIFEST" "${verify_args[@]}"
printf 'verify-devcard: %s matches the independently sealed manifest %s\n' "$IMG" "$MANIFEST"
