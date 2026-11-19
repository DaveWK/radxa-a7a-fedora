#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Record what the closed VIPLite runtime submits to the NPU through vipcore
# (built with VIPCORE_CAPTURE=1; see ../CAPTURE.md). Run as root on the
# board:
#
#   sh npu-capture.sh [-m MODE] [-n TASKS] [-o OUT_ROOT] [-l LABEL] -- COMMAND...
#
#   -m MODE   1 = video memory before the trigger, 2 = NPU-writable memory
#             after completion, 4 = the "before" snapshot on every task
#             instead of once per block (default 3)
#   -n TASKS  tasks to record (default 4)
#   -o DIR    default $NPU_CAPTURE_DIR, else /var/lib/cubie-a7a/npu-captures
#   -l LABEL  default the command's basename
#
# Example, the VIPLite ShuffleNetV2 sample, one inference:
#   cd /opt/viplite/vpm_run && sh npu-capture.sh -l shufflenetv2-l1 -- \
#       ./vpm_run -s sample.txt -l 1 -b 0 --show_top5 1
#
# Writes OUT_ROOT/<UTC time>-<label>/: capture.bin, control-before.txt,
# control-after.txt, command.txt, run.log, dmesg.txt, vip_info.txt,
# SHA256SUMS, and CAPTURE-DERIVED. Split it with python3 npu-capture-split.py.
set -eu

mode=3
tasks=4
root=${NPU_CAPTURE_DIR:-/var/lib/cubie-a7a/npu-captures}
label=
while getopts m:n:o:l: opt; do
    case $opt in
    m) mode=$OPTARG ;;
    n) tasks=$OPTARG ;;
    o) root=$OPTARG ;;
    l) label=$OPTARG ;;
    *) exit 2 ;;
    esac
done
shift $((OPTIND - 1))
[ "${1:-}" = -- ] && shift
[ $# -gt 0 ] || {
    echo "npu-capture: give the command to run after --" >&2
    exit 2
}

cap=/sys/kernel/debug/vipcore_capture
[ -w $cap/control ] || {
    echo "npu-capture: $cap/control is missing: load a vipcore built with VIPCORE_CAPTURE=1 (as root, debugfs mounted)" >&2
    exit 2
}
[ -n "$label" ] || label=$(basename "$1")
out=$root/$(date -u +%Y%m%dT%H%M%SZ)-$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' _)
mkdir -p "$out"

printf '%s\n' "$*" >"$out/command.txt"
cat $cap/control >"$out/control-before.txt"
echo "arm $mode $tasks" >$cap/control

rc=0
"$@" >"$out/run.log" 2>&1 || rc=$?
echo "exit $rc" >>"$out/run.log"

echo disarm >$cap/control
cat $cap/control >"$out/control-after.txt"
cat $cap/data >"$out/capture.bin"
echo free >$cap/control
dmesg | tail -200 >"$out/dmesg.txt"
[ -r /sys/kernel/debug/viplite/vip_info ] && cat /sys/kernel/debug/viplite/vip_info >"$out/vip_info.txt"

cat >"$out/CAPTURE-DERIVED" <<EOF
CAPTURE-DERIVED: data captured through the GPL vipcore driver while the closed
VIPLite runtime ran. Data capture only. Anything written from it
must carry the CAPTURE-DERIVED tag. Not for git.
EOF
(cd "$out" && sha256sum -- * >SHA256SUMS.tmp && grep -v ' SHA256SUMS.tmp$' SHA256SUMS.tmp >SHA256SUMS && rm SHA256SUMS.tmp)
echo "npu-capture: $out ($(stat -c %s "$out/capture.bin") bytes, command exit $rc)"
grep -E '^(tasks|records|used|dropped) ' "$out/control-after.txt" | tr '\n' ' '
echo
