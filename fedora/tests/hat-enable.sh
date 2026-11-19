#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Host tests for cubie-a7a-hat-enable: when python3 is absent from PATH or
# fails at runtime, the modprobe.d check must fail closed (treat modules as
# blocked and never invoke modprobe).
# Run: bash fedora/tests/hat-enable.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script=$here/../rpm/cubie-a7a-hat/cubie-a7a-hat-enable
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
pass=0
fail=0

ok() {
    pass=$((pass + 1))
    echo "ok   $*"
}

bad() {
    fail=$((fail + 1))
    echo "FAIL $*"
}

# Build a minimal bin directory with standard utilities and stub modinfo/modprobe
# that record any module load attempt, and deliberately NO python3.
make_stub_bin() {
    local bin=$1
    mkdir -p "$bin"
    local cmd real
    for cmd in sh bash tr grep mkdir rm cat ls sleep sync uname basename readlink tail head; do
        real=$(command -v "$cmd" 2>/dev/null) || continue
        ln -sf "$real" "$bin/$cmd"
    done
    cat >"$bin/modinfo" <<'STUB'
#!/bin/sh
exit 0
STUB
    cat >"$bin/modprobe" <<'STUB'
#!/bin/sh
if [ "${1:-}" = "-c" ]; then
    exit 0
fi
printf '%s\n' "$*" >>"${HAT_TEST_MODPROBE_LOG:?}"
exit 0
STUB
    chmod +x "$bin/modinfo" "$bin/modprobe"
}

printf 'console=ttyS0\n' >"$tmp/cmdline"
mkdir -p "$tmp/admin"
printf 'blacklist powervr\n' >"$tmp/admin/block.conf"

# 1. PATH without python3: must fail closed and never invoke modprobe.
bin_nopy=$tmp/bin-nopy
make_stub_bin "$bin_nopy"
log1=$tmp/modprobe1.log
: >"$log1"
out=$(env -i PATH="$bin_nopy" \
    HAT_TEST_MODPROBE_LOG="$log1" \
    CUBIE_A7A_HAT_STATE="$tmp/state1" \
    CUBIE_A7A_CMDLINE="$tmp/cmdline" \
    CUBIE_A7A_HAT_SETTLE=0 \
    CUBIE_A7A_MODPROBE_ADMIN_DIRS="$tmp/admin" \
    "$bin_nopy/sh" "$script" 2>&1)
rc=$?
if [ "$rc" -ne 0 ] && [ ! -s "$log1" ]; then
    ok "missing python3 on PATH fails closed without calling modprobe"
else
    bad "missing python3: rc=$rc modprobe=$(cat "$log1") out=$out"
fi

# 2. Broken python3 on PATH (exits 1): blocked() must still fail closed and
#    never call modprobe.
bin_badpy=$tmp/bin-badpy
make_stub_bin "$bin_badpy"
cat >"$bin_badpy/python3" <<'STUB'
#!/bin/sh
exit 1
STUB
chmod +x "$bin_badpy/python3"
log2=$tmp/modprobe2.log
: >"$log2"
out=$(env -i PATH="$bin_badpy" \
    HAT_TEST_MODPROBE_LOG="$log2" \
    CUBIE_A7A_HAT_STATE="$tmp/state2" \
    CUBIE_A7A_CMDLINE="$tmp/cmdline" \
    CUBIE_A7A_HAT_SETTLE=0 \
    CUBIE_A7A_MODPROBE_ADMIN_DIRS="$tmp/admin" \
    "$bin_badpy/sh" "$script" 2>&1)
if [ ! -s "$log2" ] && [[ $out == *"fail closed"* ]]; then
    ok "failing python3 treats every module as blocked and never calls modprobe"
else
    bad "failing python3: modprobe=$(cat "$log2") out=$out"
fi

# 3. Working python3 with admin blacklist: blacklisted powervr is skipped,
#    unblocked modules are loaded.
bin_okpy=$tmp/bin-okpy
make_stub_bin "$bin_okpy"
ln -sf "$(command -v python3)" "$bin_okpy/python3"
log3=$tmp/modprobe3.log
: >"$log3"
out=$(env -i PATH="$bin_okpy" \
    HAT_TEST_MODPROBE_LOG="$log3" \
    CUBIE_A7A_HAT_STATE="$tmp/state3" \
    CUBIE_A7A_CMDLINE="$tmp/cmdline" \
    CUBIE_A7A_HAT_SETTLE=0 \
    CUBIE_A7A_MODPROBE_ADMIN_DIRS="$tmp/admin" \
    "$bin_okpy/sh" "$script" 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && ! grep -qx 'powervr' "$log3" && grep -qx 'vipcore' "$log3"; then
    ok "working python3 respects admin blacklist and loads unblocked modules"
else
    bad "working python3: rc=$rc modprobe=$(cat "$log3") out=$out"
fi

if [ "$fail" -gt 0 ]; then
    echo "$fail test(s) FAILED ($pass passed)"
    exit 1
fi
echo "all hat-enable tests passed ($pass)"
