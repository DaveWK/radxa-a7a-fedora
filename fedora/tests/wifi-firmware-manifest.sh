#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Host tests for cubie-a7a-wifi-firmware's manifest handling: an empty,
# missing, unreadable or malformed manifest is an error, never an
# "installed 0/0" status, and first_required() must skip comments.
# Run: bash fedora/tests/wifi-firmware-manifest.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
pkg_dir=$here/../rpm/cubie-a7a-aic8800-usb
script=$pkg_dir/cubie-a7a-wifi-firmware
real_manifest=$pkg_dir/aic8800-d80-usb.manifest
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

status_with() { # MANIFEST
    env CUBIE_A7A_WIFI_MANIFEST="$1" \
        CUBIE_A7A_WIFI_FWDIR="$tmp/fw" \
        CUBIE_A7A_LINUX_FWDIR="$tmp/lf" \
        CUBIE_A7A_SYSFS="$tmp/sysfs" \
        "$script" status 2>&1
}

expect_manifest_error() { # NAME MANIFEST EXPECTED-SUBSTRING
    local name=$1 manifest=$2 want=$3 out rc
    out=$(status_with "$manifest")
    rc=$?
    if [ "$rc" -eq 0 ]; then
        bad "$name: exited 0"
        return
    fi
    case $out in
    *"installed (0/0"* | *"installed 0/0"*)
        bad "$name: reported installed 0/0"
        return
        ;;
    esac
    case $out in
    *"$want"*) ok "$name" ;;
    *) bad "$name: message lacks '$want': $out" ;;
    esac
}

mkdir -p "$tmp/sysfs"
sha_a=$(printf 'a%.0s' {1..64})
sha_b=$(printf 'b%.0s' {1..64})
sha_c=$(printf 'c%.0s' {1..64})

# Missing manifest.
expect_manifest_error "missing manifest" "$tmp/nope.manifest" "missing or unreadable"

# Empty manifest.
: >"$tmp/empty.manifest"
expect_manifest_error "empty manifest" "$tmp/empty.manifest" "has no entries"

# Comments-only manifest.
printf '# only a comment\n   # another comment\n' >"$tmp/comments-only.manifest"
expect_manifest_error "comments-only manifest" "$tmp/comments-only.manifest" "has no entries"

# Unreadable manifest.
printf 'a.bin 1 %s required\n' "$sha_a" >"$tmp/unreadable.manifest"
chmod 000 "$tmp/unreadable.manifest"
if [ "$(id -u)" = 0 ]; then
    ok "unreadable manifest: skipped (running as root)"
else
    expect_manifest_error "unreadable manifest" "$tmp/unreadable.manifest" "missing or unreadable"
fi
chmod 644 "$tmp/unreadable.manifest"

# Malformed entries: too few fields, bad size, bad sha256, bad role.
printf 'fw_patch_table_8800d80_u02.bin\n' >"$tmp/malformed-cols.manifest"
expect_manifest_error "malformed manifest (few fields)" "$tmp/malformed-cols.manifest" "name size sha256 role"

printf 'a.bin notanumber %s required\n' "$sha_a" >"$tmp/malformed-size.manifest"
expect_manifest_error "malformed manifest (bad size)" "$tmp/malformed-size.manifest" "bad size"

printf 'a.bin 1 not-a-sha256 required\n' >"$tmp/malformed-sha.manifest"
expect_manifest_error "malformed manifest (bad sha256)" "$tmp/malformed-sha.manifest" "bad sha256"

printf 'a.bin 1 %s bogus\n' "$sha_a" >"$tmp/malformed-role.manifest"
expect_manifest_error "malformed manifest (bad role)" "$tmp/malformed-role.manifest" "bad role"

for name in 'sub/fw.bin' 'x..y.bin'; do
    printf '%s 1 %s required\n' "$name" "$sha_a" >"$tmp/path.manifest"
    expect_manifest_error "unsafe name $name" "$tmp/path.manifest" "unsafe basename"
done
printf 'fw.bin 1 %s required\nfw.bin 1 %s optional\n' "$sha_a" "$sha_b" >"$tmp/repeated.manifest"
expect_manifest_error "duplicate basename" "$tmp/repeated.manifest" "duplicate name"

# No required entry (only optional).
printf 'a.bin 1 %s optional\nb.bin 1 %s optional\n' "$sha_a" "$sha_b" >"$tmp/no-required.manifest"
expect_manifest_error "manifest without a required entry" "$tmp/no-required.manifest" "required"

# Valid manifest (and the real package manifest) with absent files: reports
# missing firmware, never a manifest error and never installed 0/0.
for pair in "fixture:$tmp/good.manifest" "packaged:$real_manifest"; do
    label=${pair%%:*}
    mpath=${pair#*:}
    if [ "$label" = fixture ]; then
        printf 'real.bin 3 %s required\n' "$sha_a" >"$mpath"
    fi
    out=$(status_with "$mpath")
    rc=$?
    if [ "$rc" -eq 0 ]; then
        bad "$label manifest: status unexpectedly succeeded"
    elif [[ $out == *"manifest "* || $out == *"installed (0/0"* ]]; then
        bad "$label manifest: reported manifest error or 0/0: $out"
    elif [[ $out == *"firmware not installed"* ]]; then
        ok "$label manifest with absent required files reports firmware not installed"
    else
        bad "$label manifest: unexpected output: $out"
    fi
done

# first_required() skips a comment line that has 4 tokens with token 4 == required
# (e.g. "# word2 word3 required" or "# foo.bin 1 <sha> required"), so install
# probes for the real required file instead of the commented text.
mkdir -p "$tmp/src"
printf 'abc' >"$tmp/src/real.bin"
cat >"$tmp/comment.manifest" <<EOF
# fmacfw_8800d80_u02.bin 1 $sha_c required
# word1 word2 required
real.bin 3 $(sha256sum "$tmp/src/real.bin" | cut -d' ' -f1) required
EOF
out=$(env CUBIE_A7A_WIFI_MANIFEST="$tmp/comment.manifest" \
    CUBIE_A7A_WIFI_FWDIR="$tmp/fw-install" \
    CUBIE_A7A_LINUX_FWDIR="$tmp/lf" \
    CUBIE_A7A_SYSFS="$tmp/sysfs" \
    "$script" install "$tmp/src" 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && [ -f "$tmp/fw-install/real.bin" ]; then
    ok "install: first_required skips commented entries"
else
    bad "install: first_required failed with commented entries (rc=$rc): $out"
fi

# S0-12: silent truncation of the manifest entries() stream after 1 valid row
# (exit 0, no stderr) must fail closed, never report "installed (1/1)".
mkdir -p "$tmp/fw-trunc" "$tmp/bin"
printf 'abc' >"$tmp/fw-trunc/first.bin"
sha_first=$(sha256sum "$tmp/fw-trunc/first.bin" | cut -d' ' -f1)
cat >"$tmp/two.manifest" <<EOF
first.bin 3 $sha_first required
second.bin 3 $sha_b required
EOF
real_py=$(command -v python3)
cat >"$tmp/bin/python3" <<EOF
#!$real_py
import subprocess, sys
from pathlib import Path
real = "$real_py"
log_path = Path("$tmp/inject-entries.log")
count_path = Path("$tmp/entries-call-count")
stdin_bytes = sys.stdin.buffer.read()
res = subprocess.run([real] + sys.argv[1:], input=stdin_bytes, capture_output=True)
if b'parts = line.split()' in stdin_bytes and b'bad sha256' not in stdin_bytes and res.returncode == 0:
    calls = int(count_path.read_text()) if count_path.is_file() else 0
    calls += 1
    count_path.write_text(str(calls))
    # First two calls are inside check_manifest() (top-level + cmd_status); truncate the
    # third call (cmd_status override loop) to 1 valid row, exit 0, no stderr.
    if calls >= 3:
        first_line = res.stdout.splitlines(keepends=True)[:1]
        with log_path.open("a") as fh:
            fh.write(f"injected:entries-trunc:call={calls}\\n")
        sys.stdout.buffer.write(b"".join(first_line))
        sys.exit(0)
sys.stdout.buffer.write(res.stdout)
sys.stderr.buffer.write(res.stderr)
sys.exit(res.returncode)
EOF
chmod 0755 "$tmp/bin/python3"
out=$(env PATH="$tmp/bin:$PATH" \
    CUBIE_A7A_WIFI_MANIFEST="$tmp/two.manifest" \
    CUBIE_A7A_WIFI_FWDIR="$tmp/fw-trunc" \
    CUBIE_A7A_LINUX_FWDIR="$tmp/lf" \
    CUBIE_A7A_SYSFS="$tmp/sysfs" \
    "$script" status 2>&1)
rc=$?
if [ ! -s "$tmp/inject-entries.log" ]; then
    bad "S0-12: entries() truncation fault was never injected"
elif [ "$rc" -ne 0 ] && [[ $out == *"truncated"* ]]; then
    ok "S0-12: silent truncation of manifest entries() fails closed"
else
    bad "S0-12: silent truncation of manifest entries() accepted (rc=$rc): $out"
fi

# Should-fix 4c: remove validates the entire manifest stream BEFORE deleting anything.
mkdir -p "$tmp/fw-remove"
printf 'aaa' >"$tmp/fw-remove/first.bin"
printf 'bbb' >"$tmp/fw-remove/second.bin"
rm -f "$tmp/inject-entries.log" "$tmp/entries-call-count"
# Set counter to 1 so call 1 (check_manifest) succeeds and call 2 (cmd_remove) truncates.
printf '1\n' >"$tmp/entries-call-count"
out=$(env PATH="$tmp/bin:$PATH" \
    CUBIE_A7A_WIFI_MANIFEST="$tmp/two.manifest" \
    CUBIE_A7A_WIFI_FWDIR="$tmp/fw-remove" \
    CUBIE_A7A_LINUX_FWDIR="$tmp/lf" \
    CUBIE_A7A_SYSFS="$tmp/sysfs" \
    "$script" remove 2>&1)
rc=$?
if [ ! -s "$tmp/inject-entries.log" ]; then
    bad "Should-fix 4c: remove truncation fault was never injected"
elif [ "$rc" -ne 0 ] && [ -f "$tmp/fw-remove/first.bin" ] && [ -f "$tmp/fw-remove/second.bin" ]; then
    ok "Should-fix 4c: remove deletes nothing when manifest stream is truncated"
else
    bad "Should-fix 4c: remove deleted files before validating stream (rc=$rc, first=$(test -e "$tmp/fw-remove/first.bin" && echo yes || echo no), second=$(test -e "$tmp/fw-remove/second.bin" && echo yes || echo no)): $out"
fi

# F6 should-fix: remove reads one snapshot of the entry stream, checks its
# producer's exit status, refuses an unterminated last line and validates
# every field itself before deleting anything.
mkdir -p "$tmp/bin-f6"
cat >"$tmp/bin-f6/python3" <<EOF
#!$real_py
import os, subprocess, sys
from pathlib import Path
real = "$real_py"
log_path = Path("$tmp/inject-f6.log")
count_path = Path("$tmp/f6-call-count")
stdin_bytes = sys.stdin.buffer.read()
res = subprocess.run([real] + sys.argv[1:], input=stdin_bytes, capture_output=True)
mode = os.environ.get("WIFI_F6_INJECT", "")
if b'print(f"#END {count}")' in stdin_bytes and res.returncode == 0 and mode:
    calls = (int(count_path.read_text()) if count_path.is_file() else 0) + 1
    count_path.write_text(str(calls))
    if calls >= 2:  # call 1 is check_manifest's; call 2 is remove's producer
        out = res.stdout
        with log_path.open("a") as fh:
            fh.write(f"injected:{mode}:call={calls}\\n")
        if mode == "badsha":
            first = out.split(b"\\n", 1)
            parts = first[0].split(b" ")
            parts[2] = b"not-a-sha256"
            out = b" ".join(parts) + b"\\n" + first[1]
            sys.stdout.buffer.write(out)
            sys.exit(0)
        if mode == "exit1":
            sys.stdout.buffer.write(out)
            sys.exit(1)
sys.stdout.buffer.write(res.stdout)
sys.stderr.buffer.write(res.stderr)
sys.exit(res.returncode)
EOF
chmod 0755 "$tmp/bin-f6/python3"
f6_remove() { # NAME MODE MANIFEST
    local name=$1 mode=$2 manifest=$3 out rc
    rm -rf "$tmp/fw-f6" "$tmp/inject-f6.log" "$tmp/f6-call-count"
    mkdir -p "$tmp/fw-f6"
    printf 'aaa' >"$tmp/fw-f6/first.bin"
    printf 'bbb' >"$tmp/fw-f6/second.bin"
    out=$(env PATH="$tmp/bin-f6:$PATH" WIFI_F6_INJECT="$mode" \
        CUBIE_A7A_WIFI_MANIFEST="$manifest" \
        CUBIE_A7A_WIFI_FWDIR="$tmp/fw-f6" \
        CUBIE_A7A_LINUX_FWDIR="$tmp/lf" \
        CUBIE_A7A_SYSFS="$tmp/sysfs" \
        "$script" remove 2>&1)
    rc=$?
    if [ -n "$mode" ] && [ ! -s "$tmp/inject-f6.log" ]; then
        bad "$name: fault was never injected"
    elif [ "$rc" -ne 0 ] && [ -f "$tmp/fw-f6/first.bin" ] && [ -f "$tmp/fw-f6/second.bin" ]; then
        ok "$name"
    else
        bad "$name: remove deleted files or exited 0 (rc=$rc): $out"
    fi
}
f6_remove "F6: remove refuses when the stream producer exits nonzero" exit1 "$tmp/two.manifest"
f6_remove "F6: remove validates every field of its own snapshot (bad sha256)" badsha "$tmp/two.manifest"
printf 'first.bin 3 %s required\nsecond.bin 3 %s required' "$sha_first" "$sha_b" >"$tmp/unterminated.manifest"
f6_remove "F6: remove refuses a manifest whose last line is unterminated" "" "$tmp/unterminated.manifest"
# Control: the same manifest, terminated, is removed.
rm -rf "$tmp/fw-f6"
mkdir -p "$tmp/fw-f6"
printf 'aaa' >"$tmp/fw-f6/first.bin"
if env CUBIE_A7A_WIFI_MANIFEST="$tmp/two.manifest" CUBIE_A7A_WIFI_FWDIR="$tmp/fw-f6" \
    CUBIE_A7A_LINUX_FWDIR="$tmp/lf" CUBIE_A7A_SYSFS="$tmp/sysfs" \
    "$script" remove >/dev/null 2>&1 && [ ! -e "$tmp/fw-f6/first.bin" ]; then
    ok "F6: control: a valid manifest removes its files"
else
    bad "F6: control: a valid manifest did not remove its files"
fi

if [ "$fail" -gt 0 ]; then
    echo "$fail test(s) FAILED ($pass passed)"
    exit 1
fi
echo "all wifi-firmware manifest tests passed ($pass)"
