#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Read effective target SSH policy; never start a listener. A disposable test
# host key is removed before returning and never reaches the image.
set -euo pipefail
[ "${A7A_PRIVATE_BUILD:-}" = 1 ] || [ "$(id -u)" = 0 ] || {
    echo 'run via fedora/private-build.sh' >&2
    exit 1
}
TOP=$(cd "$(dirname "$0")/.." && pwd)
ROOT=$(realpath "${1:?ROOT}")
REPORT=${2:?REPORT}
[ "$ROOT" != / ] && [ -d "$ROOT/etc/ssh" ]
[ ! -e "$ROOT/dev/null" ] && [ ! -L "$ROOT/dev/null" ]
created_run=0
created_null=0
mounted=0
KEYDIR=
cleanup() {
    local rc=$?
    trap - EXIT
    if [ "$mounted" = 1 ]; then umount "$ROOT/dev/null" || rc=1; fi
    if [ "$created_null" = 1 ]; then rm "$ROOT/dev/null" || rc=1; fi
    if [ -n "$KEYDIR" ]; then
        rm -f "$KEYDIR/hostkey" "$KEYDIR/hostkey.pub" || rc=1
        rmdir "$KEYDIR" || rc=1
    fi
    if [ "$created_run" = 1 ]; then rmdir "$ROOT/run/sshd" || rc=1; fi
    exit "$rc"
}
trap cleanup EXIT
if [ ! -e "$ROOT/run/sshd" ]; then
    mkdir "$ROOT/run/sshd"
    created_run=1
fi
KEYDIR=$(mktemp -d "$ROOT/run/sshd/policy-check-XXXXXX")
ssh-keygen -q -t ed25519 -N "" -f "$KEYDIR/hostkey"
touch "$ROOT/dev/null"
created_null=1
mount --bind /dev/null "$ROOT/dev/null"
mounted=1
for address in 127.0.0.1 192.0.2.10; do
    target_report=$REPORT
    if [ "$address" = 127.0.0.1 ]; then target_report=$REPORT.loopback; fi
    env -u TMPDIR chroot "$ROOT" /usr/sbin/sshd -h "${KEYDIR#"$ROOT"}/hostkey" -T -C "user=root,host=client.example,addr=$address" >"$target_report"
    for expected in 'permitrootlogin yes' 'passwordauthentication yes' 'kbdinteractiveauthentication no' 'allowusers root' 'authenticationmethods any' 'permitemptypasswords no'; do
        grep -qixF "$expected" "$target_report"
    done
done
python3 -I "$TOP/fedora/devcard-policy.py" passwd-sole-root "$ROOT/etc/passwd"
echo 'PASS target sshd effective sole-human root/password-enabled policy (loopback and documentation remote address)'
