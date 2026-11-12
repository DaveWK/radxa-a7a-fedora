#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Workstation-local aarch64 build with a namespace-owned binfmt_misc instance.
# No host-global handler, service, loop device or filesystem image mount.
set -euo pipefail
SELF=$(realpath "$0")
if [ "${1:-}" != --inside ]; then
    A7A_OUTER_USER_NS=$(readlink /proc/self/ns/user)
    export A7A_OUTER_USER_NS
    A7A_OUTER_MOUNT_NS=$(readlink /proc/self/ns/mnt)
    export A7A_OUTER_MOUNT_NS
    exec unshare --map-auto --map-root-user --mount --pid --fork --kill-child -- "$SELF" --inside "$@"
fi
shift
[ "$(id -u)" = 0 ]
A7A_PRIVATE_USER_NS=$(readlink /proc/self/ns/user)
export A7A_PRIVATE_USER_NS
A7A_PRIVATE_MOUNT_NS=$(readlink /proc/self/ns/mnt)
export A7A_PRIVATE_MOUNT_NS
[ "$A7A_PRIVATE_USER_NS" != "$A7A_OUTER_USER_NS" ]
[ "$A7A_PRIVATE_MOUNT_NS" != "$A7A_OUTER_MOUNT_NS" ]
[ -x /usr/bin/qemu-aarch64-static ]
[ -f /usr/lib/binfmt.d/qemu-aarch64-static.conf ]
printf 'private user=%s mount=%s uid=%s\n' "$A7A_PRIVATE_USER_NS" "$A7A_PRIVATE_MOUNT_NS" "$(id -u)"
cat /proc/self/uid_map
if [ "${1:-}" = --preflight ]; then
    echo 'Preflight only: no mounts or binfmt registration performed.'
    exit 0
fi
[ $# -gt 0 ] || { echo 'usage: private-build.sh --preflight | BUILD_COMMAND [ARGS...]' >&2; exit 2; }
# The mount tree is already separate. Prevent propagation before mounting.
mount --make-rprivate /
if findmnt -rn -o PROPAGATION / | grep -q 'shared\|slave'; then
    echo 'private-build: mount propagation is not private' >&2; exit 1
fi
mount -t proc proc /proc
mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
trap 'umount /proc/sys/fs/binfmt_misc; umount /proc' EXIT
# A newly mounted instance in this fresh user namespace must be empty.
[ "$(find /proc/sys/fs/binfmt_misc -mindepth 1 -maxdepth 1 ! -name register ! -name status | wc -l)" = 0 ]
findmnt -rn -o TARGET,FSTYPE,PROPAGATION --mountpoint /proc
findmnt -rn -o TARGET,FSTYPE,PROPAGATION --mountpoint /proc/sys/fs/binfmt_misc
cat /usr/lib/binfmt.d/qemu-aarch64-static.conf > /proc/sys/fs/binfmt_misc/register
grep -q '^flags: .*F' /proc/sys/fs/binfmt_misc/qemu-aarch64
grep -q '^interpreter /usr/bin/qemu-aarch64-static$' /proc/sys/fs/binfmt_misc/qemu-aarch64
export A7A_PRIVATE_BUILD=1
"$@"
