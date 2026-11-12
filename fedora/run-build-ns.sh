#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Reuse the verified private-build.sh context; otherwise retain rootless mapping.
set -euo pipefail
mode=${1:?user or mount}
shift
case $mode in user | mount) ;; *) exit 2 ;; esac
if [ "${A7A_PRIVATE_BUILD:-}" = 1 ]; then
    [ "$(id -u)" = 0 ]
    [ "${A7A_PRIVATE_USER_NS:?}" = "$(readlink /proc/self/ns/user)" ]
    [ "${A7A_PRIVATE_MOUNT_NS:?}" = "$(readlink /proc/self/ns/mnt)" ]
    [ "$A7A_PRIVATE_USER_NS" != "${A7A_OUTER_USER_NS:?}" ]
    [ "$A7A_PRIVATE_MOUNT_NS" != "${A7A_OUTER_MOUNT_NS:?}" ]
    exec "$@"
fi
# Real root (the image builder's QEMU guest): no user namespace is needed,
# only a private mount/PID namespace for the build's mounts.
if [ "$(id -u)" = 0 ]; then
    if [ "$mode" = mount ]; then
        exec unshare --mount --propagation private --pid --fork --kill-child -- "$@"
    fi
    exec "$@"
fi
if [ "$mode" = mount ]; then
    exec unshare --map-auto --map-root-user --mount --pid --fork --kill-child -- "$@"
fi
exec unshare --map-auto --map-root-user -- "$@"
