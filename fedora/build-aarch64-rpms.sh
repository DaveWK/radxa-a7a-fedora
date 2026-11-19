#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Rebuild the aarch64 SRPMs (cubie-a7a-fwlog) natively, rootless: an aarch64
# buildroot of FEDORA_RELEASE (45 | rawhide, fedora/release.sh) made with
# dnf5 --installroot --forcearch inside a user namespace, rpmbuild run in it
# under qemu-aarch64 binfmt (what a COPR builder does natively). Each release
# has its own buildroot and dnf cache.
#
# Usage: fedora/build-aarch64-rpms.sh [RPMBUILD_DIR]  (default build/fedora/rpmbuild,
#        or build/fedora/rpmbuild-<release> when FEDORA_RELEASE is not 45)
set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=release.sh
. "$TOP/fedora/release.sh"
OUT=${1:-$TOP/build/fedora/rpmbuild$RELEASE_SUFFIX}
BR=${BUILDROOT:-$TOP/build/fedora/buildroot-aarch64$RELEASE_SUFFIX}
CACHE=${DNF_CACHE:-$TOP/build/fedora/dnf/cache-ns$RELEASE_SUFFIX}

[ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ] || {
    echo "no qemu-aarch64 binfmt handler" >&2
    exit 1
}
mkdir -p "$OUT/RPMS"

export BR CACHE OUT DIST RELEASEVER REPOSDIR
"$TOP/fedora/run-build-ns.sh" mount bash -s -- "${RELEASE_REPOS[@]}" <<'NS'
set -euo pipefail
mkdir -p "$BR"/{proc,dev,run,var/lib/dnf,srpms,out}
if [ ! -x "$BR/usr/bin/rpmbuild" ]; then
    dnf5 -y -q install --use-host-config --installroot="$BR" --forcearch=aarch64 --releasever="$RELEASEVER" \
        --setopt=reposdir="$REPOSDIR" --setopt=cachedir="$CACHE" \
        --setopt=persistdir="$BR/var/lib/dnf" --setopt=countme=False --setopt=keepcache=True \
        --setopt=install_weak_deps=False --setopt=tsflags=nocontexts,nodocs \
        --setopt=gpgcheck=True "$@" \
        fedora-release bash coreutils rpm-build redhat-rpm-config systemd-rpm-macros gcc make
fi
mount -t proc proc "$BR/proc"
for n in null zero random urandom full; do touch "$BR/dev/$n"; mount --bind "/dev/$n" "$BR/dev/$n"; done
mount -t tmpfs tmpfs "$BR/run"
rm -rf "$BR/srpms"/* "$BR/out"/*
cp "$OUT"/SRPMS/cubie-a7a-fwlog-*.src.rpm "$BR/srpms/"
for s in "$BR"/srpms/*.src.rpm; do
    chroot "$BR" rpmbuild --define "_topdir /out" --define "dist $DIST" \
        --rebuild "/srpms/$(basename "$s")"
done
mkdir -p "$OUT/RPMS/aarch64"
cp "$BR"/out/RPMS/aarch64/*.rpm "$OUT/RPMS/aarch64/"
NS
find "$OUT/RPMS/aarch64" -name '*.rpm' -printf '%p\n'
