#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Rebuild the aarch64 SRPMs (cubie-a7a-fwlog) natively, rootless: a Fedora 44
# aarch64 buildroot made with dnf5 --installroot --forcearch inside a user
# namespace, rpmbuild run in it under qemu-aarch64 binfmt (what a COPR
# builder does natively).
#
# Usage: fedora/build-aarch64-rpms.sh [RPMBUILD_DIR]  (default build/fedora/rpmbuild)
set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$TOP/build/fedora/rpmbuild}
BR=${BUILDROOT:-$TOP/build/fedora/buildroot-aarch64}
CACHE=$TOP/build/fedora/dnf/cache-ns
FEDORA_RELEASE=${FEDORA_RELEASE:-45}
DIST=${DIST:-.fc$FEDORA_RELEASE}

[ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ] || {
    echo "no qemu-aarch64 binfmt handler" >&2
    exit 1
}
mkdir -p "$OUT/RPMS"

# Fedora's own repository files: /usr/share/dnf5/repos.d on a Fedora 45 host,
# /etc/yum.repos.d before that.
REPOSDIR=${REPOSDIR:-$([ -f /usr/share/dnf5/repos.d/fedora.repo ] && echo /usr/share/dnf5/repos.d || echo /etc/yum.repos.d)}
export BR CACHE OUT DIST FEDORA_RELEASE REPOSDIR
"$TOP/fedora/run-build-ns.sh" mount bash -s <<'NS'
set -euo pipefail
mkdir -p "$BR"/{proc,dev,run,var/lib/dnf,srpms,out}
if [ ! -x "$BR/usr/bin/rpmbuild" ]; then
    dnf5 -y -q install --use-host-config --installroot="$BR" --forcearch=aarch64 --releasever="$FEDORA_RELEASE" \
        --setopt=reposdir="$REPOSDIR" --setopt=cachedir="$CACHE" \
        --setopt=persistdir="$BR/var/lib/dnf" --setopt=countme=False --setopt=keepcache=True \
        --setopt=install_weak_deps=False --setopt=tsflags=nocontexts,nodocs \
        --repo=fedora --repo=updates \
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
