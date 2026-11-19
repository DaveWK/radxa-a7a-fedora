#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Rebuild the aarch64 SRPMs (cubie-a7a-fwlog) natively, rootless: an aarch64
# buildroot of FEDORA_RELEASE (45 | rawhide, fedora/release.sh) made with
# dnf5 --installroot --forcearch inside a user namespace, rpmbuild run in it
# under qemu-aarch64 binfmt (what a COPR builder does natively). The chroot
# belongs to the run; only Fedora's DNF cache is shared within a release.
#
# Usage: fedora/build-aarch64-rpms.sh RUN_DIR
# RUN_DIR is the fresh directory printed by build-rpms.sh with FWREPO set.
set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=release.sh
. "$TOP/fedora/release.sh"
RUN=$(realpath -e "${1:?run directory printed by build-rpms.sh}")
POLICY=$TOP/fedora/devcard-policy.py
CACHE=${DNF_CACHE:-$TOP/build/fedora/dnf/cache-ns$RELEASE_SUFFIX}

[ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ] || {
    echo "no qemu-aarch64 binfmt handler" >&2
    exit 1
}
NOARCH_MANIFEST=$RUN/rpm-checks/checked-rpms.json
[ -f "$NOARCH_MANIFEST" ] && [ ! -e "$RUN/rpm-snapshot.json" ] || {
    echo "build-aarch64-rpms: expected an unsealed run with a bound source RPM" >&2
    exit 1
}
BUILD_SYS=$RUN/aarch64-root
mkdir "$BUILD_SYS"
staged=$(python3 -I "$POLICY" stage-srpm "$NOARCH_MANIFEST" "$BUILD_SYS/sources") || {
    echo "build-aarch64-rpms: no bound cubie-a7a-fwlog SRPM in $NOARCH_MANIFEST" >&2
    exit 1
}
SRPM=${staged%%$'\t'*}
NOARCH_SHA256=${staged##*$'\t'}

export BUILD_SYS CACHE DIST RELEASEVER REPOSDIR SRPM
"$TOP/fedora/run-build-ns.sh" mount bash -s -- "${RELEASE_REPOS[@]}" >&2 <<'NS'
set -euo pipefail
mkdir -p "$BUILD_SYS"/{proc,dev,run,var/lib/dnf,work/tmp}
if [ ! -x "$BUILD_SYS/usr/bin/rpmbuild" ]; then
    # The caller's TMPDIR is a host path, not a path inside the build root.
    env -u TMPDIR dnf5 -y -q install --use-host-config --installroot="$BUILD_SYS" --forcearch=aarch64 --releasever="$RELEASEVER" \
        --setopt=reposdir="$REPOSDIR" --setopt=cachedir="$CACHE" \
        --setopt=persistdir=/var/lib/dnf --setopt=countme=False --setopt=keepcache=True \
        --setopt=install_weak_deps=False --setopt=tsflags=nocontexts,nodocs \
        --setopt=gpgcheck=True "$@" \
        fedora-release bash coreutils rpm-build redhat-rpm-config systemd-rpm-macros gcc make
fi
mount -t proc proc "$BUILD_SYS/proc"
for n in null zero random urandom full; do touch "$BUILD_SYS/dev/$n"; mount --bind "/dev/$n" "$BUILD_SYS/dev/$n"; done
mount -t tmpfs tmpfs "$BUILD_SYS/run"
env -u TMPDIR chroot "$BUILD_SYS" rpmbuild --define "_topdir /work" --define "_tmppath /work/tmp" \
    --define "dist $DIST" --define 'debug_package %{nil}' --rebuild "/sources/${SRPM##*/}"
NS
shopt -s nullglob globstar dotglob
built_aarch64=("$BUILD_SYS"/work/RPMS/**/*.rpm)
if ((${#built_aarch64[@]} != 1)); then
    printf 'build-aarch64-rpms: expected exactly one aarch64 image RPM; found %s\n' "${#built_aarch64[@]}" >&2
    printf '  %s\n' "${built_aarch64[@]}" >&2
    exit 1
fi
rpm_file=${built_aarch64[0]}
if [ "${rpm_file%/*}" != "$BUILD_SYS/work/RPMS/aarch64" ] || [ ! -f "$rpm_file" ] || [ -L "$rpm_file" ]; then
    echo "build-aarch64-rpms: unexpected image RPM output: $rpm_file" >&2
    exit 1
fi
mkdir "$RUN/out/aarch64"
cp "$rpm_file" "$RUN/out/aarch64/"
python3 -I "$POLICY" write-rpm-manifest \
    "$RUN/out" "$RUN/rpm-checks/checked-aarch64-rpms.json" --kind aarch64 \
    --bind-noarch "$NOARCH_MANIFEST" --bind-noarch-sha256 "$NOARCH_SHA256" \
    "$RUN"/out/aarch64/*.rpm
python3 -I "$POLICY" seal-rpm-run "$RUN"
printf '%s\n' "$RUN"
