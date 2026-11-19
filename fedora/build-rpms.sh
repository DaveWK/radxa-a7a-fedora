#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Build the Cubie A7A Fedora packages (SRPMs for COPR, and the noarch RPMs):
#   cubie-a7a-dtb            DTB + ESP-override hook
#   cubie-a7a-board-support  DKMS kmods, dracut policy, kernel arguments
#   cubie-a7a-npu            DKMS vipcore (A733 NPU kernel driver)
#   cubie-a7a-rk1828         DKMS pcie-rkep (RK1828 coprocessor host driver)
#   cubie-a7a-display        DKMS sunxidrm (A733 HDMI display driver)
#   cubie-a7a-vdec           DKMS a733-cedrus (A733 video decoder)
#   cubie-a7a-aic8800-usb    DKMS AIC8800D80 Wi-Fi/Bluetooth driver (firmware
#                            from linux-firmware); only the reviewed driver
#                            inputs are staged, never the whole external tree
#   cubie-a7a-fwlog          firmware log reader + journal unit (aarch64; its
#                            binary RPM is built by build-aarch64-rpms.sh)
#
# Usage: fedora/build-rpms.sh [OUT_DIR]   (default build/fedora/rpmbuild, or
#        build/fedora/rpmbuild-<release> when FEDORA_RELEASE is not 45)
# FEDORA_RELEASE (45 | rawhide, fedora/release.sh) sets the dist tag only:
# the packages are noarch sources and scripts, the same for every release.
# Rootless; needs rpm-build, dtc, cpp, make, systemd-rpm-macros.
set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=release.sh
. "$TOP/fedora/release.sh"
# The firmware log reader and its format document come from a boot-chain
# tree that has tools/a7a-fwlog (FWREPO). FWREPO=none (default) builds the
# other packages only.
FWREPO=${FWREPO:-none}
if [ "$FWREPO" != none ] && [ ! -f "$FWREPO/tools/a7a-fwlog/a7a-fwlog.c" ]; then
    echo "build-rpms: $FWREPO is missing (FWREPO=none skips cubie-a7a-fwlog)" >&2
    exit 1
fi
publish=${1:-$TOP/build/fedora/rpmbuild$RELEASE_SUFFIX}
mkdir -p "$publish/tmp"
publish=$(realpath "$publish")
# A fresh topdir isolates both specs and binary outputs from earlier builds.
OUT=$(mktemp -d "$publish/tmp/build-rpms.XXXXXXXX")
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT"/{SOURCES,SPECS,SRPMS,RPMS,BUILD,tmp}

ver() { sed -n 's/^Version:[[:space:]]*//p' "$1"; }

# --- cubie-a7a-dtb ----------------------------------------------------------
spec=$TOP/fedora/rpm/cubie-a7a-dtb/cubie-a7a-dtb.spec
v=$(ver "$spec")
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --exclude='*.dtb' --exclude='*.pre.dts' \
    --transform "s|^dts|cubie-a7a-dts-$v|" \
    -C "$TOP/fedora" -czf "$OUT/SOURCES/cubie-a7a-dts-$v.tar.gz" dts
cp "$TOP"/fedora/rpm/cubie-a7a-dtb/{cubie-a7a-install-dtb,89-cubie-a7a-dtb.install,cubie-a7a-dtb.service,80-cubie-a7a-dtb.preset} "$OUT/SOURCES/"
cp "$spec" "$OUT/SPECS/"

# --- cubie-a7a-board-support -------------------------------------------------
spec=$TOP/fedora/rpm/cubie-a7a-board-support/cubie-a7a-board-support.spec
v=$(ver "$spec")
# Under the output directory, not /tmp (a RAM tmpfs on the build hosts).
stage=$(mktemp -d -p "$OUT/tmp")
# dkms.conf keeps PACKAGE_VERSION="@VERSION@": the spec sets it to the
# package's version-release, so every package build is a new DKMS version.
cp -a "$TOP/fedora/kmods/cubie-a7a-kmods" "$stage/cubie-a7a-kmods-$v"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -C "$stage" -czf "$OUT/SOURCES/cubie-a7a-kmods-$v.tar.gz" "cubie-a7a-kmods-$v"
cp "$TOP"/fedora/rpm/cubie-a7a-board-support/{dracut-cubie-a7a.conf,cubie-a7a-cmdline,cubie-a7a-depmod.conf,cubie-a7a-staged.conf,cubie-a7a-kernel,99-zz-cubie-a7a.install,cubie-a7a-watchdog.conf,cubie-a7a-panic.conf} "$OUT/SOURCES/"
# DKMS life cycle helper, one copy per DKMS package.
cp "$TOP/fedora/rpm/cubie-a7a-dkms" "$OUT/SOURCES/"
cp "$spec" "$OUT/SPECS/"

# --- cubie-a7a-npu, -rk1828, -display, -vdec, -aic8800-usb (DKMS sources) ---
for pair in cubie-a7a-npu:a733-vipcore cubie-a7a-rk1828:rk1828-pcie-rkep \
    cubie-a7a-display:a733-sunxi-drm cubie-a7a-vdec:a733-cedrus \
    cubie-a7a-aic8800-usb:aic8800-usb; do
    pkg=${pair%%:*}
    kmod=${pair##*:}
    spec=$TOP/fedora/rpm/$pkg/$pkg.spec
    v=$(ver "$spec")
    src=$TOP/fedora/kmods/$kmod
    # The AIC8800 driver is not in this repository (most of its files carry
    # no licence grant); AIC8800_SRC names a local tree of it.  Stage only
    # the reviewed driver inputs (driver-inputs.list, with SHA256 values
    # verified) and refuse the tree when it holds firmware.
    if [ "$kmod" = aic8800-usb ]; then
        src=${AIC8800_SRC:-$src}
        if [ ! -d "$src" ]; then
            echo "build-rpms: $pkg skipped: no $kmod source (AIC8800_SRC=<tree>)" >&2
            continue
        fi
        python3 -I "$TOP/fedora/stage-aic8800.py" stage "$src" "$OUT" "$v" \
            --list "$TOP/fedora/rpm/cubie-a7a-aic8800-usb/driver-inputs.list" ||
            {
                echo "build-rpms: refusing the $pkg driver source (reviewed inputs only)" >&2
                exit 1
            }
        cp "$spec" "$OUT/SPECS/"
        continue
    fi
    cp -a "$src" "$stage/$kmod-$v"
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
        -C "$stage" -czf "$OUT/SOURCES/$kmod-$v.tar.gz" "$kmod-$v"
    cp "$spec" "$OUT/SPECS/"
done
cp "$TOP"/fedora/rpm/cubie-a7a-npu/{60-cubie-a7a-npu.rules,cubie-a7a-npu.sysusers} "$OUT/SOURCES/"
cp "$TOP/fedora/rpm/cubie-a7a-display/cubie-a7a-display-modprobe.conf" "$OUT/SOURCES/"
cp "$TOP"/fedora/rpm/cubie-a7a-vdec/{cubie-a7a-vdec-modprobe.conf,cubie-a7a-vdec-selftest} "$OUT/SOURCES/"
cp "$TOP"/fedora/rpm/cubie-a7a-aic8800-usb/{cubie-a7a-wifi-firmware,aic8800-d80-usb.manifest,60-cubie-a7a-aic8800.rules,cubie-a7a-aic8800-modprobe.conf,cubie-a7a-aic-udev,driver-inputs.list} \
    "$TOP/fedora/WIFI-FIRMWARE.md" "$OUT/SOURCES/"

# --- cubie-a7a-hat -----------------------------------------------------------
cp "$TOP"/fedora/rpm/cubie-a7a-hat/{cubie-a7a-hat-enable,cubie-a7a-hat.service,80-cubie-a7a-hat.preset,cubie-a7a-hat-modprobe.conf,cubie-a7a-npu-selftest} "$OUT/SOURCES/"
cp "$TOP/fedora/rpm/cubie-a7a-hat/cubie-a7a-hat.spec" "$OUT/SPECS/"

# --- cubie-a7a-fwlog (aarch64: SRPM only here) ------------------------------
if [ "$FWREPO" != none ]; then
    cp "$FWREPO/tools/a7a-fwlog/a7a-fwlog.c" "$OUT/SOURCES/"
    # The log format document (crates/bootlog/README.md of the boot chain's
    # shared crates, or docs/fwlog.md).
    FWLOG_DOC=${FWLOG_DOC:-$FWREPO/src/ore-edk2-boot/crates/bootlog/README.md}
    [ -f "$FWLOG_DOC" ] || FWLOG_DOC=$FWREPO/docs/fwlog.md
    cp "$FWLOG_DOC" "$OUT/SOURCES/fwlog.md"
    cp \
        "$TOP"/fedora/rpm/cubie-a7a-fwlog/{a7a-fwlog.service,80-cubie-a7a-fwlog.preset} "$OUT/SOURCES/"
    cp "$TOP/fedora/rpm/cubie-a7a-fwlog/cubie-a7a-fwlog.spec" "$OUT/SPECS/"
fi

for s in "$OUT"/SPECS/*.spec; do
    rpmbuild --define "_topdir $OUT" --define "_tmppath $OUT/tmp" --define "dist $DIST" -bs "$s"
    case $s in
    *cubie-a7a-fwlog.spec) ;; # ExclusiveArch aarch64
    *)
        rpmbuild --define "_topdir $OUT" --define "_tmppath $OUT/tmp" --define "dist $DIST" -bb "$s"
        case $s in
        *cubie-a7a-aic8800-usb.spec)
            # The built RPM must carry only the reviewed driver inputs and
            # listed package outputs: no firmware, nothing unlisted.
            shopt -s nullglob
            rpms=("$OUT"/RPMS/*/cubie-a7a-aic8800-usb-*.rpm)
            if ((${#rpms[@]} != 1)); then
                echo "build-rpms: expected one current AIC8800 binary RPM" >&2
                exit 1
            fi
            python3 -I "$TOP/fedora/stage-aic8800.py" payload "${rpms[0]}" \
                --list "$TOP/fedora/rpm/cubie-a7a-aic8800-usb/driver-inputs.list"
            ;;
        esac
        ;;
    esac
done
# Preserve the consumer layout, publishing only after checking this run.
cp -a "$OUT"/{SPECS,SOURCES,RPMS,SRPMS} "$publish/"
while IFS= read -r -d '' rpm_file; do
    printf '%s/%s\n' "$publish" "${rpm_file#"$OUT"/}"
done < <(find "$OUT/SRPMS" "$OUT/RPMS" -name '*.rpm' -print0)
