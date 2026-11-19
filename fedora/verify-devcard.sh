#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Offline checks of a dev card built by fedora/mkdevcard.sh: layout and
# firmware, boot chain files, initramfs contents, image policy. Reads only.
# Not a board test.
#
# Usage: fedora/verify-devcard.sh [--compare-staging] [IMAGE] [WORK_DIR]
# --compare-staging also checks the optional build records from WORK_DIR.
#
# Set as for the build (mkdevcard.sh), to check what it added:
#   FEDORA_RELEASE=45|rawhide  the release (fedora/release.sh): default
#                           image and work directory, the kernel's .fcN, the
#                           release the image says it is, its repositories
#   KERNEL_VERSION=V-R      the one kernel installed is exactly this build
#   BOOT_MODES=protective   the three entries per kernel (fedora/bootmodes/)
#   EXTRA_PACKAGES="a b"    the extra packages are installed
#   FIRST_BOOT=maintenance  grubenv next_entry is the default's ~maintenance
#   GROW_ROOT=no            nothing grows the root: no repart config, no
#                           x-systemd.growfs, repart/growfs masked and labelled
set -uo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=release.sh
. "$TOP/fedora/release.sh"
compare_staging=no
if [[ ${1:-} == --compare-staging ]]; then
    compare_staging=yes
    shift
fi
IMG=${1:-$TOP/build/image/a7a-fedora$RELEASE_SUFFIX-dev.img}
W=${2:-$TOP/build/fedora/devcard$RELEASE_SUFFIX}
KERNEL_VERSION=${KERNEL_VERSION:-}
# The dev card firmware's build tree (FWREPO), if any.
FWREPO=${FWREPO:-none}
# FW=none (default) for an image without firmware (make fedora-image).
FW=${FW:-none}
# The DTB the firmware would embed from this source tree (DTB_ORIGIN=firmware);
# built here unless a specific firmware DTB is given.
FIRMWARE_DTB=${FIRMWARE_DTB:-}
BOOT_MODES=${BOOT_MODES:-}
EXTRA_PACKAGES=${EXTRA_PACKAGES:-}
FIRST_BOOT=${FIRST_BOOT:-}
GROW_ROOT=${GROW_ROOT:-yes}
[ -f "$IMG" ] || {
    echo "verify-devcard: image $IMG does not exist" >&2
    exit 1
}
mkdir -p "$W"
# Bind every check directly to IMG: extract the ESP and root partitions out of
# IMG itself into the work directory, never trusting a staging tree that could
# have diverged after the build (and with GROW_ROOT=no, reading the real
# post-overlay content from the image).
VERIFY_ESP=$W/verify-esp.img
VERIFY_ROOT_IMG=$W/verify-root.img
VERIFY_ROOT=$W/verify-root
VERIFY_PACKAGES=$W/verify-packages.txt
python3 -I "$TOP/fedora/image-extract.py" extract-partition "$IMG" "$VERIFY_ESP" \
    C12A7328-F81F-11D2-BA4B-00A0C93EC93B || {
    echo "verify-devcard: cannot extract the ESP from $IMG" >&2
    exit 1
}
python3 -I "$TOP/fedora/image-extract.py" extract-partition "$IMG" "$VERIFY_ROOT_IMG" \
    B921B045-1DF0-41C3-AF44-4C6F280D3FAE || {
    echo "verify-devcard: cannot extract the root partition from $IMG" >&2
    exit 1
}
# rdump preserves filesystem ownership; map the same IDs as the image builder
# rather than ignoring chown errors on a rootless workstation.
"$TOP/fedora/run-build-ns.sh" user python3 -I "$TOP/fedora/image-extract.py" extract-root "$VERIFY_ROOT_IMG" "$VERIFY_ROOT" || {
    echo "verify-devcard: cannot read the root filesystem in $IMG" >&2
    exit 1
}
ROOT=$VERIFY_ROOT
ESP=$VERIFY_ESP
ROOT_IMG=$VERIFY_ROOT_IMG
rpm --root "$ROOT" -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH} %{RSAHEADER:pgpsig}\n' |
    sort >"$VERIFY_PACKAGES" || {
    echo "verify-devcard: cannot read the rpm database in $IMG" >&2
    exit 1
}
python3 -I "$TOP/fedora/devcard-policy.py" verify-rpmdb-list "$ROOT" "$VERIFY_PACKAGES" || {
    echo "verify-devcard: rpm package listing from $IMG is incomplete" >&2
    exit 1
}
PACKAGES=$VERIFY_PACKAGES
fail=0
ok() { printf '  ok    %s\n' "$*"; }
bad() {
    printf '  FAIL  %s\n' "$*"
    fail=1
}
check() {
    local what=$1
    shift
    if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi
}
if [[ $compare_staging == yes && -f $W/root.img ]]; then
    check "staging root.img is byte-identical to IMG's root partition" cmp "$W/root.img" "$ROOT_IMG"
fi

echo "== layout"
sfdisk -J "$IMG" | python3 -I -c '
import json,sys
p=json.load(sys.stdin)["partitiontable"]["partitions"]
assert p[0]["start"]==32768 and p[0]["type"]=="C12A7328-F81F-11D2-BA4B-00A0C93EC93B", p[0]
assert p[1]["type"]=="B921B045-1DF0-41C3-AF44-4C6F280D3FAE", p[1]
print("  ok    GPT: ESP at 16 MiB, root type root-arm64")' || bad "GPT"
if [ "$FW" != none ] && [ -f "$FW" ]; then
    check "firmware.bin at sector 256 reads back" cmp -n "$(stat -c %s "$FW")" -i 0:131072 "$FW" "$IMG"
    check "eGON header at 128 KiB" bash -c "dd if='$IMG' bs=1 skip=$((131072 + 4)) count=8 status=none | grep -q 'eGON.BT0'"

    check "main.bin has the firmware log (magic + SiP 0x82000002 handler)" python3 -I "$TOP/fedora/fwcheck.py" main-fwlog "${MAIN_BIN:-$FWREPO/build/oreboot/main.bin}"
    check "main.bin in firmware.bin is the one checked" bash -c "python3 -I -c 'import sys; sys.exit(0 if open(sys.argv[1],\"rb\").read() in open(sys.argv[2],\"rb\").read() else 1)' '${MAIN_BIN:-$FWREPO/build/oreboot/main.bin}' '$FW'"
    check "EDK2 FD logs to RAM (A7AFWLOG in the FV)" python3 -I "$TOP/fedora/fwcheck.py" fd-has A7AFWLOG "$FW"
    check "EDK2 FD publishes /chosen/oreboot,firmware-log" python3 -I "$TOP/fedora/fwcheck.py" fd-has oreboot,firmware-log "$FW"
    if python3 -I "$TOP/fedora/fwcheck.py" fd-has OrebootLogSerialPortLib "$FW"; then ok "EDK2 FD names OrebootLogSerialPortLib"; else echo "  info  OrebootLogSerialPortLib not named in the FD (no DEBUG path strings)"; fi
else
    check "firmware gap LBA 256-32767 is zero (image without firmware)" cmp -n $((32768 * 512 - 256 * 512)) -i $((256 * 512)):0 "$IMG" /dev/zero
fi

echo "== ESP"
check "shim as EFI/BOOT/BOOTAA64.EFI" mtype -i "$ESP" ::/EFI/BOOT/BOOTAA64.EFI
check "grub in EFI/fedora" mtype -i "$ESP" ::/EFI/fedora/grubaa64.efi
check "shim in EFI/fedora" mtype -i "$ESP" ::/EFI/fedora/shimaa64.efi
uuid=$(sed -n 's/^UUID=\([^ ]*\) *\/ .*/\1/p' "$ROOT/etc/fstab")
check "EFI/fedora/grub.cfg finds root UUID $uuid" bash -c "mtype -i '$ESP' ::/EFI/fedora/grub.cfg | grep -q '$uuid'"
check "boot/grub2/grub.cfg sets root to UUID $uuid" bash -c "'$TOP/fedora/run-build-ns.sh' user cat '$ROOT/boot/grub2/grub.cfg' | grep -q -- '--set=root $uuid'"
# The admission mkdevcard.sh runs at build: DTB stamps validated first, the
# exact entry set with types, the DTB's bytes against the cubie-a7a-dtb
# payload digest, and the marker.
if out=$(python3 -I "$TOP/fedora/devcard-policy.py" esp-admit --root "$ROOT" --esp-img "$ESP" 2>&1); then
    ok "ESP is our build's (stamps, exact entries and types, DTB bytes and marker)"
else
    bad "ESP is our build's: $out"
fi

echo "== kernel, BLS, initramfs"
kver=$(ls "$ROOT/usr/lib/modules")
echo "  kernel $kver ($(grep -c . <<<"$kver") installed)"
check "one Fedora kernel installed" test "$(grep -c . <<<"$kver")" = 1
check "kernel is a Fedora $RELEASEVER build (.fc$RELEASE_NUM)" bash -c "[[ '$kver' == *.fc$RELEASE_NUM.aarch64 ]]"
if [ -n "$KERNEL_VERSION" ]; then
    check "kernel is the pinned build $KERNEL_VERSION" test "$kver" = "$KERNEL_VERSION.aarch64"
fi
# What the image says it is, and where its dnf looks for packages.
osrel_get() { # KEY: its value in the image's os-release (read as text, never sourced)
    sed -n "s/^$1=\"\{0,1\}\([^\"]*\)\"\{0,1\}\$/\1/p" "$ROOT/etc/os-release" | head -1
}
echo "  os-release: VERSION_ID=$(osrel_get VERSION_ID) VARIANT_ID=$(osrel_get VARIANT_ID) VERSION=$(osrel_get VERSION)"
check "os-release VERSION_ID is $RELEASE_NUM" test "$(osrel_get VERSION_ID)" = "$RELEASE_NUM"
enabled_repos() { # ids of the enabled repositories in the image's repository files
    # dnf5 reads both directories; either may be empty.
    python3 -I "$TOP/fedora/devcard-policy.py" enabled-repos \
        "$ROOT/etc/yum.repos.d" "$ROOT/usr/share/dnf5/repos.d"
}
echo "  enabled repositories in the image: $(enabled_repos)"
if [ "$FEDORA_RELEASE" = rawhide ]; then
    check "os-release names Rawhide" bash -c "grep -qi rawhide '$ROOT/etc/os-release'"
    check "image dnf uses the rawhide repository only (no fedora/updates of an unreleased number)" bash -c "[ \"$(enabled_repos | tr -s ' ' '\n' | grep -vx 'fedora-cisco-openh264' | tr '\n' ' ')\" = 'rawhide ' ]"
    check "Rawhide signing key in the image (fedora-gpg-keys)" bash -c "test -e '$ROOT/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-rawhide-aarch64' || test -e '$ROOT/usr/share/pki/rpm-gpg/RPM-GPG-KEY-fedora-rawhide-aarch64'"
else
    check "image dnf uses fedora and updates (no rawhide)" bash -c "r=' $(enabled_repos)'; [[ \$r == *' fedora '* && \$r == *' updates '* && \$r != *' rawhide '* ]]"
fi
check "kernel-core is Fedora-signed" bash -c "grep -E '^kernel-core-' '$PACKAGES' | grep -vq '(none)'"
boot_kmods=$(cubie_boot_kmods "$kver")
pinctrl_builtin=no
case " ${boot_kmods%% -- *} " in *" pinctrl-sun60i-a733 "*) ;; *) pinctrl_builtin=yes ;; esac
for e in "$ROOT"/boot/loader/entries/*.conf; do
    linux=$(python3 -I "$TOP/fedora/devcard-policy.py" loader-entry "$e" linux)
    initrd=$(python3 -I "$TOP/fedora/devcard-policy.py" loader-entry "$e" initrd)
    opts=$(python3 -I "$TOP/fedora/devcard-policy.py" loader-entry "$e" options)
    check "$(basename "$e"): linux $linux exists" test -f "$ROOT$linux"
    check "$(basename "$e"): initrd $initrd exists" test -f "$ROOT$initrd"
    check "$(basename "$e"): root=UUID=$uuid" grep -q "root=UUID=$uuid" <<<"$opts"
    check "$(basename "$e"): clk_ignore_unused pd_ignore_unused" bash -c "grep -q clk_ignore_unused <<<'$opts' && grep -q pd_ignore_unused <<<'$opts'"
    check "$(basename "$e"): regulator_ignore_unused (temporary)" grep -qw regulator_ignore_unused <<<"$opts"
    check "$(basename "$e"): no devicetree line (firmware DTB wins)" bash -c "! grep -q '^devicetree' '$e'"
    rd=$ROOT$initrd
    # The root-on-SD path of this kernel series (release.sh): the board
    # kmods from extra/, and the stock modules.
    for m in ${boot_kmods%% -- *}; do
        check "initramfs has the board kmod $m (extra/)" \
            python3 -I "$TOP/fedora/devcard-policy.py" initramfs-check \
            --run-build-ns "$TOP/fedora/run-build-ns.sh" \
            --require-path "/extra/${m}\\.ko" "$rd"
    done
    for m in ${boot_kmods##* -- }; do
        check "initramfs has $m" \
            python3 -I "$TOP/fedora/devcard-policy.py" initramfs-check \
            --run-build-ns "$TOP/fedora/run-build-ns.sh" \
            --require-path "/${m}\\.ko" "$rd"
    done
    if [ "$pinctrl_builtin" = yes ]; then
        check "initramfs carries no A733 pinctrl module (the kernel's built-in driver binds)" \
            python3 -I "$TOP/fedora/devcard-policy.py" initramfs-check \
            --run-build-ns "$TOP/fedora/run-build-ns.sh" \
            --forbid-path "pinctrl-sun60i-a733" "$rd"
        check "initramfs does not force-load a pinctrl module" \
            python3 -I "$TOP/fedora/devcard-policy.py" initramfs-check \
            --run-build-ns "$TOP/fedora/run-build-ns.sh" \
            --file etc/cmdline.d/20-force_drivers.conf \
            --forbid-text pinctrl "$rd"
    fi
    check "initramfs force-loads the A733 drivers" \
        python3 -I "$TOP/fedora/devcard-policy.py" initramfs-check \
        --run-build-ns "$TOP/fedora/run-build-ns.sh" \
        --file etc/cmdline.d/20-force_drivers.conf \
        --require-text sun60i_a733_ccu "$rd"
done
if [ "$pinctrl_builtin" = yes ]; then
    dkms_mods="sun60i-a733-ccu axp318w axp318-regulator dwmac-sun55i sun8i_thermal nvmem_sunxi_sid"
    override_mods="dwmac-sun55i sun55i-pck600 sun8i_thermal nvmem_sunxi_sid"
    check "kernel config: A733 pinctrl built in (CONFIG_PINCTRL_SUN60I_A733=y)" grep -qx 'CONFIG_PINCTRL_SUN60I_A733=y' "$ROOT/usr/lib/modules/$kver/config"
    check "no A733 pinctrl kmod for $kver (it would never bind)" \
        python3 -I "$TOP/fedora/devcard-policy.py" absence-check "$ROOT" \
        --mode no-glob --pattern 'pinctrl-sun60i-a733.ko*' "usr/lib/modules/$kver/extra"
    check "sun6i-dma is the stock module (A733 support is upstream)" bash -c \
        "python3 -I '$TOP/fedora/devcard-policy.py' absence-check '$ROOT' --mode no-glob --pattern 'sun6i-dma.ko*' 'usr/lib/modules/$kver/extra' && grep -q '^kernel/drivers/dma/sun6i-dma.ko' '$ROOT/usr/lib/modules/$kver/modules.dep'"
    check "stock sun6i-dma knows the A733 (allwinner,sun60i-a733-dma alias)" bash -c "grep -q 'sun60i-a733-dma.* sun6i_dma' '$ROOT/usr/lib/modules/$kver/modules.alias'"
else
    dkms_mods="sun60i-a733-ccu pinctrl-sun60i-a733 axp318w axp318-regulator sun6i-dma dwmac-sun55i sun8i_thermal nvmem_sunxi_sid"
    override_mods="sun6i-dma dwmac-sun55i sun55i-pck600 sun8i_thermal nvmem_sunxi_sid"
fi
for m in $dkms_mods; do
    f=$(ls "$ROOT/usr/lib/modules/$kver/extra/$m.ko"* 2>/dev/null)
    check "DKMS $m built for $kver" test -n "$f"
done
for m in $override_mods; do
    check "depmod prefers the A733 $m (extra/)" bash -c "grep -q '^extra/$m.ko' '$ROOT/usr/lib/modules/$kver/modules.dep'"
done
check "the board package's own kernel check passes for $kver" "$TOP/fedora/run-build-ns.sh" user chroot "$ROOT" /usr/libexec/cubie-a7a/kernel check "$kver"
check "SerDes/PCIe/PPU staged (modprobe.d blacklist)" grep -q '^blacklist sun60i_a733_pcie' "$ROOT/usr/lib/modprobe.d/cubie-a7a-staged.conf"
check "kernel-install guard installed, after Fedora's 95-set-boot-entry" bash -c "test -x '$ROOT/usr/lib/kernel/install.d/99-zz-cubie-a7a.install' && [ \"\$(ls '$ROOT/usr/lib/kernel/install.d' | sort | tail -1)\" = 99-zz-cubie-a7a.install ]"
check "systemd pets WDT0 (16 s, the sunxi_wdt maximum)" grep -qx 'RuntimeWatchdogSec=16s' "$ROOT/usr/lib/systemd/system.conf.d/60-cubie-a7a-watchdog.conf"
check "an oops panics, a panic reboots after 10 s (sysctl.d)" bash -c "grep -qx 'kernel.panic_on_oops = 1' '$ROOT/usr/lib/sysctl.d/60-cubie-a7a-panic.conf' && grep -qx 'kernel.panic = 10' '$ROOT/usr/lib/sysctl.d/60-cubie-a7a-panic.conf'"
check "RTL8125B firmware present" bash -c "ls '$ROOT'/usr/lib/firmware/rtl_nic/rtl8125b-2.fw* >/dev/null"
# Closed-firmware audit: a report, not a check (fedora/image-firmware.py).
if [[ $compare_staging == yes && -s $W/firmware-audit.txt ]]; then
    echo "  info  firmware audit (report only): $(grep '^image-firmware: ' "$W/firmware-audit.txt" | tail -1)"
fi

echo "== DTB"
d_rpm=$ROOT/usr/lib/cubie-a7a/dtb/allwinner/sun60i-a733-cubie-a7a.dtb
check "packaged DTB origin is rpm" bash -c "[ \"\$(fdtget '$d_rpm' / cubie-a7a,dtb-origin)\" = rpm ]"
if [ -z "$FIRMWARE_DTB" ]; then
    FIRMWARE_DTB=$W/verify-firmware-origin.dtb
    rm -f "$FIRMWARE_DTB"
    make -s -C "$TOP/fedora/dts" OUT="$FIRMWARE_DTB" DTB_ORIGIN=firmware >/dev/null 2>&1 || :
fi
if [ -f "$FIRMWARE_DTB" ]; then
    check "packaged and firmware DTB differ only in origin" bash -c "diff <(dtc -I dtb -O dts '$d_rpm' 2>/dev/null | grep -v dtb-origin) <(dtc -I dtb -O dts '$FIRMWARE_DTB' 2>/dev/null | grep -v dtb-origin)"
fi
check "SPI NOR is one read-only partition" bash -c "fdtget '$d_rpm' /soc/spi@2540000/flash@0/partitions/partition@0 read-only >/dev/null"
check "thermal: five zones on the A733 THS, fan cooling device" bash -c "[ \"\$(fdtget -l '$d_rpm' /thermal-zones | wc -l)\" = 5 ] && fdtget '$d_rpm' /thermal-zones/cpu-big-thermal/cooling-maps/map0 cooling-device >/dev/null"

echo "== policy"
shadow=$("$TOP/fedora/run-build-ns.sh" user cat "$ROOT/etc/shadow")
shadow_fields=$(python3 -I "$TOP/fedora/devcard-policy.py" shadow <<<"$shadow")
salt=${shadow_fields%%$'\t'*}
rest=${shadow_fields#*$'\t'}
root_hash=${rest%%$'\t'*}
others=${rest#*$'\t'}
if [ "$root_hash" = "$(openssl passwd -6 -salt "$salt" Fedora123)" ]; then ok "root password is Fedora123"; else bad "root password is Fedora123"; fi
if [ -n "$others" ]; then bad "only root has a password"; else ok "only root has a password"; fi
check "sshd: PermitRootLogin yes" grep -q '^PermitRootLogin yes' "$ROOT/etc/ssh/sshd_config.d/00-public-image.conf"
check "no SSH host keys" \
    python3 -I "$TOP/fedora/devcard-policy.py" absence-check "$ROOT" \
    --mode no-glob --pattern 'ssh_host_*' etc/ssh
check "no authorized_keys" \
    python3 -I "$TOP/fedora/devcard-policy.py" absence-check "$ROOT" \
    --mode no-glob --pattern 'authorized_keys*' root/.ssh
# cubie-a7a-fwlog is optional (built only where the boot-chain checkout is).
units=(sshd NetworkManager firewalld chronyd cubie-a7a-dtb dkms bluetooth)
if grep -q '^cubie-a7a-fwlog-' "$PACKAGES"; then
    units+=(a7a-fwlog)
    check "a7a-fwlog installed (aarch64)" bash -c "file '$ROOT/usr/bin/a7a-fwlog' | grep -q 'ARM aarch64'"
    check "a7a-fwlog.service: SyslogIdentifier, previous boot first, exit 1 tolerated" bash -c "u='$ROOT/usr/lib/systemd/system/a7a-fwlog.service'; grep -q '^SyslogIdentifier=a7a-fwlog' \$u && grep -q '^SuccessExitStatus=1' \$u && [ \"\$(grep -n 'a7a-fwlog -p\$' \$u | cut -d: -f1)\" -lt \"\$(grep -n '^ExecStart=/usr/bin/a7a-fwlog\$' \$u | cut -d: -f1)\" ]"
else
    echo "  info  cubie-a7a-fwlog not installed (no boot-chain checkout at build time)"
fi
for u in "${units[@]}"; do
    check "$u.service enabled" bash -c "ls '$ROOT'/etc/systemd/system/*.wants/$u.service >/dev/null 2>&1"
done
check "no cockpit" bash -c "! grep -q '^cockpit' '$PACKAGES'"
check "CPU rendering: Mesa llvmpipe (libgallium), kms_swrast, EGL and GBM" bash -c "ls '$ROOT'/usr/lib64/libgallium-*.so '$ROOT'/usr/lib64/dri/kms_swrast_dri.so '$ROOT'/usr/lib64/libEGL_mesa.so.0 '$ROOT'/usr/lib64/libgbm.so.1 >/dev/null"
# Every AIC8800 file under usr/lib/firmware must be owned by a signed Fedora
# package and match its recorded digest: provenance, not path.  Fedora's
# linux-firmware files pass (Dave 2026-11-19); an unowned, modified or
# non-Fedora file fails.  Verified directly against ROOT's rpm database.
check "no unowned, modified or non-Fedora AIC8800 firmware" \
    python3 -I "$TOP/fedora/devcard-policy.py" aic-provenance "$ROOT"
if grep -q '^cubie-a7a-aic8800-usb-' "$PACKAGES"; then
    for m in aic_load_fw aic8800_fdrv; do
        check "DKMS $m built for $kver" bash -c "ls '$ROOT/usr/lib/modules/$kver/extra/$m.ko'* >/dev/null"
    done
    # Bluetooth on the mainline btusb; the vendor aic_btusb is not built.
    check "no aic_btusb module for $kver" \
        python3 -I "$TOP/fedora/devcard-policy.py" absence-check "$ROOT" \
        --mode no-glob --pattern 'aic_btusb.ko*' "usr/lib/modules/$kver/extra"
    check "cubie-a7a-wifi-firmware (optional override) and its manifest installed" bash -c "test -x '$ROOT/usr/bin/cubie-a7a-wifi-firmware' && test -s '$ROOT/usr/share/cubie-a7a/aic8800-d80-usb.manifest' && test -s '$ROOT/usr/share/cubie-a7a/WIFI-FIRMWARE.md'"
    check "aic_btusb blacklisted (Bluetooth on the mainline btusb)" bash -c "grep -qx 'blacklist aic_btusb' '$ROOT/usr/lib/modprobe.d/cubie-a7a-aic8800.conf' && grep -qx 'install aic_btusb /bin/false' '$ROOT/usr/lib/modprobe.d/cubie-a7a-aic8800.conf' && ! grep -q '^softdep' '$ROOT/usr/lib/modprobe.d/cubie-a7a-aic8800.conf'"
fi
# Wi-Fi out of the box: NetworkManager manages wlan0 only
# with its Wi-Fi plugin and a supplicant; nothing marks Wi-Fi unmanaged and
# nothing connects anywhere on its own.
for pkg in NetworkManager-wifi wpa_supplicant iw bluez wireless-regdb; do
    check "$pkg installed" grep -q "^$pkg-[0-9]" "$PACKAGES"
done
check "no iwd (NetworkManager's Wi-Fi backend is wpa_supplicant)" bash -c "! grep -q '^iwd-[0-9]' '$PACKAGES'"
check "NetworkManager Wi-Fi device plugin present" bash -c "ls '$ROOT'/usr/lib64/NetworkManager/*/libnm-device-plugin-wifi.so >/dev/null 2>&1"
check "NetworkManager config leaves devices managed (no unmanaged-devices, no managed=false)" \
    python3 -I "$TOP/fedora/devcard-policy.py" absence-check "$ROOT" \
    --mode no-text --ignore-case --pattern '^[ \t]*(unmanaged-devices|managed[ \t]*=[ \t]*(0|false|no))' \
    etc/NetworkManager usr/lib/NetworkManager/conf.d
check "no udev rule marks Wi-Fi unmanaged (only NetworkManager's own 85-nm-unmanaged.rules, which names no Wi-Fi)" bash -c \
    "python3 -I '$TOP/fedora/devcard-policy.py' absence-check '$ROOT' --mode no-text --pattern 'NM_UNMANAGED' --allow-basename 85-nm-unmanaged.rules etc/udev/rules.d usr/lib/udev/rules.d && python3 -I '$TOP/fedora/devcard-policy.py' absence-check '$ROOT' --mode no-text --ignore-case --pattern 'wlan|wifi|wlp|aic' usr/lib/udev/rules.d/85-nm-unmanaged.rules"
check "no Wi-Fi connection profile in the image (nothing auto-connects)" \
    python3 -I "$TOP/fedora/devcard-policy.py" absence-check "$ROOT" \
    --mode no-text --pattern 'type=wifi|type=802-11-wireless' \
    etc/NetworkManager/system-connections usr/lib/NetworkManager/system-connections
for pkg in $EXTRA_PACKAGES; do
    check "$pkg installed (EXTRA_PACKAGES)" grep -q "^$pkg-[0-9]" "$PACKAGES"
done
if [[ $compare_staging == yes && -s $W/overlay.sha256 ]]; then
    check "overlay files in the root as built ($(wc -l <"$W/overlay.sha256") files)" "$TOP/fedora/run-build-ns.sh" user bash -c "cd '$(realpath "$ROOT")' && sha256sum --quiet -c '$(realpath "$W/overlay.sha256")'"
fi
# check-sshd.sh runs the target sshd (qemu-user) in the private namespace.
if [ "${A7A_PRIVATE_BUILD:-}" = 1 ] || [ "$(id -u)" = 0 ]; then
    check "actual target sshd policy and sole human account" "$TOP/fedora/check-sshd.sh" "$ROOT" "$W/effective-sshd.txt"
else
    check "actual target sshd policy and sole human account" "$TOP/fedora/private-build.sh" "$TOP/fedora/check-sshd.sh" "$ROOT" "$W/effective-sshd.txt"
fi
check "SELinux enforcing" grep -q '^SELINUX=enforcing' "$ROOT/etc/selinux/config"
# Build-host paths must not appear in the image (dnf persistdir, cachedir and
# the like are relative to the installroot) and /dev holds no regular files.
check "no build-host paths in the root (/work, /data, /home/*)" \
    python3 -I "$TOP/fedora/devcard-policy.py" absence-check "$ROOT" \
    --mode no-entries home work data
check "/dev has no regular files" \
    python3 -I "$TOP/fedora/devcard-policy.py" absence-check "$ROOT" \
    --mode no-regular-files dev
# Rootless builds see file capabilities as v3 xattrs with the build user's
# rootid outside the namespace; inside it (where mkfs.ext4 -d runs) the kernel
# hands out the v2 form, which the board applies for root. Lock that in.
check "file capabilities in ext4 are version 2 (no namespace rootid)" bash -c "debugfs -R 'ea_get -x usr/sbin/arping security.capability' '$ROOT_IMG' 2>/dev/null | grep -q 'security.capability (20) = 00 00 00 02'"
check "SELinux labels in ext4 match target policy" "$TOP/fedora/run-build-ns.sh" user python3 -I "$TOP/fedora/selinux-label.py" --verify "$ROOT" "$ROOT_IMG" "$W/selinux-verify"
check "no first-boot relabel required (all image labels verified)" test ! -e "$ROOT/.autorelabel"
check "machine-id empty (first boot)" test ! -s "$ROOT/etc/machine-id"
# systemd-repart discards the unpartitioned gap in front of the first
# partition whenever it changes the partition table (--discard=yes is its
# default), and that gap holds the boot firmware. Every repart unit in the
# image must therefore run its own command line plus --discard=no
# (mkdevcard.sh writes the drop-ins); an image with a repart.d configuration
# and no such setting loses its firmware on the first rw boot from a native
# eMMC or SD slot.
repart_root_ok() {
    local out
    if out=$(python3 -I "$TOP/fedora/devcard-policy.py" repart-root --grow-root "$GROW_ROOT" "$ROOT" 2>&1); then
        ok "systemd-repart runs with --discard=no, pinned configuration, GROW_ROOT=$GROW_ROOT (the unpartitioned gap holds the boot firmware)"
    else
        bad "systemd-repart runs with --discard=no, pinned configuration, GROW_ROOT=$GROW_ROOT: $out"
    fi
}
repart_initramfs_ok() {
    local img out found=0
    for img in "$ROOT"/boot/initramfs-*.img; do
        [ -f "$img" ] || continue
        found=1
        if out=$(python3 -I "$TOP/fedora/devcard-policy.py" repart-initramfs \
            --run-build-ns "$TOP/fedora/run-build-ns.sh" "$img" 2>&1); then
            ok "${img##*/}: effective systemd-repart carries --discard=no (or absent/masked)"
        else
            bad "${img##*/}: effective systemd-repart lacks --discard=no: $out"
        fi
    done
    [ "$found" = 1 ] || bad "initramfs: none found under $ROOT/boot"
}
repart_root_ok
repart_initramfs_ok
if [ "$GROW_ROOT" = yes ]; then
    # repart-root --grow-root yes above: the unit present, unmasked and
    # enabled, and exactly our etc/repart.d/50-root.conf.
    echo "== root growth: on first boot (GROW_ROOT=yes, checked by repart-root)"
else
    echo "== root growth: never (GROW_ROOT=no)"
    check "no repart.d config (etc, usr/lib, usr/local/lib)" \
        python3 -I "$TOP/fedora/devcard-policy.py" absence-check "$ROOT" \
        --mode no-glob --recursive --pattern '*.conf' etc/repart.d run/repart.d usr/lib/repart.d usr/local/lib/repart.d
    check "fstab: no x-systemd.growfs (and no x-systemd.makefs)" bash -c "! grep -qE 'x-systemd\.(growfs|makefs)' '$ROOT/etc/fstab'"
    repart_initramfs_absent() {
        local img found=0
        for img in "$ROOT"/boot/initramfs-*.img; do
            [ -f "$img" ] || continue
            found=1
            python3 -I "$TOP/fedora/devcard-policy.py" repart-initramfs \
                --run-build-ns "$TOP/fedora/run-build-ns.sh" --forbid-repart "$img" >/dev/null || return 1
        done
        [ "$found" = 1 ]
    }
    check "initramfs does not run systemd-repart (post-overlay image)" repart_initramfs_absent
    for u in systemd-repart.service systemd-growfs-root.service; do
        lbl=$(debugfs -R "ea_get -V etc/systemd/system/$u security.selinux" "$ROOT_IMG" 2>/dev/null | tr -d '\0\n')
        check "$u masked in /etc/systemd/system (-> /dev/null)" bash -c "[ \"\$(readlink '$ROOT/etc/systemd/system/$u')\" = /dev/null ]"
        check "$u mask labelled in the image ($lbl)" bash -c "[[ '$lbl' == system_u:object_r:*_t:s0 ]]"
    done
fi
echo "  info  root filesystem: $(python3 -I "$TOP/fedora/devcard-policy.py" dumpe2fs "$ROOT_IMG"); image $(stat -c %s "$IMG") bytes"

if [ "$BOOT_MODES" = protective ]; then
    echo "== boot modes (protective default, maintenance, full)"
    bm=$ROOT/usr/local/bin/cubie-a7a-bootmode
    check "cubie-a7a-bootmode installed" test -x "$bm"
    # Found by name where it is used: a command over ssh gets sshd's compiled
    # PATH (no sbin directories on Fedora 42+), not a login shell's.
    sshpath=$(strings "$ROOT/usr/libexec/openssh/sshd-session" "$ROOT/usr/bin/sshd" 2>/dev/null | grep -m1 -E '^/usr/local/bin:/' || :)
    echo "  info  sshd PATH for commands: ${sshpath:-not found}"
    check "cubie-a7a-bootmode found by name on that PATH (ssh root@board cubie-a7a-bootmode ...)" bash -c "[ -n '$sshpath' ] && IFS=: && for d in \$(echo '$sshpath'); do [ -x '$ROOT'\$d/cubie-a7a-bootmode ] && exit 0; done; exit 1"
    check "cubie-a7a-bootmode labelled bin_t in the image" bash -c "debugfs -R 'ea_get usr/local/bin/cubie-a7a-bootmode security.selinux' '$ROOT_IMG' 2>/dev/null | grep -q ':object_r:bin_t:s0'"
    check "kernel-install plugin 96-cubie-a7a-bootmodes installed" test -x "$ROOT/etc/kernel/install.d/96-cubie-a7a-bootmodes.install"
    check "the plugin and cubie-a7a-bootmode-ro.service call the installed helper" bash -c "for f in '$ROOT/etc/kernel/install.d/96-cubie-a7a-bootmodes.install' '$ROOT/etc/systemd/system/cubie-a7a-bootmode-ro.service'; do for h in \$(grep -o '/usr/[a-z/]*/cubie-a7a-bootmode\\b' \"\$f\" | sort -u); do [ -x '$ROOT'\$h ] || exit 1; done; grep -q '/usr/local/bin/cubie-a7a-bootmode' \"\$f\" || exit 1; done"
    check "cubie-a7a-bootmode-ro.service enabled" bash -c "ls '$ROOT'/etc/systemd/system/sysinit.target.wants/cubie-a7a-bootmode-ro.service >/dev/null 2>&1"
    check "cubie-a7a-bootmode-next.service enabled, rw boots only (clears a next_entry GRUB could not)" bash -c "ls '$ROOT'/etc/systemd/system/sysinit.target.wants/cubie-a7a-bootmode-next.service >/dev/null 2>&1 && grep -q '^ConditionKernelCommandLine=!systemd.volatile=overlay\$' '$ROOT/etc/systemd/system/cubie-a7a-bootmode-next.service' && grep -q '^ExecStart=/usr/local/bin/cubie-a7a-bootmode consume-next\$' '$ROOT/etc/systemd/system/cubie-a7a-bootmode-next.service'"
    dargs=$(bash "$bm" default-args 2>/dev/null)
    hat=cubie_a7a.hat=0
    protect=${dargs#"$hat" }
    echo "  default entry adds: $dargs"
    has_all() { # words line
        local w
        for w in $1; do case " $2 " in *" $w "*) ;; *) return 1 ;; esac done
    }
    strip() { # line words
        local o="" w x k
        for w in $1; do
            k=1
            for x in $2; do [ "$w" = "$x" ] && k=0; done
            [ $k = 1 ] && o="$o $w"
        done
        echo "${o# }"
    }
    check "/etc/kernel/cmdline carries the protective options (new kernels' default entry)" has_all "$dargs" "$(cat "$ROOT/etc/kernel/cmdline")"
    check "/etc/default/grub GRUB_CMDLINE_LINUX carries them (grub2-mkconfig fallback stays protective)" has_all "$dargs" "$(sed -n 's/^GRUB_CMDLINE_LINUX=\"\(.*\)\"$/\1/p' "$ROOT/etc/default/grub")"
    check "/etc/kernel/cmdline newer than /etc/default/grub (no grub2-mkconfig from 20-grub.install)" test "$ROOT/etc/kernel/cmdline" -nt "$ROOT/etc/default/grub"
    check "masked units exist as named (cubie-a7a-dtb, systemd-repart, systemd-growfs@)" bash -c "test -f '$ROOT/usr/lib/systemd/system/cubie-a7a-dtb.service' && test -f '$ROOT/usr/lib/systemd/system/systemd-repart.service' && test -f '$ROOT/usr/lib/systemd/system/systemd-growfs-root.service'"
    check "fstab: /boot/efi (boot-efi.mount)" grep -q ' /boot/efi ' "$ROOT/etc/fstab"
    nmain=0
    for e in "$ROOT"/boot/loader/entries/*.conf; do
        case "$(basename "$e")" in *~*) continue ;; esac
        nmain=$((nmain + 1))
        id=$(basename "$e" .conf)
        o=$(python3 -I "$TOP/fedora/devcard-policy.py" loader-entry "$e" options)
        mt=${e%.conf}~maintenance.conf
        fu=${e%.conf}~full.conf
        mo=$(python3 -I "$TOP/fedora/devcard-policy.py" loader-entry "$mt" options)
        fo=$(python3 -I "$TOP/fedora/devcard-policy.py" loader-entry "$fu" options)
        echo "  $id"
        echo "    default:     $o"
        echo "    maintenance: $mo"
        echo "    full:        $fo"
        check "$id: default entry has $dargs" has_all "$dargs" "$o"
        check "$id~maintenance: exists, = default minus the protective options (rw, hat=0)" bash -c "test -f '$mt' && [ '$mo' = '$(strip "$o" "$protect")' ] && grep -qw '$hat' <<<'$mo'"
        check "$id~full: exists, = maintenance minus cubie_a7a.hat=0 (rw, HAT on)" bash -c "test -f '$fu' && [ '$fo' = '$(strip "$mo" "$hat")' ] && ! grep -q 'cubie_a7a.hat' <<<'$fo' && ! grep -q 'systemd.volatile' <<<'$fo'"
        check "$id: the three entries boot the same kernel and initramfs" bash -c "[ \"\$(grep -E '^(linux|initrd|version) ' '$e')\" = \"\$(grep -E '^(linux|initrd|version) ' '$mt')\" ] && [ \"\$(grep -E '^(linux|initrd|version) ' '$e')\" = \"\$(grep -E '^(linux|initrd|version) ' '$fu')\" ]"
        check "$id: titles name the modes" bash -c "grep -q '^title .*(protective: ro overlay, hat=0)\$' '$e' && grep -q '^title .* maintenance (rw, hat=0)\$' '$mt' && grep -q '^title .* full (rw, HAT on)\$' '$fu'"
    done
    check "one default entry per kernel ($nmain), three entries each" bash -c "[ $nmain = \"\$(ls '$ROOT/usr/lib/modules' | wc -l)\" ] && [ \"\$(ls '$ROOT'/boot/loader/entries/*.conf | wc -l)\" = $((nmain * 3)) ]"
    genv=$("$TOP/fedora/run-build-ns.sh" user cat "$ROOT/boot/grub2/grubenv")
    saved=$(sed -n 's/^saved_entry=//p' <<<"$genv")
    echo "  grubenv: $(grep -v '^#' <<<"$genv" | tr '\n' ' ')"
    check "grubenv saved_entry is a default (protective) entry" bash -c "[ -n '$saved' ] && [ -f '$ROOT/boot/loader/entries/$saved.conf' ] && [[ '$saved' != *~* ]]"
    if [ "$FIRST_BOOT" = maintenance ]; then
        nxt=$(sed -n 's/^next_entry=//p' <<<"$genv")
        check "grubenv next_entry is the default's ~maintenance entry, once (first boot rw, hat=0)" bash -c "[ '$nxt' = '$saved~maintenance' ] && [ -f '$ROOT/boot/loader/entries/$nxt.conf' ] && [ \"\$(grep -c '^next_entry=' <<<'$genv')\" = 1 ]"
    else
        check "grubenv has no next_entry (the first boot is the default entry)" bash -c "! grep -q '^next_entry=' <<<'$genv'"
    fi
    check "grubenv is one 1024-byte block (cubie-a7a-bootmode rewrites it in place on the ro boot)" bash -c "[ \"\$(stat -c %s '$ROOT/boot/grub2/grubenv')\" = 1024 ] && debugfs -R 'blocks /boot/grub2/grubenv' '$ROOT_IMG' 2>/dev/null | grep -qE '^[0-9]+ *\$'"
    check "without saved_entry, the newest default entry still sorts first (rpm/sort -V order)" bash -c "ls '$ROOT/boot/loader/entries' | sed 's/\.conf\$//' | sort -rV | head -1 | grep -qv '~'"
    check "grub.cfg: next_entry honoured, and its only save_env clears it (GRUB writes nothing on a default boot)" bash -c "c=\$('$TOP/fedora/run-build-ns.sh' user cat '$ROOT/boot/grub2/grub.cfg'); grep -q 'set default=\"\\\${next_entry}\"' <<<\"\$c\" && [ \"\$(grep -c save_env <<<\"\$c\")\" = 1 ] && grep -q '^ *save_env next_entry\$' <<<\"\$c\""
    for e in "$ROOT"/boot/loader/entries/*.conf; do
        case "$(basename "$e")" in *~*) continue ;; esac
        rd=$ROOT$(python3 -I "$TOP/fedora/devcard-policy.py" loader-entry "$e" initrd)
        check "$(basename "$e" .conf): initramfs has systemd-volatile-root and overlay.ko" \
            python3 -I "$TOP/fedora/devcard-policy.py" initramfs-check \
            --run-build-ns "$TOP/fedora/run-build-ns.sh" \
            --require-path 'systemd/systemd-volatile-root$' \
            --require-path 'systemd-volatile-root\.service$' \
            --require-path '/overlay\.ko' "$rd"
    done
fi
unsigned=$(grep -v -E '^gpg-pubkey' "$PACKAGES" | grep '(none)' | cut -d' ' -f1 | tr '\n' ' ')
echo "  info  unsigned packages: ${unsigned:-none}"
check "unsigned packages limited to the cubie-a7a board packages" bash -c "! grep -v -E '^(gpg-pubkey|cubie-a7a-)' '$PACKAGES' | grep -q '(none)'"

if [ $fail = 0 ]; then
    echo "all checks passed"
else
    echo "some checks FAILED"
    exit 1
fi
