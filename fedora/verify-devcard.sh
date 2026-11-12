#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Offline checks of a dev card built by fedora/mkdevcard.sh: layout and
# firmware, boot chain files, initramfs contents, image policy. Reads only.
# Not a board test.
#
# Usage: fedora/verify-devcard.sh [IMAGE] [WORK_DIR]
set -uo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
IMG=${1:-$TOP/build/image/a7a-fedora-dev.img}
W=${2:-$TOP/build/fedora/devcard}
# The dev card firmware's build tree (FWREPO), if any.
FWREPO=${FWREPO:-none}
# FW=none (default) for an image without firmware (make fedora-image).
FW=${FW:-none}
ROOT=$W/root
# The DTB the firmware would embed from this source tree (DTB_ORIGIN=firmware);
# built here unless a specific firmware DTB is given.
FIRMWARE_DTB=${FIRMWARE_DTB:-}
ESP=$W/esp.img
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
fwstamp=$(cat "$ROOT/var/lib/cubie-a7a/firmware-dtb-version")
pkgstamp=$(cat "$ROOT/usr/lib/cubie-a7a/dtb/VERSION")
if [ "$fwstamp" -lt "$pkgstamp" ]; then
    check "ESP DTB override present (firmware stamp $fwstamp < package $pkgstamp)" mtype -i "$ESP" ::/dtb/allwinner/sun60i-a733-cubie-a7a.dtb
else
    if mdir -i "$ESP" ::/dtb >/dev/null 2>&1; then bad "no DTB override on the ESP (firmware DTB is current)"; else ok "no DTB override on the ESP (firmware DTB is current)"; fi
fi

echo "== kernel, BLS, initramfs"
kver=$(ls "$ROOT/usr/lib/modules")
echo "  kernel $kver ($(grep -c . <<<"$kver") installed)"
check "one Fedora kernel installed" test "$(grep -c . <<<"$kver")" = 1
check "kernel is a Fedora ${FEDORA_RELEASE:-45} build" bash -c "[[ '$kver' == *.fc${FEDORA_RELEASE:-45}.aarch64 ]]"
check "kernel-core is Fedora-signed" bash -c "grep -E '^kernel-core-' '$W/packages.txt' | grep -vq '(none)'"
for e in "$ROOT"/boot/loader/entries/*.conf; do
    linux=$(awk '$1=="linux"{print $2}' "$e")
    initrd=$(awk '$1=="initrd"{print $2}' "$e")
    opts=$(awk '$1=="options"{$1="";print}' "$e")
    check "$(basename "$e"): linux $linux exists" test -f "$ROOT$linux"
    check "$(basename "$e"): initrd $initrd exists" test -f "$ROOT$initrd"
    check "$(basename "$e"): root=UUID=$uuid" grep -q "root=UUID=$uuid" <<<"$opts"
    check "$(basename "$e"): clk_ignore_unused pd_ignore_unused" bash -c "grep -q clk_ignore_unused <<<'$opts' && grep -q pd_ignore_unused <<<'$opts'"
    check "$(basename "$e"): regulator_ignore_unused (temporary)" grep -qw regulator_ignore_unused <<<"$opts"
    check "$(basename "$e"): no devicetree line (firmware DTB wins)" bash -c "! grep -q '^devicetree' '$e'"
    rd=$ROOT$initrd
    for m in sun60i-a733-ccu pinctrl-sun60i-a733 axp318w axp318-regulator sun6i-dma sunxi-mmc i2c-mv64xxx; do
        check "initramfs has $m" bash -c "'$TOP/fedora/run-build-ns.sh' user lsinitrd '$rd' 2>/dev/null | grep -q '/$m.ko'"
    done
    check "initramfs force-loads the A733 drivers" bash -c "'$TOP/fedora/run-build-ns.sh' user lsinitrd -f etc/cmdline.d/20-force_drivers.conf '$rd' 2>/dev/null | grep -q sun60i_a733_ccu"
done
for m in sun60i-a733-ccu pinctrl-sun60i-a733 axp318w axp318-regulator sun6i-dma dwmac-sun55i sun8i_thermal nvmem_sunxi_sid; do
    f=$(ls "$ROOT/usr/lib/modules/$kver/extra/$m.ko"* 2>/dev/null)
    check "DKMS $m built for $kver" test -n "$f"
done
for m in sun6i-dma dwmac-sun55i sun55i-pck600 sun8i_thermal nvmem_sunxi_sid; do
    check "depmod prefers the A733 $m (extra/)" bash -c "grep -q '^extra/$m.ko' '$ROOT/usr/lib/modules/$kver/modules.dep'"
done
check "SerDes/PCIe/PPU staged (modprobe.d blacklist)" grep -q '^blacklist sun60i_a733_pcie' "$ROOT/usr/lib/modprobe.d/cubie-a7a-staged.conf"
check "kernel-install guard installed, after Fedora's 95-set-boot-entry" bash -c "test -x '$ROOT/usr/lib/kernel/install.d/99-zz-cubie-a7a.install' && [ \"\$(ls '$ROOT/usr/lib/kernel/install.d' | sort | tail -1)\" = 99-zz-cubie-a7a.install ]"
check "RTL8125B firmware present" bash -c "ls '$ROOT'/usr/lib/firmware/rtl_nic/rtl8125b-2.fw* >/dev/null"
# Closed-firmware audit: a report, not a check (fedora/image-firmware.py).
if [ -s "$W/firmware-audit.txt" ]; then
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
salt=$(awk -F: '$1=="root"{split($2,a,"$"); print a[3]}' <<<"$shadow")
if [ "$(awk -F: '$1=="root"{print $2}' <<<"$shadow")" = "$(openssl passwd -6 -salt "$salt" Fedora123)" ]; then ok "root password is Fedora123"; else bad "root password is Fedora123"; fi
if awk -F: '$2 ~ /^\$/ && $1 != "root"' <<<"$shadow" | grep -q .; then bad "only root has a password"; else ok "only root has a password"; fi
check "sshd: PermitRootLogin yes" grep -q '^PermitRootLogin yes' "$ROOT/etc/ssh/sshd_config.d/00-public-image.conf"
check "no SSH host keys" bash -c "! ls '$ROOT'/etc/ssh/ssh_host_* >/dev/null 2>&1"
check "no authorized_keys" bash -c "! ls '$ROOT'/root/.ssh/authorized_keys* >/dev/null 2>&1"
# cubie-a7a-fwlog is optional (built only where the boot-chain checkout is).
units="sshd NetworkManager firewalld chronyd cubie-a7a-dtb dkms"
if grep -q '^cubie-a7a-fwlog-' "$W/packages.txt"; then
    units="$units a7a-fwlog"
    check "a7a-fwlog installed (aarch64)" bash -c "file '$ROOT/usr/bin/a7a-fwlog' | grep -q 'ARM aarch64'"
    check "a7a-fwlog.service: SyslogIdentifier, previous boot first, exit 1 tolerated" bash -c "u='$ROOT/usr/lib/systemd/system/a7a-fwlog.service'; grep -q '^SyslogIdentifier=a7a-fwlog' \$u && grep -q '^SuccessExitStatus=1' \$u && [ \"\$(grep -n 'a7a-fwlog -p\$' \$u | cut -d: -f1)\" -lt \"\$(grep -n '^ExecStart=/usr/bin/a7a-fwlog\$' \$u | cut -d: -f1)\" ]"
else
    echo "  info  cubie-a7a-fwlog not installed (no boot-chain checkout at build time)"
fi
# shellcheck disable=SC2086 # a word list
for u in $units; do
    check "$u.service enabled" bash -c "ls '$ROOT'/etc/systemd/system/*.wants/$u.service >/dev/null 2>&1"
done
check "no cockpit" bash -c "! grep -q '^cockpit' '$W/packages.txt'"
check "CPU rendering: Mesa llvmpipe (libgallium), kms_swrast, EGL and GBM" bash -c "ls '$ROOT'/usr/lib64/libgallium-*.so '$ROOT'/usr/lib64/dri/kms_swrast_dri.so '$ROOT'/usr/lib64/libEGL_mesa.so.0 '$ROOT'/usr/lib64/libgbm.so.1 >/dev/null"
# AIC8800D80 firmware: Fedora's linux-firmware (
# WIFI-FIRMWARE.md). The image never carries the user override directory.
check "AIC8800 firmware present from linux-firmware (aic/aic8800d80)" bash -c "grep -q '^linux-firmware-[0-9]*:' '$W/packages.txt' && for f in fw_patch_table_8800d80_u02 fw_adid_8800d80_u02 fw_patch_8800d80_u02 fmacfw_8800d80_u02; do ls '$ROOT'/usr/lib/firmware/aic/aic8800d80/\$f.bin* >/dev/null 2>&1 || exit 1; done"
check "no user-override AIC8800 firmware in the image (aic8800_fw)" bash -c "! find '$ROOT/usr/lib/firmware' -path '*aic8800_fw*' -print -quit | grep -q ."
f=$(find "$ROOT/usr/lib/firmware/aic/aic8800d80" -name 'fmacfw_8800d80_u02.bin*' -print -quit 2>/dev/null || :)
if [ -n "$f" ] && [ "$(xz -dcf -- "$f" 2>/dev/null | grep -ac 'sdio_func1_h2d')" != 0 ]; then
    echo "  info  linux-firmware's AIC8800D80 Wi-Fi image is the SDIO build: the USB chip stays unbound until a USB build is there (WIFI-FIRMWARE.md)"
fi
if grep -q '^cubie-a7a-aic8800-usb-' "$W/packages.txt"; then
    for m in aic_load_fw aic8800_fdrv aic_btusb; do
        check "DKMS $m built for $kver" bash -c "ls '$ROOT/usr/lib/modules/$kver/extra/$m.ko'* >/dev/null"
    done
    check "cubie-a7a-wifi-firmware (optional override) and its manifest installed" bash -c "test -x '$ROOT/usr/bin/cubie-a7a-wifi-firmware' && test -s '$ROOT/usr/share/cubie-a7a/aic8800-d80-usb.manifest' && test -s '$ROOT/usr/share/cubie-a7a/WIFI-FIRMWARE.md'"
    check "aic_btusb before btusb (softdep)" grep -q '^softdep btusb pre: aic_btusb' "$ROOT/usr/lib/modprobe.d/cubie-a7a-aic8800.conf"
    check "NetworkManager-wifi and bluez installed" bash -c "grep -q '^NetworkManager-wifi-' '$W/packages.txt' && grep -q '^bluez-' '$W/packages.txt'"
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
check "no build-host paths in the root (/work, /data, /home/*)" bash -c "! find '$ROOT/home' '$ROOT/work' '$ROOT/data' -mindepth 1 2>/dev/null | grep -q ."
check "/dev has no regular files" bash -c "! find '$ROOT/dev' -type f 2>/dev/null | grep -q ."
# Rootless builds see file capabilities as v3 xattrs with the build user's
# rootid outside the namespace; inside it (where mkfs.ext4 -d runs) the kernel
# hands out the v2 form, which the board applies for root. Lock that in.
check "file capabilities in ext4 are version 2 (no namespace rootid)" bash -c "debugfs -R 'ea_get -x usr/sbin/arping security.capability' '$W/root.img' 2>/dev/null | grep -q 'security.capability (20) = 00 00 00 02'"
check "SELinux labels in ext4 match target policy" "$TOP/fedora/run-build-ns.sh" user python3 -I "$TOP/fedora/selinux-label.py" --verify "$ROOT" "$W/root.img" "$W/selinux-verify"
check "no first-boot relabel required (all image labels verified)" test ! -e "$ROOT/.autorelabel"
check "machine-id empty (first boot)" test ! -s "$ROOT/etc/machine-id"
check "repart grows root" test -f "$ROOT/etc/repart.d/50-root.conf"
unsigned=$(grep -v -E '^gpg-pubkey' "$W/packages.txt" | grep '(none)' | cut -d' ' -f1 | tr '\n' ' ')
echo "  info  unsigned packages: ${unsigned:-none}"
check "unsigned packages limited to the cubie-a7a board packages" bash -c "! grep -v -E '^(gpg-pubkey|cubie-a7a-)' '$W/packages.txt' | grep -q '(none)'"

if [ $fail = 0 ]; then
    echo "all checks passed"
else
    echo "some checks FAILED"
    exit 1
fi
