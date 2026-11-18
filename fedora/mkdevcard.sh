#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Build the Fedora dev card (FEDORA_RELEASE, default 45) for the Radxa Cubie A7A, rootless:
#   build/image/a7a-fedora-dev.img (sparse raw) and .img.xz
#
#   0x00000000  protective MBR + GPT
#   0x00020000  firmware.bin (oreboot bt0 at 128 KiB, layout table, main, EDK2)
#   16 MiB      GPT 1 "EFI"  FAT32 ESP, 512 MiB (shim + grub, Fedora layout)
#   528 MiB     GPT 2 "root" ext4 "Fedora<release>-root" (type root-arm64), grown to
#                       the card on first boot by systemd-repart + growfs
#                       (GROW_ROOT=no: never grown)
#
# Root filesystem: stock Fedora packages (signature-checked by dnf) plus
# cubie-a7a-dtb and cubie-a7a-board-support, installed with dnf5 into an
# aarch64 installroot inside a user namespace (unshare --map-auto); package
# scriptlets run under qemu-aarch64 binfmt. That includes the DKMS build of
# the A733 modules and the initramfs. SELinux labels cannot be set from a
# user namespace; fedora/selinux-label.py writes them into the ext4 image.
#
# Image policy: root is the only human login,
# password Fedora123 (ROOT_PASSWORD), root password SSH allowed, sshd and
# DHCP on, no Cockpit, no SSH keys of anyone, no host keys (generated on
# first boot).
#
# Usage: fedora/mkdevcard.sh FIRMWARE_BIN RPMS_DIR   (rpmbuild RPMS/: noarch/ and aarch64/)
#
# Optional (unset: the image as before):
#   EXTRA_PACKAGES="a b"   more Fedora packages (e.g. perf memtester)
#   BOOT_MODES=protective  three GRUB entries per kernel (fedora/bootmodes/):
#     default: root read-only under a RAM overlay, HAT stack off, nothing
#              on the card written (/etc/kernel/cmdline carries it, so
#              kernel updates keep it); "~maintenance": rw, HAT off;
#              "~full": rw, HAT on. Root growth (systemd-repart + growfs)
#              is masked on the default entry and happens on the first
#              maintenance boot. cubie-a7a-bootmode selects a one-shot entry
#              from any of them.
#   FIRST_BOOT=maintenance (with BOOT_MODES=protective) the first boot is a
#              one-shot maintenance boot (grubenv next_entry), so the
#              machine-id and SSH host keys are written once to the card;
#              every later boot is the protective default.
#   GROW_ROOT=no  the root is never grown, on any entry: no
#              /etc/repart.d config, no x-systemd.growfs, systemd-repart and
#              systemd-growfs-root masked in /etc/systemd/system (for cards
#              that must not be written beyond the image).
#   ROOT_MIN_MIB=N  root filesystem at least N MiB (default: content + 30 %
#              + 512 MiB), e.g. room for package installs when GROW_ROOT=no.
#
# FIRMWARE_BIN "none" builds the Fedora image alone (make fedora-image): LBA
# 256-32767 (128 KiB-16 MiB) stay zero for the boot firmware's
# firmware.bin (radxa-a7a-workspace, make firmware), which is written at
# LBA 256 afterwards. That firmware must embed the DTB from fedora/dts at the
# same DTB_VERSION, since the image records it as the firmware's.
set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
FIRMWARE=${1:?firmware.bin}
RPMDIR=${2:?rpmbuild RPMS directory with noarch/ and aarch64/ cubie-a7a packages}
W=${WORK:-$TOP/build/fedora/devcard}
OUT=${OUT:-$TOP/build/image/a7a-fedora-dev.img}
ROOT_PASSWORD=${ROOT_PASSWORD:-Fedora123}
RELEASEVER=${FEDORA_RELEASE:-45}
# Fedora's own kernel: whatever the fedora + updates repositories carry at
# build time (recorded in the manifest, never pinned or rebuilt). The board
# kmods follow it through DKMS (cubie-a7a-board-support).
KERNEL_PACKAGES=(kernel kernel-core kernel-modules-core kernel-modules kernel-devel)
BUILD_JOBS=${BUILD_JOBS:-2}
[[ $BUILD_JOBS =~ ^[1-9][0-9]*$ ]] || {
    echo "invalid BUILD_JOBS" >&2
    exit 2
}
ESP_MIB=512
DTB_VERSION=$(cat "$TOP/fedora/dts/DTB_VERSION")
# The binding stamp of the DTB the card's firmware embeds. 0 (default):
# unknown, so cubie-a7a-dtb installs its DTB on the ESP and the image boots
# with its own device tree whatever firmware is written at LBA 256. Set it
# to DTB_VERSION only for a card whose firmware embeds this commit's DTB.
FIRMWARE_DTB_VERSION=${FIRMWARE_DTB_VERSION:-0}
[[ $FIRMWARE_DTB_VERSION =~ ^[0-9]+$ ]] || {
    echo "invalid FIRMWARE_DTB_VERSION" >&2
    exit 2
}

die() {
    echo "mkdevcard: $*" >&2
    exit 1
}
for t in unshare dnf5 mkfs.ext4 mkfs.fat mcopy sfdisk openssl xz debugfs python3; do
    command -v $t >/dev/null || die "$t not found"
done
python3 -I -c 'import selinux' 2>/dev/null || die "python3-libselinux not found"
# On an aarch64 host (the image builder's QEMU guest) the target's scriptlets
# run natively; elsewhere they need qemu-aarch64 binfmt.
if [ "$(uname -m)" != aarch64 ]; then
    command -v qemu-aarch64-static >/dev/null || die "qemu-aarch64-static not found"
    [ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ] || die "no qemu-aarch64 binfmt handler registered"
    grep -q '^flags: .*F' /proc/sys/fs/binfmt_misc/qemu-aarch64 || die "qemu-aarch64 binfmt needs the F (fix-binary) flag"
fi
if [ "$FIRMWARE" = none ]; then
    FIRMWARE=
else
    [ -f "$FIRMWARE" ] || die "missing $FIRMWARE"
    SEEK=$(cat "${FIRMWARE%.bin}.seek" 2>/dev/null || echo 256)
    FW_END=$((SEEK * 512 + $(stat -c %s "$FIRMWARE")))
    ((FW_END <= 16 * 1024 * 1024)) || die "firmware ends at $FW_END, inside the first partition"
fi
# shellcheck disable=SC2012 # RPM file names are plain
DTB_RPM=$(ls "$RPMDIR"/noarch/cubie-a7a-dtb-*.noarch.rpm | sort -V | tail -1)
# shellcheck disable=SC2012 # RPM file names are plain
BSP_RPM=$(ls "$RPMDIR"/noarch/cubie-a7a-board-support-*.noarch.rpm | sort -V | tail -1)
# shellcheck disable=SC2012 # RPM file names are plain
# cubie-a7a-fwlog is optional (not built where the boot-chain repository is
# absent, e.g. the sbc-image-maker build guest).
FWLOG_RPM=$(ls "$RPMDIR"/aarch64/cubie-a7a-fwlog-[0-9]*.aarch64.rpm 2>/dev/null | sort -V | tail -1 || :)
BOARD_RPMS=("$DTB_RPM" "$BSP_RPM")
BOARD_UNITS=(cubie-a7a-dtb.service)
if [ -n "$FWLOG_RPM" ]; then
    BOARD_RPMS+=("$FWLOG_RPM")
    BOARD_UNITS+=(a7a-fwlog.service)
fi
# cubie-a7a-npu (A733 NPU, vipcore), cubie-a7a-rk1828 (RK1828 coprocessor
# host driver), cubie-a7a-display (HDMI, sunxidrm) and cubie-a7a-vdec (video
# decoder, a733-cedrus) go in when they were built; cubie-a7a-hat loads them.
# cubie-a7a-aic8800-usb (AIC8800D80 Wi-Fi/Bluetooth driver) goes in the same
# way. Its firmware is Fedora's linux-firmware (aic/aic8800d80;
# fedora/WIFI-FIRMWARE.md), in PACKAGES below and required by the driver
# package; verify-devcard.sh checks it is there and that the image carries no
# user-override firmware.
for extra in cubie-a7a-npu cubie-a7a-rk1828 cubie-a7a-display cubie-a7a-vdec cubie-a7a-hat \
    cubie-a7a-aic8800-usb; do
    # shellcheck disable=SC2012 # RPM file names are plain
    r=$(ls "$RPMDIR"/noarch/"$extra"-[0-9]*.noarch.rpm 2>/dev/null | sort -V | tail -1 || :)
    [ -z "$r" ] || BOARD_RPMS+=("$r")
    [ -z "$r" ] || [ "$extra" != cubie-a7a-hat ] || BOARD_UNITS+=(cubie-a7a-hat.service)
done
# Wi-Fi and Bluetooth userspace, in every image (Wi-Fi out of the box),
# whether or not the driver package was built: NetworkManager
# manages wlan0 only with its Wi-Fi plugin (without it the device shows as
# unmanaged), and the plugin needs a supplicant. Weak dependencies are off
# here, and NetworkManager-wifi requires "wpa_supplicant or iwd", so the
# supplicant is named. Fedora Server installs the same two by default (comps
# group networkmanager-submodules in server-product-environment); bluez and
# iw, not in Fedora Server's default set, are the basic Bluetooth and Wi-Fi
# tools, and bluetooth.service is enabled. No Wi-Fi connection, credential or
# regulatory domain is configured: nmcli device wifi connect <SSID> --ask
# (fedora/WIFI-FIRMWARE.md).
RADIO_PACKAGES=(NetworkManager-wifi wpa_supplicant iw bluez wireless-regdb)
BOARD_UNITS+=(bluetooth.service)
OVERLAY=${OVERLAY:-}
EXTRA_PACKAGES=${EXTRA_PACKAGES:-}
read -ra EXTRA_PKGS <<<"$EXTRA_PACKAGES"
BOOT_MODES=${BOOT_MODES:-}
case "$BOOT_MODES" in '' | protective) ;; *) echo "invalid BOOT_MODES" >&2; exit 2 ;; esac
FIRST_BOOT=${FIRST_BOOT:-}
case "$FIRST_BOOT" in '') ;; maintenance) [ "$BOOT_MODES" = protective ] || {
    echo "FIRST_BOOT=maintenance needs BOOT_MODES=protective" >&2
    exit 2
} ;; *) echo "invalid FIRST_BOOT" >&2; exit 2 ;; esac
GROW_ROOT=${GROW_ROOT:-yes}
case "$GROW_ROOT" in yes | no) ;; *) echo "invalid GROW_ROOT" >&2; exit 2 ;; esac
ROOT_MIN_MIB=${ROOT_MIN_MIB:-0}
[[ $ROOT_MIN_MIB =~ ^[0-9]+$ ]] || { echo "invalid ROOT_MIN_MIB" >&2; exit 2; }
[ -z "$OVERLAY" ] || [ -d "$OVERLAY" ] || { echo "OVERLAY $OVERLAY is not a directory" >&2; exit 2; }
# XZ=no leaves the compression to the caller (the build guest).
XZ=${XZ:-yes}

ROOT_UUID=${ROOT_UUID:-$(cat /proc/sys/kernel/random/uuid)}
ESP_ID=${ESP_ID:-$(od -An -tx4 -N4 /dev/urandom | tr -d ' ' | tr a-f A-F)}
ESP_UUID="${ESP_ID:0:4}-${ESP_ID:4:4}"
PW_HASH=$(openssl passwd -6 "$ROOT_PASSWORD")

PACKAGES=(
    fedora-release-server fedora-repos bash coreutils util-linux systemd systemd-udev
    passwd shadow-utils openssh-server openssh-clients NetworkManager chrony firewalld
    iproute iputils less vim-minimal dnf5 rpm sudo
    selinux-policy-targeted policycoreutils e2fsprogs dosfstools
    dracut "${KERNEL_PACKAGES[@]}" dkms gcc make kmod
    grub2-efi-aa64 grub2-tools shim-aa64 grubby efibootmgr
    linux-firmware realtek-firmware pciutils glibc-langpack-en
    mesa-vulkan-drivers mesa-dri-drivers vulkan-tools
    mesa-libEGL mesa-libGL mesa-libgbm
    git-core gcc-c++ cmake glibc-devel unzip
    zram-generator-defaults
    v4l-utils usbutils python3-pip
    gstreamer1-plugins-base-tools gstreamer1-plugins-good gstreamer1-plugins-bad-free
    gstreamer1-plugin-libav gstreamer1-plugin-dav1d ffmpeg-free dav1d
    opencv opencv-devel libjpeg-turbo-devel
    python3-numpy python3-opencv python3-pillow
    libglvnd-gles python3-absl-py python3-flatbuffers python3-certifi
    python3-matplotlib python3-sounddevice
    "${RADIO_PACKAGES[@]}"
    "${EXTRA_PKGS[@]}"
    "${BOARD_RPMS[@]}"
)
EXCLUDES=(cockpit\* initial-setup\* cloud-init dracut-config-rescue)

# Keep the outputs of earlier builds; each build receives fresh owned paths.
python3 -I - "$TOP" "$W" "$OUT" <<'PATHS'
from pathlib import Path
import sys
base=Path(sys.argv[1]).resolve()/'build'
for value in sys.argv[2:]:
 p=Path(value).resolve();assert p.is_relative_to(base) and not p.exists(), 'fresh owned build/output path required'
PATHS
mkdir -p "$W/root" "$(dirname "$OUT")"
ROOT=$W/root

echo "mkdevcard: root UUID $ROOT_UUID, ESP $ESP_UUID"

# --- stage 1: root filesystem (user namespace) -------------------------------
# Fedora's own repository files: /usr/share/dnf5/repos.d on a Fedora 45 host,
# /etc/yum.repos.d before that.
REPOSDIR=${REPOSDIR:-$([ -f /usr/share/dnf5/repos.d/fedora.repo ] && echo /usr/share/dnf5/repos.d || echo /etc/yum.repos.d)}
export TOP ROOT W ROOT_UUID ESP_UUID PW_HASH RELEASEVER FIRMWARE_DTB_VERSION BUILD_JOBS REPOSDIR OVERLAY BOOT_MODES FIRST_BOOT GROW_ROOT
"$TOP/fedora/run-build-ns.sh" mount bash -s \
    "${PACKAGES[@]}" -- "${EXCLUDES[@]}" <<'STAGE1'
set -euo pipefail
pkgs=(); ex=()
while [ $# -gt 0 ] && [ "$1" != -- ]; do pkgs+=("$1"); shift; done
shift; ex=("$@")

mkdir -p "$ROOT"/{proc,sys,dev,run,tmp,etc/kernel,var/lib/dnf,var/lib/cubie-a7a,boot/efi}
mount -t proc proc "$ROOT/proc"
for n in null zero random urandom full tty; do
    touch "$ROOT/dev/$n"; mount --bind "/dev/$n" "$ROOT/dev/$n"
done
mount -t tmpfs tmpfs "$ROOT/run"
ln -sf /proc/self/fd "$ROOT/dev/fd"

# Before any kernel lands: kernel-install copies this into the BLS entry
# (otherwise it would take the build host's /proc/cmdline). cubie-a7a-
# board-support appends clk_ignore_unused pd_ignore_unused and, for now,
# regulator_ignore_unused (temporary, see its cmdline script). earlycon follows
# /chosen/stdout-path (UART0), so the boot is visible before the A733 CCU
# kmod lets 8250_dw bind ttyS0.
echo "root=UUID=$ROOT_UUID ro rootwait earlycon console=tty0 console=ttyS0,115200" >"$ROOT/etc/kernel/cmdline"
# BOOT_MODES=protective: the default entry's options (the kernel's own entry,
# from /etc/kernel/cmdline) are the protective ones; the kernel-install
# plugin derives the maintenance and full entries from it.
if [ "$BOOT_MODES" = protective ]; then
    # /usr/local/bin, not sbin: sshd's PATH for a command over ssh is
    # /usr/local/bin:/usr/bin (Fedora's merged sbin); only login shells add
    # /usr/local/sbin (/etc/profile).
    install -Dm0755 "$TOP/fedora/bootmodes/cubie-a7a-bootmode" "$ROOT/usr/local/bin/cubie-a7a-bootmode"
    install -Dm0755 "$TOP/fedora/bootmodes/96-cubie-a7a-bootmodes.install" \
        "$ROOT/etc/kernel/install.d/96-cubie-a7a-bootmodes.install"
    install -Dm0644 "$TOP/fedora/bootmodes/cubie-a7a-bootmode-ro.service" \
        "$ROOT/etc/systemd/system/cubie-a7a-bootmode-ro.service"
    install -Dm0644 "$TOP/fedora/bootmodes/cubie-a7a-bootmode-next.service" \
        "$ROOT/etc/systemd/system/cubie-a7a-bootmode-next.service"
    sed -i "s|\$| $("$TOP/fedora/bootmodes/cubie-a7a-bootmode" default-args)|" "$ROOT/etc/kernel/cmdline"
fi
# A machine id for kernel-install's entry names; emptied at the end so the
# board makes its own on first boot.
echo 0123456789abcdef0123456789abcdef >"$ROOT/etc/machine-id"
# What the card's firmware embeds (FIRMWARE_DTB_VERSION): cubie-a7a-dtb puts
# its DTB on the ESP while its stamp is newer.
echo "$FIRMWARE_DTB_VERSION" >"$ROOT/var/lib/cubie-a7a/firmware-dtb-version"
growfs=,x-systemd.growfs
[ "$GROW_ROOT" = yes ] || growfs=
cat >"$ROOT/etc/fstab" <<EOF
UUID=$ROOT_UUID  /          ext4  defaults$growfs  1 1
UUID=$ESP_UUID   /boot/efi  vfat  umask=0077,shortname=winnt  0 2
EOF

mkdir -p "$ROOT/etc/dkms/framework.conf.d"
printf 'parallel_jobs="%s"\n' "$BUILD_JOBS" > "$ROOT/etc/dkms/framework.conf.d/00-image-build.conf"

exclude=$(IFS=,; echo "${ex[*]}")
# rpm reads ~/.rpmmacros: install message catalogs for en_US only (headless
# image), the same on every build host, whatever its own macros say.
mkdir -p "$W/rpm-home"
echo '%_install_langs en_US' >"$W/rpm-home/.rpmmacros"
# persistdir is relative to the installroot (a host path would be recreated
# inside the image).
HOME=$W/rpm-home dnf5 -y install --use-host-config --installroot="$ROOT" --forcearch=aarch64 --releasever="$RELEASEVER" \
    --setopt=reposdir="$REPOSDIR" --setopt=cachedir="$W/../dnf/cache-ns" \
    --setopt=persistdir=/var/lib/dnf --setopt=countme=False \
    --setopt=install_weak_deps=False --setopt=tsflags=nocontexts,nodocs \
    --setopt=keepcache=True --setopt=gpgcheck=True --setopt=localpkg_gpgcheck=False \
    --exclude="$exclude" --repo=fedora --repo=updates "${pkgs[@]}"

# BOOT_MODES=protective: every kernel's maintenance and full entries, with
# the arguments the board package added to all entries after the kernel's
# own kernel-install run.
if [ "$BOOT_MODES" = protective ]; then
    chroot "$ROOT" /usr/local/bin/cubie-a7a-bootmode sync
fi

# --- board modules, initramfs and BLS checks -----------------------------
# Every kernel needs the A733 kmods (DKMS) in extra/ and the boot-critical
# ones in its initramfs; the BLS entries must carry the interim arguments and
# no devicetree line (the DTB comes from the firmware's EFI table).
kernels=$(ls "$ROOT/usr/lib/modules")
[ "$(wc -w <<<"$kernels")" = 1 ] || { echo "mkdevcard: expected one kernel, got: $kernels" >&2; exit 1; }
for k in $kernels; do
    # The board package's own guard: every boot kmod built (and selected
    # by depmod) for this kernel and present in its initramfs.
    chroot "$ROOT" /usr/libexec/cubie-a7a/kernel check "$k" ||
        { echo "mkdevcard: board kmods incomplete for $k" >&2; exit 1; }
    for m in sun60i-a733-serdes sun60i-a733-pcie sun55i-pck600; do
        ls "$ROOT/usr/lib/modules/$k/extra/$m.ko"* >/dev/null 2>&1 ||
            { echo "mkdevcard: staged module $m.ko missing for $k" >&2; exit 1; }
    done
    chroot "$ROOT" lsinitrd "/boot/initramfs-$k.img" >"$W/initramfs-$k.txt"
    for m in sunxi-mmc i2c-mv64xxx; do
        grep -q "/$m\.ko" "$W/initramfs-$k.txt" ||
            { echo "mkdevcard: $m not in initramfs-$k.img" >&2; exit 1; }
    done
    echo "$k" >"$W/kernel.txt"
done
for e in "$ROOT"/boot/loader/entries/*.conf; do
    grep -q '^devicetree' "$e" && { echo "mkdevcard: $e sets devicetree" >&2; exit 1; }
    grep -q '^options .*clk_ignore_unused pd_ignore_unused' "$e" ||
        { echo "mkdevcard: $e lacks the interim kernel arguments" >&2; exit 1; }
    grep -q '^options .* regulator_ignore_unused\b' "$e" ||
        { echo "mkdevcard: $e lacks regulator_ignore_unused (temporary)" >&2; exit 1; }
    cp "$e" "$W/"
done

# Build concurrency is a build-host setting, not a target policy.
rm -f "$ROOT/etc/dkms/framework.conf.d/00-image-build.conf"

# --- policy -------------------------------------------------------------
# Root password (the only human login).
sed -i "s|^root:[^:]*:|root:$PW_HASH:|" "$ROOT/etc/shadow"
mkdir -p "$ROOT/etc/ssh/sshd_config.d"
cat >"$ROOT/etc/ssh/sshd_config.d/00-public-image.conf" <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
AllowUsers root
EOF
rm -f "$ROOT"/etc/ssh/ssh_host_* "$ROOT"/root/.ssh/authorized_keys*
systemctl --root="$ROOT" enable sshd.service NetworkManager.service firewalld.service \
    chronyd.service "${BOARD_UNITS[@]}" >/dev/null

# Grow the root partition to the card on first boot (systemd-repart), then
# the filesystem (x-systemd.growfs in fstab). GROW_ROOT=no: never, on any
# entry (the masks are files in /etc, independent of the kernel command
# line and of kernel updates).
if [ "$GROW_ROOT" = yes ]; then
    mkdir -p "$ROOT/etc/repart.d"
    cat >"$ROOT/etc/repart.d/50-root.conf" <<'EOF'
[Partition]
Type=root
EOF
else
    systemctl --root="$ROOT" mask systemd-repart.service systemd-growfs-root.service >/dev/null
fi

# GRUB: BLS entries from kernel-install; grub.cfg as Fedora writes it, minus
# what grub2-mkconfig would probe on the build host.
mkdir -p "$ROOT/boot/grub2" "$ROOT/boot/efi/EFI/fedora" "$ROOT/etc/default"
# /etc/default/grub as anaconda writes it. Without it a grub2-mkconfig on
# the board still rewrites every BLS entry's options line, to "root=... ro"
# and nothing else (10_linux update_bls_cmdline), dropping the console and
# interim arguments. grubby --update-kernel=ALL keeps GRUB_CMDLINE_LINUX in
# step with later argument changes (cubie-a7a-board-support's cmdline hook).
cat >"$ROOT/etc/default/grub" <<EOF
GRUB_TIMEOUT=3
GRUB_DISTRIBUTOR="\$(sed 's, release .*\$,,g' /etc/system-release)"
GRUB_DEFAULT=saved
GRUB_DISABLE_SUBMENU=true
GRUB_TERMINAL_OUTPUT="console"
GRUB_CMDLINE_LINUX="$(sed -e 's/^root=[^ ]* ro //' "$ROOT/etc/kernel/cmdline")"
GRUB_DISABLE_RECOVERY="true"
GRUB_ENABLE_BLSCFG=true
EOF
cat >"$ROOT/boot/grub2/grub.cfg" <<EOF
# Cubie A7A dev card (fedora/mkdevcard.sh). grub2-mkconfig may replace this.
# /boot lives on the root filesystem, so the BLS entries' /boot/... paths
# are relative to it.
search --no-floppy --fs-uuid --set=root $ROOT_UUID
set timeout=3
load_env
if [ "\${next_entry}" ] ; then
   set default="\${next_entry}"
   set next_entry=
   save_env next_entry
else
   set default="\${saved_entry}"
fi
# Fedora's blscfg starts every entry it builds with load_video (00_header
# defines it); without it each boot prints "can't find command load_video".
function load_video {
  if [ x\$feature_all_video_module = xy ]; then
    insmod all_video
  else
    insmod efi_gop
  fi
}
insmod part_gpt
insmod ext2
insmod blscfg
blscfg
EOF
cat >"$ROOT/boot/efi/EFI/fedora/grub.cfg" <<EOF
search --no-floppy --fs-uuid --set=dev $ROOT_UUID
set prefix=(\$dev)/boot/grub2
export \$prefix
configfile \$prefix/grub.cfg
EOF
chroot "$ROOT" grub2-editenv /boot/grub2/grubenv create
chroot "$ROOT" grub2-editenv /boot/grub2/grubenv set boot_success=0
if [ "$BOOT_MODES" = protective ]; then
    # GRUB boots saved_entry: the newest kernel's protective entry.
    def=$(cd "$ROOT/boot/loader/entries" && ls -- *.conf | grep -v '~' | sed 's/\.conf$//' | sort -V | tail -1)
    chroot "$ROOT" grub2-editenv /boot/grub2/grubenv set "saved_entry=$def"
    # FIRST_BOOT=maintenance: GRUB boots this once and clears it (grub.cfg).
    if [ "$FIRST_BOOT" = maintenance ]; then
        [ -f "$ROOT/boot/loader/entries/$def~maintenance.conf" ]
        chroot "$ROOT" grub2-editenv /boot/grub2/grubenv set "next_entry=$def~maintenance"
    fi
    systemctl --root="$ROOT" enable cubie-a7a-bootmode-ro.service >/dev/null
    # A rw boot clears a next_entry GRUB could not (read-only firmware
    # Block I/O: GRUB's save_env fails), so a one-shot stays one-shot.
    systemctl --root="$ROOT" enable cubie-a7a-bootmode-next.service >/dev/null
    # 20-grub.install runs grub2-mkconfig (replacing this grub.cfg and every
    # entry's options with GRUB_CMDLINE_LINUX) when /etc/kernel/cmdline is
    # older than /etc/default/grub.
    touch -d "@$(($(stat -c %Y "$ROOT/etc/default/grub") + 1))" "$ROOT/etc/kernel/cmdline"
fi

# First boot: new machine id, fresh host keys (sshd-keygen), random seed.
# SELinux labels are written into the ext4 image in stage 2, so no relabel
# (and no extra reboot) is needed.
: >"$ROOT/etc/machine-id"
rm -rf "$ROOT"/var/cache/dnf/* "$ROOT"/var/lib/dnf/repos "$ROOT"/var/log/dnf* \
    "$ROOT"/var/lib/systemd/random-seed "$ROOT"/tmp/*

# OVERLAY=<dir>: files for this card that are in no package (e.g. vendor AI
# runtimes under /opt), copied over the root as root:root; systemd units in
# it are enabled, and the dynamic linker cache is refreshed.
if [ -n "$OVERLAY" ]; then
    cp -a --no-preserve=ownership "$OVERLAY"/. "$ROOT"/
    for u in "$OVERLAY"/usr/lib/systemd/system/*.service; do
        [ -e "$u" ] || continue
        systemctl --root="$ROOT" enable "$(basename "$u")" >/dev/null
    done
    chroot "$ROOT" ldconfig
    (cd "$OVERLAY" && find . -type f | LC_ALL=C sort | xargs sha256sum) >"$W/overlay.sha256"
fi

# Firmware audit, a report only (never fails the build, removes nothing):
# which firmware files in the root and initramfs are closed blobs, Realtek's
# named separately; fedora/image-firmware.allow lists the reviewed open
# ones. Open replacements take a blob's place once they reach parity.
# shellcheck disable=SC2046 # one --list per kernel
python3 -I "$TOP/fedora/image-firmware.py" audit --root "$ROOT" --quiet \
    $(for k in $(cat "$W/kernel.txt"); do echo --list "$W/initramfs-$k.txt"; done) \
    --allow "$TOP/fedora/image-firmware.allow" --json "$W/firmware-audit.json" \
    >"$W/firmware-audit.txt" 2>&1 || echo "mkdevcard: firmware audit did not run (report only)" >&2

chroot "$ROOT" rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH} %{RSAHEADER:pgpsig}\n' \
    | sort >"$W/packages.txt"
umount -R "$ROOT/run" "$ROOT/proc" || :
for n in null zero random urandom full tty; do umount "$ROOT/dev/$n"; rm -f "$ROOT/dev/$n"; done
rm -f "$ROOT/dev/fd"
# Scriptlets in the chroot may have written to device paths that were not
# bind-mounted (/dev/kmsg): devtmpfs covers /dev on the board, so no regular
# file belongs here.
find "$ROOT/dev" -mindepth 1 -type f -delete
find "$ROOT/dev" -mindepth 1 -empty -type d -delete
STAGE1

# --- stage 2: filesystem images (same user namespace mapping) ----------------
ROOT_KIB=$(du -sk --apparent-size "$ROOT" | cut -f1)
ROOT_MIB=$(((ROOT_KIB * 13 / 10) / 1024 + 512))
((ROOT_MIB >= ROOT_MIN_MIB)) || ROOT_MIB=$ROOT_MIN_MIB
export ROOT_MIB ESP_MIB ESP_ID TOP
"$TOP/fedora/run-build-ns.sh" user bash -s <<'STAGE2'
set -euo pipefail
esp=$W/esp.img; rootimg=$W/root.img
rm -f "$esp" "$rootimg"
mkfs.fat -F 32 -n EFI -i "$ESP_ID" -C "$esp" $((ESP_MIB * 1024)) >/dev/null
# FAT keeps no owners or modes; copy the tree, then leave /boot/efi empty
# as the mount point.
mcopy -s -p -m -i "$esp" "$ROOT"/boot/efi/* ::
find "$ROOT/boot/efi" -mindepth 1 -delete
truncate -s "${ROOT_MIB}M" "$rootimg"
mkfs.ext4 -q -L "Fedora$RELEASEVER-root" -U "$ROOT_UUID" -E root_owner=0:0 -d "$ROOT" "$rootimg"
# SELinux labels, written into the image (they cannot be set here): an
# unlabeled root freezes systemd when booted enforcing, before any relabel.
python3 -I "$TOP/fedora/selinux-label.py" "$ROOT" "$rootimg" "$W/selinux"
python3 -I "$TOP/fedora/selinux-label.py" --verify "$ROOT" "$rootimg" "$W/selinux-verify"
STAGE2

# --- stage 3: disk image ------------------------------------------------------
ESP_START=$((16 * 2048))
ESP_SECTORS=$((ESP_MIB * 2048))
ROOT_START=$((ESP_START + ESP_SECTORS))
ROOT_SECTORS=$(($(stat -c %s "$W/root.img") / 512))
TOTAL=$(((ROOT_START + ROOT_SECTORS + 2048) * 512))
rm -f "$OUT" "$OUT.xz"
truncate -s "$TOTAL" "$OUT"
sfdisk --quiet --no-reread --no-tell-kernel "$OUT" <<EOF
label: gpt
first-lba: 34
start=$ESP_START, size=$ESP_SECTORS, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI"
start=$ROOT_START, size=$ROOT_SECTORS, type=B921B045-1DF0-41C3-AF44-4C6F280D3FAE, uuid=$ROOT_UUID, name="root"
EOF
dd if="$W/esp.img" of="$OUT" bs=1M seek=16 conv=notrunc,sparse status=none
dd if="$W/root.img" of="$OUT" bs=512 seek=$ROOT_START conv=notrunc,sparse status=none
if [ -n "$FIRMWARE" ]; then
    dd if="$FIRMWARE" of="$OUT" bs=512 seek="$SEEK" conv=notrunc status=none
    cmp -n "$(stat -c %s "$FIRMWARE")" -i 0:$((SEEK * 512)) "$FIRMWARE" "$OUT" || die "firmware readback"
else
    # The firmware gap (LBA 256-32767) must be zero.
    cmp -n $((ESP_START * 512 - 256 * 512)) -i $((256 * 512)):0 "$OUT" /dev/zero || die "firmware gap not zero"
fi

# Read back what was written.
cmp -n $((ESP_SECTORS * 512)) -i 0:$((ESP_START * 512)) "$W/esp.img" "$OUT" || die "ESP readback"
cmp -n $((ROOT_SECTORS * 512)) -i 0:$((ROOT_START * 512)) "$W/root.img" "$OUT" || die "root readback"
sfdisk --verify "$OUT" >/dev/null || die "GPT verify"

if [ "$XZ" = yes ]; then
    xz -T"${XZ_THREADS:-2}" -6 -k "$OUT"
    (cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")" "$(basename "$OUT").xz") >"$OUT.sha256"
else
    (cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")") >"$OUT.sha256"
fi
cat >"$W/manifest.txt" <<EOF
image        $OUT
root UUID    $ROOT_UUID
ESP UUID     $ESP_UUID
DTB          stamp $DTB_VERSION; firmware stamp $FIRMWARE_DTB_VERSION ($(if [ "$FIRMWARE_DTB_VERSION" -lt "$DTB_VERSION" ]; then echo "ESP copy in use"; else echo "firmware DTB in use"; fi))
firmware     $(if [ -n "$FIRMWARE" ]; then echo "$FIRMWARE sha256 $(sha256sum <"$FIRMWARE" | cut -d' ' -f1) at sector $SEEK"; else echo "none (LBA 256-32767 zero, for firmware.bin at LBA 256)"; fi)
cubie-a7a    $(for r in "${BOARD_RPMS[@]}"; do basename "$r"; done | tr '\n' ' ')
packages     $W/packages.txt ($(wc -l <"$W/packages.txt") RPMs)
kernel       $(grep -o '^kernel-core-[^ ]*' "$W/packages.txt" | tr '\n' ' ')
firmware fs  $(grep '^image-firmware: ' "$W/firmware-audit.txt" | tail -1 | sed 's/^image-firmware: //') (audit, report only: $W/firmware-audit.txt)
extra pkgs   ${EXTRA_PACKAGES:-none}
boot modes   ${BOOT_MODES:-single entry per kernel}${FIRST_BOOT:+; first boot: $FIRST_BOOT (one-shot)}
root growth  $([ "$GROW_ROOT" = yes ] && echo "on first boot (repart + growfs)" || echo "never (repart and growfs masked)"); root $ROOT_MIB MiB
EOF
cat "$OUT.sha256" "$W/manifest.txt"
