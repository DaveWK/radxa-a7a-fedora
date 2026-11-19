# radxa-a7a-fedora

Fedora packaging and image scripts for the **Radxa Cubie A7A** (Allwinner
A733) running the oreboot + EDK2 boot chain. The board runs the **stock
Fedora kernel**. The board support (device tree, out-of-tree kernel modules
built with DKMS, dracut and kernel-argument policy) ships as RPMs.

This repository is the `fedora/` submodule of
[radxa-a7a-workspace](https://github.com/DaveWK/radxa-a7a-workspace). That
workspace builds the firmware and runs these scripts in a container
(`make fedora-image`). You can also use them on their own on a Fedora 45 host.

**No images are hosted or distributed.** You build your own. Never commit or
upload a built image.

## Packages

| Package | What |
|---|---|
| `cubie-a7a-dtb` | the Cubie A7A device tree (`fedora/dts`); installs it on the ESP when the firmware's built-in DTB is older |
| `cubie-a7a-board-support` | DKMS modules for the A733 (`fedora/kmods/cubie-a7a-kmods`: CCU, pinctrl, PMIC, PCK-600 power domains, SerDes/PCIe/USB PHYs, thermal, GMAC glue, ...), dracut and kernel-argument policy |
| `cubie-a7a-npu` | DKMS VeriSilicon VIP NPU driver (`kmods/a733-vipcore`) |
| `cubie-a7a-rk1828` | DKMS host driver for an RK1828 coprocessor on PCIe (`kmods/rk1828-pcie-rkep`) |
| `cubie-a7a-display` | DKMS HDMI display driver (`kmods/a733-sunxi-drm`) |
| `cubie-a7a-vdec` | DKMS video decoder (`kmods/a733-cedrus`) |
| `cubie-a7a-hat` | service that loads the late modules one at a time, with a hang guard |
| `cubie-a7a-aic8800-usb` | AIC8800D80 Wi-Fi/Bluetooth: packaging only (see below) |
| `cubie-a7a-fwlog` | firmware log reader (optional, needs a boot-chain tree with `tools/a7a-fwlog`: `FWREPO=<tree>`) |

Each kernel module directory keeps its upstream licence headers and a
`PROVENANCE` file that names its source and commit.

## Build

Requirements on a Fedora 45 host: `rpm-build`, `dtc`, `cpp`, `make`,
`systemd-rpm-macros`, `dnf5`, `util-linux` (`unshare`), `e2fsprogs`,
`dosfstools`, `mtools`, `openssl`, `xz`, `python3-libselinux`, and
`qemu-user-static-aarch64` with its binfmt handler (the `F` flag) on x86_64
hosts.

    fedora/build-rpms.sh build/fedora/rpmbuild          # SRPMs + noarch RPMs
    WORK=build/fedora/image OUT=build/image/a7a-fedora45.img \
      fedora/mkdevcard.sh none build/fedora/rpmbuild/RPMS  # image, no firmware

`mkdevcard.sh FIRMWARE_BIN RPMS_DIR` builds the image rootless. It installs
Fedora packages with dnf5 into an aarch64 installroot inside a user
namespace, and the package scriptlets (DKMS, initramfs) run under
qemu-aarch64. With `none` as FIRMWARE_BIN, sectors 256-32767 stay zero for
the boot firmware (`firmware.bin`, written at LBA 256). Image policy: root
is the only login, the password is `Fedora123` (`ROOT_PASSWORD`), sshd and
DHCP are on, and the image holds no SSH keys of anyone (host keys are
generated on first boot).

## Tests

    python3 fedora/tests/pinctrl-bank-supply.py

A host model (needs `gcc`) of the pin controller module's per-bank supply
bookkeeping under concurrent pin requests. It is a model of the
interleavings, not a board test.

## Not in this repository

- **AIC8800 Wi-Fi/Bluetooth driver source.** Most of the upstream driver
  files (radxa-pkg/aic8800) carry no licence grant, so they are not
  redistributed here. `build-rpms.sh` skips `cubie-a7a-aic8800-usb` unless
  `AIC8800_SRC` names a local tree of the driver. The firmware comes from
  Fedora's `linux-firmware` (see `fedora/WIFI-FIRMWARE.md`).
- **GPU firmware.** No PowerVR firmware, original or modified, is part of
  this repository. An image carries only the GPU firmware files that
  Fedora's `linux-firmware` packages install.
- **Closed binaries.** None. Firmware the board needs comes from Fedora's
  packages at image build time.

## Licence

Scripts, specs and our own modules are GPL-2.0-only (`LICENSE`) unless a file
says otherwise. The device tree carries its SPDX tags (`fedora/dts/LICENSES`),
and the kernel modules carry their upstream licences.
