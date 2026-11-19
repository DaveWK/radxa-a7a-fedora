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
`systemd-rpm-macros`, `createrepo_c`, `dnf5`, `util-linux` (`unshare`), `e2fsprogs`,
`dosfstools`, `mtools`, `openssl`, `xz`, `python3-libselinux`, and
`qemu-user-static-aarch64` with its binfmt handler (the `F` flag) on x86_64
hosts.

    run=$(fedora/build-rpms.sh build/fedora/rpmbuild)   # SRPMs + noarch RPMs
    WORK=build/fedora/image OUT=build/image/a7a-fedora45.img \
      fedora/mkdevcard.sh none "$run"                   # image, no firmware

Each build creates a new `runs/<id>` directory. With `FWREPO` set, run
`fedora/build-aarch64-rpms.sh "$run"` before making the image. The final
stage records `rpm-snapshot.json`, seals the RPM outputs and creates the
local repository from verified copies. Image builds pass only the checked
RPM paths to DNF, without enabling that repository. After the transaction,
the installed board RPMs must match the retained snapshot.

`mkdevcard.sh FIRMWARE_BIN RUN_DIR` builds the image rootless. It installs
Fedora packages with dnf5 into an aarch64 installroot inside a user
namespace, and the package scriptlets (DKMS, initramfs) run under
qemu-aarch64. With `none` as FIRMWARE_BIN, sectors 256-32767 stay zero for
the boot firmware (`firmware.bin`, written at LBA 256). Image policy: root
is the only login, the password is `Fedora123` (`ROOT_PASSWORD`), sshd and
DHCP are on, and the image holds no SSH keys of anyone (host keys are
generated on first boot).

### Dev card pre-boot checks

`fedora/mkdevcard.sh` records the requested profile in the build manifest. The
staged policy below runs after the overlay for `BOOT_MODES=protective`,
`GROW_ROOT=no`, with no `FIRST_BOOT` selection. These checks read plain files
and compare symlink target strings, not effective systemd state.

| Check | Proves | Does not prove |
| --- | --- | --- |
| BLS triples, default, kernel/initrd paths and options | The final entries match those staged by the build for `kernel.txt`, and point to its kernel and digest-bound initramfs. The default has the expected root UUID, `ro`, and journal no-replay (`rootflags=noload` in `fedora/bootmodes/cubie-a7a-bootmode`). | Which entry, kernel or initramfs actually booted. |
| First boot | The build's `grub.cfg` uses `saved_entry` when no `next_entry` is present; the entire generated grubenv matches, and the protective overlay cannot modify the named boot-control inputs. | Effective systemd units or runtime boot actions. |
| Growth | `repart.d` entries are listed and contain no `.conf` files; fstab matches the generated mount table byte for byte; the three growth mask targets are exactly `/dev/null`. | Runtime growth or absence of disk writes. |
| Identity | The machine ID remains empty, as staged by the build; there is no random seed or SSH host key. | The identity generated on boot. |
| Accounts | The staged root password matches the build-selected password, no other account has an unlocked password, and there is exactly one UID 0 account (`root`) and no other human UID. No password hash is printed. | Live PAM, NSS or SSH login behaviour. |
| Wi-Fi | No persisted NetworkManager connection in `/etc/NetworkManager/system-connections/` and no staged `wpa_supplicant` network block in the standard `/etc` configuration locations. | Live networking or hardware isolation. |

Integrity checks are independent of that profile:

| Check | Proves | Does not prove |
| --- | --- | --- |
| AIC firmware signer and digests | The staged AIC firmware matches Fedora-signed RPM records before the final dracut run and again on the final post-overlay root. | Which firmware actually loaded on the board. |
| Root module selection | The staged root's module lookup selects the required board overrides from `extra/` and the expected newer kernel pinctrl setting is built in. | Which modules the initramfs contains or the boot selects. |
| Overlay veto | The overlay cannot write `/boot/initramfs-*` or the firmware directory (including its `/lib` alias). | What is inside the initramfs. |
| Initramfs SHA-256 | The final staged initramfs bytes match those captured immediately after building the shipping images with dracut. | Archive content, device nodes or the actual boot handoff. |
| `zstd -t --check` | Stream integrity only. | Newc validity, content, or which initramfs boots. |

Effective systemd state and initramfs content belong to on-board acceptance,
not an offline simulation.

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
