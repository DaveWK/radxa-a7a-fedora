# Cubie A7A Wi-Fi and Bluetooth firmware (Fedora's linux-firmware)

The Cubie A7A's Wi-Fi 6 / Bluetooth 5 module (FCU760K, an AICSemi
AIC8800D80 on USB behind the FE1.1S hub, port 4) runs vendor firmware that
the host loads into it at every power-up.

## Fedora's firmware

> "Use Fedora's firmware."

Fedora 45's `linux-firmware` (20261019) ships AICSemi AIC8800D80 firmware
under `aic/aic8800d80/`, redistributable under its `LICENSE.aic`. This
replaces the user opt-in of 2026-11-11:

- The image installs `cubie-a7a-aic8800-usb` together with `linux-firmware`,
  and the driver package requires `linux-firmware`.
- The driver (`aic_load_fw`) loads each file from the user override
  directory `/lib/firmware/aic8800_fw/USB/aic8800D80/` if it is there, and
  otherwise from linux-firmware's `/lib/firmware/aic/aic8800d80/`.
- `cubie-a7a-wifi-firmware` stays, as an **optional** override: it installs
  a USB firmware set you obtained yourself (checked against the manifest
  below) into the override directory. Nothing requires it.
- `mkdevcard.sh` checks staged AIC file provenance against Fedora-signed RPM
  records and file digests before dracut and again after the overlay.
  `verify-devcard.sh` then checks the sealed image bytes, not Wi-Fi policy.

None of our packages or repositories carries firmware, and nothing here
downloads it.

## Open issue: linux-firmware's Wi-Fi image is the SDIO build

Checked 2026-11-12 against `linux-firmware-20261019-1.fc45`:

| linux-firmware file | SHA256 (decompressed) | Bytes | Same as the USB set? |
|---|---|---:|---|
| `aic/aic8800d80/fmacfw_8800d80_u02.bin.xz` | `ea91583a4b0004d8e8e7fb304b49a85df9468ddca42fb52841e37c7bb825de42` | 332536 | no: an **SDIO** build (its strings name `sdio_func1_h2d_*` queues), for the upstream SDIO driver RFC |
| `aic/aic8800d80/fw_patch_8800d80_u02.bin.xz` | `be3d13e5cf1adb18a57dc829da34f6bf9450ace5c92b8d9baa39f55ba310318f` | 28468 | no (a different Bluetooth patch build, Sep 23 2024, git fe00fa3) |
| `aic/aic8800d80/fw_patch_table_8800d80_u02.bin.xz` | `6fb9284b3d1d6ba88e1495adce7c2da02c0cc8cd0df83a6ca23c2f8a5f0d8a45` | 23272 | no (same `AICBT_PT_TAG` format; names no extension patch) |
| `aic/aic8800d80/fw_adid_8800d80_u02.bin.xz` | `a526cbd02fcdc495f049f3ad6b5933cb08cd984b16790c716a060d582fee1a56` | 1708 | yes, byte-identical |

There is no `fw_patch_8800d80_u02_ext0.bin`; linux-firmware's patch table
does not ask for one. The USB chip cannot run an SDIO Wi-Fi image, and
`aic_load_fw` loads Bluetooth and Wi-Fi in one sequence, so `aic_load_fw`
**refuses** an `fmacfw` from linux-firmware that is an SDIO build (one
error naming the override directory and this file) instead of starting it;
the chip stays unbound in ROM mode, as without firmware.
`cubie-a7a-wifi-firmware status` reports this on the running system.
Wi-Fi/Bluetooth therefore work out of the box only once linux-firmware
carries a USB build of the D80 Wi-Fi image (or the user installs the
optional override). Not tested on hardware: whether linux-firmware's
Bluetooth patch set works over USB with a USB Wi-Fi image.

## Licence of the override files: unclear

The only public source of the USB files is Radxa's `radxa-pkg/aic8800`
repository and its `aic8800-firmware` Debian package. Its `debian/copyright`
labels everything `GPL-3+` (`Files: *`) or `GPL-2` (`src/*`), but:

- no source code exists for the firmware binaries, so a GPL label cannot be
  complied with as written, and is not evidence of a licence from AICSemi;
- AICSemi publishes no licence or redistribution terms for these USB files
  (linux-firmware's `LICENSE.aic` covers only the files it carries).

We therefore do not redistribute them, and you install them at your own
discretion. What this package ships is the host driver source, GPL-2.0 by
its per-file notices and the upstream metadata.

## The override files

Manifest: `/usr/share/cubie-a7a/aic8800-d80-usb.manifest`
(source: `fedora/rpm/cubie-a7a-aic8800-usb/aic8800-d80-usb.manifest`).
Reference copy: Radxa `aic8800-firmware` **5.0+git20260123.5f7be68d-9**
(`aic8800-firmware_5.0+git20260123.5f7be68d-9_all.deb`, SHA256
`1dbc31172830232bfdc53d6416fc73d9a2c80fe862545c51a1398f671b7a55ca`), from
the release page
<https://github.com/radxa-pkg/aic8800/releases/tag/5.0%2Bgit20260123.5f7be68d-9>,
directory `lib/firmware/aic8800_fw/USB/aic8800D80/` in the package. Release
-9 is built from radxa-pkg/aic8800 commit `d13d07963cd1`, the driver this
package pins; release -11 has byte-identical USB D80 files.

| File | Bytes | SHA256 | Role |
|---|---:|---|---|
| `fw_patch_table_8800d80_u02.bin` | 1384 | `9decb77435b7e9713e33e32da483d683b7329ed93b672b2d1b134031d7da5f67` | required (Bluetooth patch table) |
| `fw_adid_8800d80_u02.bin` | 1708 | `a526cbd02fcdc495f049f3ad6b5933cb08cd984b16790c716a060d582fee1a56` | required (Bluetooth) |
| `fw_patch_8800d80_u02.bin` | 32700 | `f0e2f5bbc17bc327ca7f1574ff55370dfd863d931514347bb4abc18a74f6218f` | required (Bluetooth) |
| `fw_patch_8800d80_u02_ext0.bin` | 16136 | `ca738f5ea5aca6021c4f48b60ff35e835dfdaf072a8490e3ba8ba0a42440e3e5` | required (Bluetooth) |
| `fmacfw_8800d80_u02.bin` | 358072 | `23f2bed2ac0e8f7bda8f36df7defd30d9b928c97867f6f0f01f28d89dd78d670` | required (Wi-Fi) |
| `fmacfw_8800d80_h_u02.bin` | 358640 | `c5c8c774dfae93aed71f8da7489e35159192135e4929591ea8a945b76deba6bd` | optional ("H" chip variants) |
| `aic_userconfig_8800d80.txt` | 2724 | `56c039d10af63c888b18890f508968a143f034de279fd2c4ec7ee65133e3dbdb` | optional (TX power/crystal settings) |
| `lmacfw_rf_8800d80_u02.bin` | 283846 | `5abae35d6718d031f93ae8287d008b6b9ee9504c47dd212239907e30c006bba8` | optional (RF test mode) |
| `fw_ble_scan_ad_filter.bin` | 371284 | `9cc0dde69252c2f9ed281195a638878991cc54d88c86bbbbed89d64ab9fc7317` | optional (BLE scan wake mode) |

"Required" is what the A7A's chip (revision U02/U03; the vendor image loads
exactly these five) needs at every power-up. The other files in the package
(`*_u04`, `*_ipc`, `calibmode`, `aic_powerlimit`) are not used by this driver
build and are not installed.

## Commands

```sh
# What is there: chip state (a69c:8d80 = ROM, no firmware; 8d81 = running),
# drivers, each override file present/missing and its SHA256 match, the
# linux-firmware files the driver uses for the rest (an SDIO Wi-Fi build is
# flagged), wlan/hci.
cubie-a7a-wifi-firmware status

# Optional override:

# Install from a .deb or a directory you obtained yourself (as root).
# Every file found must match the manifest, and the five required ones must
# be there, or nothing is installed. Never downloads.
sudo cubie-a7a-wifi-firmware install ./aic8800-firmware_5.0+git20260123.5f7be68d-9_all.deb
sudo cubie-a7a-wifi-firmware install /path/to/aic8800D80/

# Remove exactly the manifest files (other files stay). The chip keeps
# running loaded firmware until it loses power: reboot afterwards.
sudo cubie-a7a-wifi-firmware remove
```

`install` writes `/lib/firmware/aic8800_fw/USB/aic8800D80/` (plain files),
restores SELinux labels and probes a waiting chip again, so Wi-Fi usually
appears without a reboot. The driver also accepts `<name>.xz` or
`<name>.zst` there, and honours `firmware_class.path=`.

## What the driver does

- `aic_load_fw` binds the chip in ROM mode (`a69c:8d80`), loads the files
  through the kernel firmware loader (`request_firmware_direct`, no
  user-space fallback, no timeout), each from the override directory or
  else from linux-firmware's `aic/aic8800d80/`, and starts them; the chip
  re-enumerates as `a69c:8d81`, where `aic8800_fdrv` (Wi-Fi, `wlan0`) and
  the mainline `btusb` (Bluetooth, `hci0`) bind. A file taken from
  linux-firmware is logged (`... from linux-firmware`).
- A file in neither place, or an SDIO Wi-Fi image from linux-firmware: one
  error naming the paths and this document, probe fails with that error,
  the chip stays unbound in ROM mode. No retry loop; installing the files
  (or replugging/rebooting) probes again. `aic_fw_path=` (a directory
  relative to the firmware path) turns the linux-firmware fallback off.
- Bluetooth: the mainline `btusb` (since cubie-a7a-aic8800-usb 0.4). The
  Bluetooth patch set (ADID, patch, ext patch, patch table) is uploaded by
  `aic_load_fw` with the Wi-Fi image, before the chip re-enumerates; after
  that the D80 exposes a standard Bluetooth interface (class e0/01/01),
  which `btusb` binds (`hci0` came up on the board this way, 2026-11-12).
  The vendor `aic_btusb` is no longer built or shipped;
  `/usr/lib/modprobe.d/cubie-a7a-aic8800.conf` blacklists it
  (`blacklist` plus `install aic_btusb /bin/false`) so a module left by an
  older package cannot bind.
- MAC address: the chip's eFuse normally holds it (the vendor image's
  capture shows `wlan0` at `9c:04:b6:84:2e:7b`, not the driver's fallback). If the eFuse is empty the driver would invent
  `88:00:33:77:xx:xx`, different each load; the udev rule replaces that
  with a locally administered address derived from `/etc/machine-id`,
  stable for this installation.

## Radio policy defaults

- NetworkManager manages `wlan0` (`nmcli device wifi list`,
  `nmcli device wifi connect <SSID> --ask`); Bluetooth is BlueZ
  (`bluetoothctl`). Every image installs `NetworkManager-wifi`,
  `wpa_supplicant`, `iw`, `bluez` and `wireless-regdb` and enables
  `bluetooth.service` (`mkdevcard.sh`; runtime state is not checked by the
  packed-image verifier).
  Without the Wi-Fi plugin NetworkManager lists `wlan0` as unmanaged even
  with the driver and firmware working; `NetworkManager-wifi` needs
  `wpa_supplicant` or `iwd`, and the image names `wpa_supplicant` (Fedora
  Server's default too). No connection or credential is preconfigured. On a
  card built before this: `dnf install NetworkManager-wifi wpa_supplicant
  iw bluez`, `systemctl enable --now bluetooth`, `systemctl restart
  NetworkManager`.
- rfkill: nothing is soft-blocked by default; `systemd-rfkill` restores the
  last state (`rfkill list`, `nmcli radio wifi on|off`).
- Regulatory domain: the driver follows cfg80211 (its permissive
  `custregd` mode stays off) and starts in the world domain `00`, which
  limits channels and power. NetworkManager does not set a country. Set
  yours with `iw reg set XX` (until reboot) or persistently with
  `options cfg80211 ieee80211_regdom=XX` in
  `/etc/modprobe.d/cfg80211-country.conf`.
