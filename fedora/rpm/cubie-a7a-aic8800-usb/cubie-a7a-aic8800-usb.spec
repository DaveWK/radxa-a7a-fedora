Name:           cubie-a7a-aic8800-usb
Version:        0.4
Release:        1%{?dist}
Summary:        AIC8800D80 USB Wi-Fi driver and firmware loader for the Cubie A7A (firmware from linux-firmware)
License:        GPL-2.0-only
BuildArch:      noarch
# DKMS version = package version-release: every build is a new DKMS version,
# so an update never keeps the module built from older sources.
%global dkms_name %{name}
%global dkms_ver %{version}-%{release}
Source0:        aic8800-usb-%{version}.tar.gz
Source1:        cubie-a7a-wifi-firmware
Source2:        aic8800-d80-usb.manifest
Source3:        WIFI-FIRMWARE.md
Source4:        60-cubie-a7a-aic8800.rules
Source5:        cubie-a7a-aic8800-modprobe.conf
Source6:        cubie-a7a-aic-udev
Source9:        cubie-a7a-dkms
BuildRequires:  systemd-rpm-macros
Requires:       dkms gcc make kmod
# DKMS builds the modules for every installed Fedora kernel; kernel-devel is
# installonly and follows the kernel (as for cubie-a7a-board-support).
Requires:       kernel-devel
# cubie-a7a-wifi-firmware: ar (a .deb), tar, xz/zstd (compressed files);
# the udev helper: ip, logger.
Requires:       binutils tar xz zstd coreutils iproute util-linux
# Fedora's firmware: the AIC8800D80 firmware comes from
# linux-firmware (aic/aic8800d80, LICENSE.aic); nothing here ships or downloads
# firmware. A user-installed USB set (cubie-a7a-wifi-firmware) is an optional
# override that takes precedence (WIFI-FIRMWARE.md).
Requires:       linux-firmware
# NetworkManager manages wlan0 only with its Wi-Fi plugin, which needs
# wpa_supplicant or iwd; wpa_supplicant is named (Fedora Server's default).
Recommends:     NetworkManager-wifi wpa_supplicant bluez iw wireless-regdb

%description
The AICSemi AIC8800 USB driver (Radxa's radxa-pkg/aic8800, pinned) for the
AIC8800D80 Wi-Fi 6 / Bluetooth 5 module of the Radxa Cubie A7A, built by DKMS
against Fedora's own kernel: aic_load_fw (loads the Wi-Fi and Bluetooth
firmware into the chip) and aic8800_fdrv (Wi-Fi, cfg80211). Public fixes from
the radxa-pkg/aic8800 and shenmintao/aic8800d80 forks are applied (scan
use-after-free, command timeout, bounds checks on firmware-supplied data,
unplug teardown).

No firmware is included: the driver loads Fedora's linux-firmware files
(/lib/firmware/aic/aic8800d80/), which this package requires. Files a user
installs with cubie-a7a-wifi-firmware (checked against the pinned manifest,
names and SHA256) under /lib/firmware/aic8800_fw/USB/aic8800D80/ take
precedence, file by file; that override is optional. It never downloads
anything. linux-firmware 20261019's Wi-Fi image is the SDIO build, which the
loader refuses for this USB chip, so until a USB build is there the chip stays
unbound and the log says why. Read /usr/share/cubie-a7a/WIFI-FIRMWARE.md.

Bluetooth runs on the kernel's own btusb, which binds the D80's standard
Bluetooth interface once the firmware runs; the vendor aic_btusb is not built
and is blacklisted (modprobe.d). A chip without an eFuse MAC address gets a
stable locally administered one (udev).

%prep
%setup -q -n aic8800-usb-%{version}

%build

%install
mkdir -p %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}
cp -a . %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/
sed -i 's/@VERSION@/%{dkms_ver}/' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
grep -qx 'PACKAGE_VERSION="%{dkms_ver}"' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
install -Dpm0755 %{SOURCE9} %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
sed -i -e 's/@MODULE@/%{dkms_name}/g' -e 's/@VERSION@/%{dkms_ver}/g' \
    %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
install -Dpm0755 %{SOURCE1} %{buildroot}%{_bindir}/cubie-a7a-wifi-firmware
install -Dpm0644 %{SOURCE2} %{buildroot}%{_datadir}/cubie-a7a/aic8800-d80-usb.manifest
# Not %%doc: images are built with tsflags=nodocs, and the helper points here.
install -Dpm0644 %{SOURCE3} %{buildroot}%{_datadir}/cubie-a7a/WIFI-FIRMWARE.md
install -Dpm0644 %{SOURCE4} %{buildroot}%{_udevrulesdir}/60-cubie-a7a-aic8800.rules
install -Dpm0644 %{SOURCE5} %{buildroot}%{_prefix}/lib/modprobe.d/cubie-a7a-aic8800.conf
install -Dpm0755 %{SOURCE6} %{buildroot}%{_libexecdir}/cubie-a7a/aic-udev

%post
%{_libexecdir}/cubie-a7a/dkms-%{dkms_name} add || :
%udev_rules_update

%posttrans
# Every installed kernel, not the running one: images are assembled in a
# chroot. Later kernels are built by dkms's own kernel-install hook. On an
# update this builds the new version, then installs it in place of the old
# one (which stays where the build fails) and drops the old one from DKMS.
%{_libexecdir}/cubie-a7a/dkms-%{dkms_name} sync || :

%preun
# Erase: out of every kernel. Update: out of DKMS unless installed; installed
# modules stay until the new package has built its own (%%posttrans).
%{_libexecdir}/cubie-a7a/dkms-%{dkms_name} preun $1 %{dkms_ver} || :

%postun
%udev_rules_update

%files
%license COPYING
%{_usrsrc}/%{dkms_name}-%{dkms_ver}/
%{_bindir}/cubie-a7a-wifi-firmware
%dir %{_datadir}/cubie-a7a
%{_datadir}/cubie-a7a/aic8800-d80-usb.manifest
%{_datadir}/cubie-a7a/WIFI-FIRMWARE.md
%{_udevrulesdir}/60-cubie-a7a-aic8800.rules
%{_prefix}/lib/modprobe.d/cubie-a7a-aic8800.conf
%dir %{_libexecdir}/cubie-a7a
%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
%{_libexecdir}/cubie-a7a/aic-udev

%changelog
* Thu Nov 12 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.4-1
- Bluetooth on the mainline btusb: aic_btusb is no longer built or shipped
  (aic_load_fw uploads the Bluetooth patch set itself); modprobe.d
  blacklists it (blacklist + install /bin/false) instead of the softdep,
  and the udev hand-over to aic_btusb is gone
- Scan request use-after-free fixed (shenmintao/aic8800d80 da47f20;
  radxa-pkg/aic8800 PR #110)
- A timed-out command is taken off the queue, so a late confirmation no
  longer writes into a returned stack frame (radxa-pkg/aic8800 issue #84,
  PR #113; the unlink part, without its device reset)
- Bounds checks on firmware-supplied data from radxa-pkg/aic8800 PR #114,
  its 9 patches with USB parts: confirmation copy length, message ids and
  vif/sta/chan indices, RX lengths and TIDs, RX aggregate lengths, BT
  patch-table parsers and ext patch count, CAP_NET_ADMIN on private
  commands, no BUG_ON on an unknown frequency, command allocation failure
- Unplug teardown lifetime (shenmintao/aic8800d80 PR #106)

* Thu Nov 12 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.3-2
- Recommends wpa_supplicant next to NetworkManager-wifi (it needs
  wpa_supplicant or iwd; without the Wi-Fi plugin wlan0 is unmanaged)
- WIFI-FIRMWARE.md: every image carries the Wi-Fi/Bluetooth userspace and
  enables bluetooth.service; how to add it on an older card

* Thu Nov 12 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.3-1
- Fedora's firmware, replacing the user opt-in: Requires
  linux-firmware; aic_load_fw falls back file by file from the user override
  (aic8800_fw/USB/aic8800D80) to linux-firmware's aic/aic8800d80 for the D80
- An fmacfw from linux-firmware that is an SDIO build (20261019's is) is
  refused with one error naming the override, instead of being started on
  the USB chip
- cubie-a7a-wifi-firmware stays as the optional override; status also shows
  the linux-firmware files the driver will use and flags an SDIO build

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.2-2
- DKMS version is the package's version-release (was the version alone), so
  an update builds and installs the new sources instead of keeping the old
  build ("already installed, skip")
- Scriptlets through /usr/libexec/cubie-a7a/dkms-cubie-a7a-aic8800-usb: an update
  builds the new version, installs it in place of the old one (dkms
  uninstalls that through its kept dkms.conf, or a stand-in when an older
  package already removed its source) and drops the old version from DKMS;
  a failed build keeps the old modules

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.2-1
- Firmware is a user opt-in: no firmware dependency;
  cubie-a7a-wifi-firmware status/install/remove against the pinned manifest
  (Radxa aic8800-firmware 5.0+git20260123.5f7be68d-9, names and SHA256 only);
  WIFI-FIRMWARE.md
- Kernel firmware loader (request_firmware_direct) under
  /lib/firmware/aic8800_fw/USB/aic8800D80/, .xz/.zst accepted; a missing file
  fails the probe with one logged error and leaves the chip unbound
- DKMS for every installed Fedora kernel (no 7.2.9-200.fc44 pin)
- aic_btusb drives the D80 Bluetooth interface (softdep, udev hand-over from
  btusb); stable local MAC when the eFuse has none

* Thu Oct 08 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-1
- Stage official pinned USB driver sources and exact Fedora kernel ABI
- Keep native BlueZ, per-device bounded paths and explicit firmware dependency
