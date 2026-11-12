Name:           cubie-a7a-dtb
Version:        0.17
Release:        1%{?dist}
Summary:        Radxa Cubie A7A device tree, used when newer than the firmware's
License:        (GPL-2.0-only OR MIT) AND BSD-2-Clause AND MIT
Source0:        cubie-a7a-dts-%{version}.tar.gz
Source1:        cubie-a7a-install-dtb
Source2:        89-cubie-a7a-dtb.install
Source3:        cubie-a7a-dtb.service
Source4:        80-cubie-a7a-dtb.preset

BuildArch:      noarch
BuildRequires:  dtc
BuildRequires:  cpp
BuildRequires:  make
BuildRequires:  systemd-rpm-macros
Requires:       coreutils
Requires:       cubie-a7a-board-support >= 0.13
%{?systemd_requires}

# Build with --with esp_override when the drivers in this release need a
# binding the firmware does not have yet even at the same stamp.
%bcond esp_override 0

%description
Device tree for the Radxa Cubie A7A (Allwinner A733) running a stock Fedora
kernel with cubie-a7a-board-support: the board tree from the Cubie A7A
Linux series, native paired SERDES/PCIe and remaining firmware-initialised
EHCI/OHCI nodes, the SPI NOR as one read-only partition, the A733 thermal
sensors with five thermal zones, the PL9 gpio-fan, the HDMI display path
(display engine, tcon-tv0, DW HDMI) for cubie-a7a-display, the video
decoder for cubie-a7a-vdec and the WDT0 watchdog (mainline sunxi_wdt), which
cubie-a7a-board-support has systemd pet. It works with Fedora's own kernel
and the cubie-a7a-board-support modules.

The oreboot + EDK2 firmware embeds a DTB built from the same source. This
package installs its copy on the ESP (\dtb\allwinner\, which the firmware
prefers) only while its binding stamp, cubie-a7a,dtb-version, is newer than
the firmware's, and removes it again once the firmware has caught up.

%prep
%setup -q -n cubie-a7a-dts-%{version}

%build
make DTB_ORIGIN=rpm OUT=sun60i-a733-cubie-a7a.dtb

%install
install -Dpm0644 sun60i-a733-cubie-a7a.dtb \
    %{buildroot}%{_prefix}/lib/cubie-a7a/dtb/allwinner/sun60i-a733-cubie-a7a.dtb
install -Dpm0644 DTB_VERSION %{buildroot}%{_prefix}/lib/cubie-a7a/dtb/VERSION
%if %{with esp_override}
touch %{buildroot}%{_prefix}/lib/cubie-a7a/dtb/esp-override
%endif
install -Dpm0755 %{SOURCE1} %{buildroot}%{_libexecdir}/cubie-a7a/install-dtb
install -Dpm0755 %{SOURCE2} %{buildroot}%{_prefix}/lib/kernel/install.d/89-cubie-a7a-dtb.install
install -Dpm0644 %{SOURCE3} %{buildroot}%{_unitdir}/cubie-a7a-dtb.service
install -Dpm0644 %{SOURCE4} %{buildroot}%{_presetdir}/80-cubie-a7a-dtb.preset
install -d %{buildroot}%{_sharedstatedir}/cubie-a7a

%post
%systemd_post cubie-a7a-dtb.service

%preun
%systemd_preun cubie-a7a-dtb.service
if [ $1 -eq 0 ]; then
    %{_libexecdir}/cubie-a7a/install-dtb --remove || :
fi

%postun
%systemd_postun cubie-a7a-dtb.service

%posttrans
%{_libexecdir}/cubie-a7a/install-dtb || :

%files
%license LICENSES/*
%doc PROVENANCE
%dir %{_prefix}/lib/cubie-a7a
%{_prefix}/lib/cubie-a7a/dtb/
%dir %{_libexecdir}/cubie-a7a
%{_libexecdir}/cubie-a7a/install-dtb
%{_prefix}/lib/kernel/install.d/89-cubie-a7a-dtb.install
%{_unitdir}/cubie-a7a-dtb.service
%{_presetdir}/80-cubie-a7a-dtb.preset
%dir %{_sharedstatedir}/cubie-a7a

%changelog
* Thu Nov 12 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.17-1
- Binding stamp 22: WDT0 (0x02050000) for the mainline sunxi_wdt driver,
  compatible "allwinner,sun60i-a733-wdt", "allwinner,sun55i-a523-wdt"
  (cubie-a7a-watchdog.dtsi). The node was tested on the board with a
  one-shot test DTB (the same device tree as this one): /dev/watchdog0,
  16 s, settable; a forced hang with the watchdog running reset the SoC
  into FEL. cubie-a7a-board-support 0.15 has systemd pet it
- Stamp 21 and version 0.16 are skipped: an eMMC draft (mmc2 node) that was
  never shipped used them. The eMMC node takes the next stamp (23) and
  version on top of this release, because install-dtb only installs a
  stamp newer than the firmware's

* Thu Nov 12 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.15-1
- Binding stamp 20: GPU power on demand. The PCK-600 node also names the
  GPU's AHB and MBUS master gates (gpu-ahb, gpu-mbus), which the provider
  holds only while GPU_TOP is on; they are no longer critical in the CCU.
  gpu@1800000, its clocks, reset, both power domains, the 600 MHz
  assignment, the GPU_CORE handshake clocks/reset and the 800 MHz opt-in are
  unchanged. DCDC4 (the GPU rail) stays always-on, as on the vendor image
- Requires cubie-a7a-board-support >= 0.13 (on-demand GPU domains and the
  master gates held by GPU_TOP)

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.14-1
- Binding stamp 19: the stamp-17 content restored (0.13 is withdrawn: it
  removed the GPU work before an open replacement existed). gpu@1800000 is
  enabled again with its 600 MHz PERI0 clock assignment and both GPU power
  domains; the PCK-600 node names the GPU clocks, reset and 600 MHz
  assignment for the GPU_CORE handshake again; the 800 MHz opt-in
  (cubie-a7a-gpu-800m.dtsi, GPU-800M.md) is back in fedora/dts/
- Requires cubie-a7a-board-support >= 0.12 (its PCK-600 driver handles the
  GPU_CORE handshake again; 0.11 is withdrawn)

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.13-1
- Binding stamp 18: PowerVR removed from the stack (the GPU needs
  Imagination's closed firmware). gpu@1800000 stays as a description with
  status "disabled", without assigned clocks; the PCK-600 node no longer
  names the GPU clocks, reset and 600 MHz assignment, so nothing powers or
  clocks the GPU. DCDC4 (VDD-GPU) stays always-on as before. The 800 MHz
  opt-in (cubie-a7a-gpu-800m.dtsi) was set aside
- Requires cubie-a7a-board-support >= 0.11 (its PCK-600 driver no longer
  switches the GPU domains on at probe)

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.12-1
- Binding stamp 17: board workaround for SDC0-D3 (PF4) leaking to ground
  (cubie-a7a-sd-d3-workaround.dtsi): mmc0 1-bit on PF0..PF3/PF5, the
  PF0..PF5 mmc0_pins group deleted, PF4 held high by an always-on fixed
  regulator (no gpio-hog)

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.11-1
- Binding stamp 16: video decoder from cubie-a7a-video-codec.dtsi
  (video-codec@1c0e000, PCK-600 VE_DEC domain, 624 MHz from pll-ve0, no
  IOMMU) for the a733-cedrus module of cubie-a7a-vdec

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.10-1
- Binding stamp 15: HDMI display path from cubie-a7a-display.dtsi (DE v352,
  tcon-top1, tcon-tv0, DW HDMI 2.0 TX; PCK-600 DE_SYS/VO1 domains, CLDO2 and
  DCDC2 supplies) for the sunxidrm module of cubie-a7a-display

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.9-1
- Binding stamp 14: EEPROM write-protect via wp-gpios (the gpio-hog failed the
  main pin controller on 7.1+ kernels); PMIC rails dcdc1, swout1, swout2,
  cldo5, dcdc8, dldo1, dldo6 always-on; Arm PMU; fan supply; PG bank on ALDO1

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.8-1
- Binding stamp 13: GPU rail (DCDC4) and HDMI 1.8 V (CLDO2) kept on, CPU
  capacities 430/1024

* Tue Nov 10 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.7-1
- Binding stamp 12: A733 GPU node for the mainline powervr driver, 600 MHz

* Tue Nov 10 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.6-1
- Binding stamp 11: A733 NPU node (vipcore, cubie-a7a-npu), 492 MHz

* Thu Oct 15 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.5-1
- Binding stamp 10: A733 THS and SID nodes, five thermal zones (fan on at
  60 C, critical 110 C), PL9 gpio-fan; requires cubie-a7a-board-support 0.6

* Thu Oct 15 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.4-1
- Binding stamp 9: clock IDs of the A733 CCU v6 posting (R-CCU renumbered
  after R_TWD); requires cubie-a7a-board-support 0.5 (matching CCU kmod)

* Thu Oct 15 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.3-1
- Binding stamp 8: SPI NOR as one read-only partition; Fedora's own kernel
  (the private RTC kernel requirement is gone)

* Thu Oct 08 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-5
- Binding stamp5: schematic-correct PJ LEDs and read-only, write-protected EEPROM

* Thu Oct 08 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-4
- Binding stamp4: schematic-matched battery RTC, PL12/13 mux and stable rtc0 ID

* Thu Oct 08 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-3
- Binding stamp3: preserve full native combo0 SuperSpeed controller capability

* Thu Oct 08 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-2
- Binding stamp 2: explicit unrolled PCIe iATU mapping and generic application/MSI IRQ resources

* Wed Oct 07 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-1
- Initial package: Cubie A7A DTB (binding stamp 1) with an ESP override that
  is installed only while the firmware's DTB is older
