Name:           cubie-a7a-board-support
Version:        0.16
Release:        4%{?dist}
Summary:        Radxa Cubie A7A support for the stock Fedora kernel
License:        GPL-2.0-only
BuildArch:      noarch
# DKMS version = package version-release: every build is a new DKMS version,
# so an update never keeps the kmods built from older sources.
%global dkms_name cubie-a7a-kmods
%global dkms_ver %{version}-%{release}

Source0:        dracut-cubie-a7a.conf
Source1:        cubie-a7a-kmods-%{version}.tar.gz
Source2:        cubie-a7a-cmdline
Source3:        cubie-a7a-depmod.conf
Source4:        cubie-a7a-staged.conf
Source5:        cubie-a7a-kernel
Source6:        99-zz-cubie-a7a.install
Source7:        cubie-a7a-dkms
Source8:        cubie-a7a-watchdog.conf
Source9:        cubie-a7a-panic.conf

# DKMS builds the kmods on the board for every Fedora kernel, inside the
# same dnf transaction (file trigger below), so kernel-devel must follow
# the kernel: it is installonly, so dnf upgrade installs the matching one.
Requires:       dkms gcc make kmod
Requires:       kernel-devel
Requires:       kernel-core
Requires:       dracut grubby
# 0.17 (binding stamp 22) has the WDT0 node the systemd watchdog drop-in
# pets; with an older DTB there is no /dev/watchdog0 and the drop-in idles.
Recommends:     cubie-a7a-dtb >= 0.17
# 0.15 (binding stamp 20) names the GPU master gates on the PCK-600 node;
# with an older DTB nothing would enable them for the GPU.
Conflicts:      cubie-a7a-dtb < 0.15

%description
Board support for running Fedora's own kernel (the kernel packages from the
Fedora 44 repositories) on the Radxa Cubie A7A (Allwinner A733), until the
A733 drivers are in Fedora's kernel. Boot firmware: oreboot + EDK2 (it
initialises the Ethernet PHY, and PCIe/USB for the interim device tree).

- DKMS cubie-a7a-kmods, from the Cubie A7A Linux series:
  - sun60i-a733-ccu, pinctrl-sun60i-a733, axp318w, axp318-regulator: the
    A733 clock and pin controllers and the AXP318W PMIC. Fedora builds the
    sunxi-ng CCU, pinctrl-sunxi and AXP20x MFD cores into vmlinux without
    the A733 changes, so each module carries a private copy of its core
    (no exported symbols, A733 compatibles only, renamed drivers), leaving
    the built-in drivers and every other Allwinner board untouched.
  - sun6i-dma, dwmac-sun55i (and sun55i-pck600): replace the stock modules
    with A733 support (depmod.d override). They embed kernel-internal
    headers, one set for the 7.2 and 7.3 series and one for 7.4.
  - Linux 7.4: the A733 pin controllers are built into the kernel and the
    stock sun6i-dma has the A733, so neither module is built there; the
    initramfs policy and the kernel guard follow the kernel series.
  - sun60i-a733-serdes, sun60i-a733-pcie, sun55i-pck600: built but not
    loaded automatically yet (modprobe.d), enabled one peripheral at a time.
  - sun8i_thermal, nvmem_sunxi_sid: the stock drivers with the A733 entries
    (five thermal sensors, SID calibration, two-segment curve; the SID's
    non-secure window), replacing the stock modules like sun6i-dma.
- Kernel updates: an RPM transaction file trigger builds the kmods for each
  new kernel and rebuilds its initramfs once the whole dnf transaction is in
  place, and a kernel-install plugin (last in order, after Fedora's default
  switch) checks every kernel. A kernel without the boot kmods never stays
  the default boot entry; the journal says why.
- dracut policy: generic initramfs that loads the A733 drivers first, so
  the SD card root can mount.
- Kernel arguments clk_ignore_unused pd_ignore_unused, which the interim,
  firmware-initialised device tree nodes need, and, temporarily,
  regulator_ignore_unused until the always-on PMIC rails in the board DTB
  are proven on hardware; cma=512M (unless a cma= is set already) for the
  video decoder and display buffers.
- Hardware watchdog: systemd (PID 1) opens /dev/watchdog0 (WDT0, binding
  stamp 22 of cubie-a7a-dtb) with a 16 s timeout, the driver's maximum, at
  run time and during reboot, so a hung kernel or PID 1 resets the SoC and
  the board recovers on its own (into FEL while the SD slot is dead).
  RuntimeWatchdogSec=off in /etc/systemd/system.conf.d/ turns it off.
- sysctl kernel.panic_on_oops=1 and kernel.panic=10
  (/usr/lib/sysctl.d/60-cubie-a7a-panic.conf): an oops panics and a panic
  reboots after 10 s, so with the watchdog any oops, panic or hang ends in
  a reset. Applied at boot by systemd-sysctl, not at install.
Retire each piece as soon as Fedora's kernel carries the driver.

%prep
%setup -q -c -T -a 1 -n %{name}-%{version}

%build

%install
install -Dpm0644 %{SOURCE0} %{buildroot}%{_sysconfdir}/dracut.conf.d/cubie-a7a.conf
install -Dpm0755 %{SOURCE2} %{buildroot}%{_libexecdir}/cubie-a7a/cmdline
install -Dpm0644 %{SOURCE3} %{buildroot}%{_prefix}/lib/depmod.d/cubie-a7a.conf
install -Dpm0644 %{SOURCE4} %{buildroot}%{_prefix}/lib/modprobe.d/cubie-a7a-staged.conf
install -Dpm0755 %{SOURCE5} %{buildroot}%{_libexecdir}/cubie-a7a/kernel
sed -i 's/@VERSION@/%{dkms_ver}/' %{buildroot}%{_libexecdir}/cubie-a7a/kernel
install -Dpm0755 %{SOURCE6} %{buildroot}%{_prefix}/lib/kernel/install.d/99-zz-cubie-a7a.install
install -Dpm0644 %{SOURCE8} %{buildroot}%{_prefix}/lib/systemd/system.conf.d/60-cubie-a7a-watchdog.conf
install -Dpm0644 %{SOURCE9} %{buildroot}%{_prefix}/lib/sysctl.d/60-cubie-a7a-panic.conf
mkdir -p %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}
cp -a cubie-a7a-kmods-%{version}/* %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/
sed -i 's/@VERSION@/%{dkms_ver}/' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
grep -qx 'PACKAGE_VERSION="%{dkms_ver}"' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
install -Dpm0755 %{SOURCE7} %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
sed -i -e 's/@MODULE@/%{dkms_name}/g' -e 's/@VERSION@/%{dkms_ver}/g' \
    %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}

%post
%{_libexecdir}/cubie-a7a/dkms-%{dkms_name} add || :

%posttrans
%{_libexecdir}/cubie-a7a/cmdline add || :
# Every installed kernel, not just the running one: images are assembled in
# a chroot, where uname -r is the build host's. ensure builds this DKMS
# version wherever another one (or none) is installed, replacing the old
# modules only once the build succeeded, and rebuilds the initramfs when its
# boot kmods changed; prune then drops versions no kernel uses any more.
for v in %{_prefix}/lib/modules/*/vmlinuz; do
    [ -f "$v" ] || continue
    k=${v%%/vmlinuz}; k=${k##*/}
    %{_libexecdir}/cubie-a7a/kernel ensure "$k" || :
    %{_libexecdir}/cubie-a7a/kernel guard "$k" || :
done
%{_libexecdir}/cubie-a7a/dkms-%{dkms_name} prune || :

# New kernels and kernel-devel packages: runs once at the end of the dnf
# transaction, after every package (kernel-core, kernel-modules, kernel-devel)
# is in place, whatever order dnf installed them in. Fedora's kernel-core
# lists its files under /lib/modules (not /usr/lib/modules), and rpm matches
# trigger prefixes on the packaged path, so both prefixes are named.
%transfiletriggerin -- /lib/modules %{_prefix}/lib/modules %{_usrsrc}/kernels
kvers=$(sed -n -e 's|^/lib/modules/\([^/]*\)/vmlinuz$|\1|p' \
    -e 's|^%{_prefix}/lib/modules/\([^/]*\)/vmlinuz$|\1|p' \
    -e 's|^%{_usrsrc}/kernels/\([^/]*\)/Makefile$|\1|p' | sort -u)
for k in $kvers; do
    [ -f %{_prefix}/lib/modules/$k/vmlinuz ] || continue
    %{_libexecdir}/cubie-a7a/kernel ensure "$k" || :
    %{_libexecdir}/cubie-a7a/kernel guard "$k" || :
done

%preun
# Erase: out of every kernel. Update: out of DKMS unless installed; installed
# kmods stay until the new package has built its own (%%posttrans), so a
# failed build never leaves a kernel without its boot modules.
%{_libexecdir}/cubie-a7a/dkms-%{dkms_name} preun $1 %{dkms_ver} || :
if [ $1 -eq 0 ]; then
    %{_libexecdir}/cubie-a7a/cmdline remove || :
fi

%files
%{_sysconfdir}/dracut.conf.d/cubie-a7a.conf
%{_prefix}/lib/depmod.d/cubie-a7a.conf
%{_prefix}/lib/modprobe.d/cubie-a7a-staged.conf
%{_prefix}/lib/kernel/install.d/99-zz-cubie-a7a.install
%{_prefix}/lib/systemd/system.conf.d/60-cubie-a7a-watchdog.conf
%{_prefix}/lib/sysctl.d/60-cubie-a7a-panic.conf
%dir %{_libexecdir}/cubie-a7a
%{_libexecdir}/cubie-a7a/cmdline
%{_libexecdir}/cubie-a7a/kernel
%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
%{_usrsrc}/%{dkms_name}-%{dkms_ver}/

%changelog
* Thu Nov 19 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.16-4
- pinctrl-sun60i-a733: sunxi_pmx_free() handles a regulator_disable
  failure on the last-user path like the driver's other error paths: it
  logs with dev_err and still puts and clears the handle, so the bank has
  no stale regulator and a later request gets a fresh one instead of
  disabling the same regulator twice.  Host model extended with
  --fail-disable (fedora/tests/pinctrl-bank-supply.py).  Board check
  pending (row B / task-000057)

* Wed Nov 18 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.16-3
- pinctrl-sun60i-a733 (built for 7.2 and 7.3 kernels): backport of
  "pinctrl: sunxi: a733: do not switch the mux to read IRQ lines" (Vinicius
  Pedrosa, list posting of 2026-11-10; not in mainline v7.4-rc3). The main
  controller no longer sets irq_read_needs_mux: reading a GPIO that is in
  use as an interrupt left the pin on function 6 instead of the A733
  interrupt function 14, so its interrupt stopped. On this board that is
  the microSD card-detect line PF6 (mmc0 cd-gpios); R-PIO never had the
  flag. The kernel's own driver, which 7.4 kernels use, still has it
- Its own release on purpose: 0.16-2 has the bank supply lock only, for
  counting boots against the refcount race
- Checked by a build. Not yet run on a board

* Wed Nov 18 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.16-2
- pinctrl-sun60i-a733 (built for 7.2 and 7.3 kernels): a mutex per pin bank
  around the bank supply bookkeeping in sunxi_pmx_request() and
  sunxi_pmx_free(). The pinctrl core serialises these callbacks per pin,
  not per bank, so two devices with pins in one bank that probe at the same
  time could both take the "no supply yet" path: one regulator handle was
  leaked and the bank's user count restarted at 1. On 2026-11-18 one boot
  in five of the 6 GB board then logged "refcount_t: underflow;
  use-after-free" from sunxi_pmx_free when a deferred probe released its
  pins (bank PF by the register dump; with the device tree of that boot,
  older than binding stamp 25, mmc0 and the PF4 regulator GPIO have pins
  there and probe in parallel). No functional change without the race
- Mainline v7.4-rc3 has the same unlocked code, and on 7.4 kernels the pin
  controller is the kernel's own, which this package does not replace
- Checked in a host model of the two functions (fedora/tests) and by a
  build. Not yet run on a board

* Wed Nov 18 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.16-1
- Linux 7.4 (Fedora Rawhide, 7.4.0-0.rc3.26.fc46): mainline has the A733
  pin controllers since v7.4-rc1 and Fedora builds them in
  (CONFIG_PINCTRL_SUN60I_A733=y), and the stock sun6i-dma has the A733 DMA
  controller. cubie-a7a-kmods builds neither pinctrl-sun60i-a733 nor the
  sun6i-dma override for 7.4 kernels; 7.2 and 7.3 kernels get both as before
- Internal header sets per kernel series: stmmac/k7.3 and pcie/k7.3 (the
  set used so far, unchanged) and stmmac/k7.4 and pcie/k7.4 from Fedora's
  7.4.0-0.rc3.26.fc46 source; dkms.conf picks by kernel version. A series
  without a set still gets no override modules and fails the guard
- dracut policy: force-loads each A733 boot module only where the kernel
  has it as a module (no pinctrl-sun60i-a733.ko on 7.4)
- /usr/libexec/cubie-a7a/kernel: the boot module list follows the kernel
  series; from 7.4 on the check wants CONFIG_PINCTRL_SUN60I_A733=y in the
  kernel's config and the stock sun6i-dma in the initramfs
- The module sources are unchanged (CCU, AXP318W, GMAC, PPU, thermal, SID,
  SerDes, PCIe build for both series as they are)

* Thu Nov 12 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.15-2
- sysctl drop-in /usr/lib/sysctl.d/60-cubie-a7a-panic.conf:
  kernel.panic_on_oops = 1 and kernel.panic = 10. On 2026-11-12 a
  non-fatal "list_del corruption" BUG (an oops in process context) left the
  board limping, sshd resetting connections, instead of rebooting into FEL.
  Now an oops panics, a panic reboots after 10 s, and the 16 s watchdog
  covers hangs. Replaces the board's manual
  /etc/sysctl.d/90-panic-reboot.conf (kernel.panic = 10), which can stay
- Not applied at install time (sysctls are not namespaced: an image build
  in a container would change the build host's kernel); systemd-sysctl
  applies it at the next boot, or sysctl --system at once. An oops before
  systemd-sysctl runs (initramfs) still uses the kernel defaults

* Thu Nov 12 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.15-1
- systemd drop-in /usr/lib/systemd/system.conf.d/60-cubie-a7a-watchdog.conf:
  RuntimeWatchdogSec=16s and RebootWatchdogSec=16s, so PID 1 pets WDT0
  (/dev/watchdog0, cubie-a7a-dtb 0.17, binding stamp 22) and a hang in
  Linux, or in the final stage of a reboot, resets the SoC (into FEL while
  the SD slot is dead) instead of needing a USB-C replug
- 16 s is the sunxi_wdt maximum (WDT_MAX_TIMEOUT); the watchdog core
  rejects a longer timeout with EINVAL, so a 30 s runtime value, or
  systemd's default RebootWatchdogSec=10min, cannot be programmed on this
  board. systemd pets at half the timeout (8 s)
- Recommends cubie-a7a-dtb >= 0.17 (without the WDT0 node there is no
  watchdog device and the drop-in has no effect)
- The DKMS sources are unchanged from 0.14-1 (new DKMS version 0.15-1 by
  the version-release rule)

* Thu Nov 12 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.14-1
- sun55i-pck600: a GPU domain found on at probe is switched off before it is
  published, GPU_CORE (clock/reset handshake, GPU_TOP's master gates held)
  before GPU_TOP (gates released), so genpd and powervr power them on on
  demand. On the board GPU_TOP stayed on under 0.13 with its master gates
  enabled: a domain published on stays on until every consumer of the
  provider has probed (genpd sync_state), and pd_ignore_unused or
  genpd_power_off_unused never apply to a module. A domain that will not
  switch off stays published on, as before
- sun55i_pck600.gpu_core_always_on=1 unchanged: the 0.12 behaviour, nothing
  is switched off at probe
- sun55i-pck600: clock lookups precede every PPU write; a probe failure
  releases the gates of every domain

* Thu Nov 12 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.13-1
- GPU power on demand: GPU_TOP and GPU_CORE are no longer
  switched on at probe; genpd switches them on when the GPU device (powervr)
  attaches or resumes through its power-domains, and off when it suspends
- sun55i-pck600: GPU_CORE is not always-on by default; the GPU_CORE
  clock/reset handshake and the gpu_core_seq/settle_ms experiments run at
  that on-demand power-on. sun55i_pck600.gpu_core_always_on=1 restores the
  0.12 behaviour (GPU_TOP and GPU_CORE on at probe, GPU_CORE always-on)
- sun55i-pck600: GPU_TOP holds the GPU bus master gates (gpu-ahb,
  gpu-mbus on the PCK-600 node, binding stamp 20) while it is on
- CCU: ahb-gpu0/mbus-gpu0 are ordinary gates again (critical up to 0.12)
- Conflicts cubie-a7a-dtb < 0.15
- No package-level powervr block; the board's temporary /etc/modprobe.d
  block stays the board's own

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.12-1
- 0.10-2 sources and behaviour restored (0.11 is withdrawn: it removed the
  GPU work before an open replacement existed):
- sun55i-pck600: GPU_CORE always-on again (parent GPU_TOP switched on
  first), the GPU_CORE inner-device clocks/reset handshake and the
  gpu_core_seq/settle_ms experiments are back
- CCU: ahb-gpu0/mbus-gpu0 critical again (a733-master-gates patch 0002)
- No package-level powervr block: no /usr/lib/modprobe.d/cubie-a7a-no-powervr.conf,
  no dracut omit, no %%_netsharedpath macro. The board's temporary
  /etc/modprobe.d block stays the board's own
- tests/ppu: the 0.10 controls and mutations

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.11-1
- PowerVR removed from the stack (the A733 GPU needs Imagination's closed
  firmware): /usr/lib/modprobe.d/cubie-a7a-no-powervr.conf blocks powervr
  (blacklist + install /bin/false; replaces the board's temporary
  /etc/modprobe.d/zz-a7a-no-powervr.conf), dracut omits it, and
  macros.cubie-a7a-no-powervr sets %%_netsharedpath so rpm never installs
  /usr/lib/firmware/powervr or Mesa's PowerVR Vulkan ICD
- sun55i-pck600: GPU_CORE is no longer always-on, so neither GPU domain is
  switched on at probe (both stay off as the firmware leaves them); the
  GPU_CORE inner-device clocks/reset and the gpu_core_seq/settle_ms
  experiments are gone (frame logging and debugfs pck600-regs stay)
- CCU: ahb-gpu0/mbus-gpu0 are ordinary gates again, not critical

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.10-2
- DKMS version is the package's version-release (was the version alone):
  0.8 -> 0.10 left cubie-a7a-kmods/0.10 only added and 0.8 broken (source
  removed, still installed), so 0.10 could not be installed
- Scriptlets through /usr/libexec/cubie-a7a/dkms-cubie-a7a-kmods: an update
  builds the new version first, then installs it in place of the old one
  (dkms uninstalls that through its kept dkms.conf, or a stand-in when an
  older package already removed its source) and drops the old version from
  DKMS; a failed build keeps the old kmods
- kernel ensure: rebuilds when the installed DKMS version is not the
  package's (not only when a boot kmod is missing), and rebuilds the
  initramfs when its boot kmods are older than those in the module tree

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.10-1
- Kernel argument cma=512M, added only where no cma= is set: the 64 MiB
  default pool cannot hold the video decoder's (cubie-a7a-vdec) frame
  buffers beyond small clips
- sun55i-pck600: parent-first power-on, degraded (off) registration of a domain
  that won't switch on, GPU clocks/reset held across GPU_CORE, full PPU logging,
  debugfs pck600-regs, gpu_core_seq experiments
- CCU: pll-npu within the vendor factor range (N 53-105, no input divider)
- pinctrl: dynamic GPIO base (chip offsets unchanged)

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.9-1
- Kernel arguments: regulator_ignore_unused (temporary, with the DT always-on
  rails of cubie-a7a-dtb 0.9)

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.8-1
- CCU: bus master gate registers keep a software copy, so one master's gate
  write cannot clear another's; GPU bus master gates kept on

* Tue Nov 10 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.7-1
- Fedora 45: override modules also built for 7.3 kernels (stmmac internal
  headers from 7.3.3, layout-identical to 7.2.10); PCIe INTx domain through
  irq_domain_create_linear

* Thu Oct 15 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.6-1
- Thermal: sun8i_thermal and nvmem_sunxi_sid overrides with the A733 entries
  (five sensors, SID calibration at 0x44, two-segment curve, polling, SID
  non-secure window 0x80); pairs with cubie-a7a-dtb 0.5 (thermal zones, fan)

* Thu Oct 15 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.5-1
- A733 CCU drivers and clock IDs from the v6 posting of the series
  (2026-10-09): R-CCU R_TWD bus clock dropped (IDs after 8 shift), mbus-nand0,
  ahb-store/mbus-store gate parents; internal headers from Fedora 7.2.10.
  Needs cubie-a7a-dtb >= 0.4 (same clock IDs)

* Thu Oct 15 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.4-3
- kernel-install plugin renamed 99-zz-cubie-a7a.install so it runs after
  Fedora's 95-set-boot-entry.install (which makes the new kernel the default)
  and 99-grub-mkconfig.install; CUBIE_A7A_RUNNING_KERNEL test hook

* Thu Oct 15 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.4-2
- File trigger also on /lib/modules (kernel-core's packaged path); the guard
  logs its result for every kernel

* Thu Oct 15 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.4-1
- Fedora's own kernel releases (no private kernel): kernel-devel follows
  the kernel, transaction file trigger + kernel-install guard keep a kernel
  without the boot kmods from becoming the default, depmod.d overrides for
  the A733 sun6i-dma/dwmac-sun55i/sun55i-pck600, SerDes/PCIe/PPU staged
  (modprobe.d), minimum initramfs set

* Wed Oct 07 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-1
- Initial board support for the stock Fedora 44 kernel (7.2.8-200.fc44):
  DKMS A733 CCU/pinctrl/AXP318W with private cores, sun6i-dma and
  dwmac-sun55i overrides, dracut policy, interim kernel arguments
