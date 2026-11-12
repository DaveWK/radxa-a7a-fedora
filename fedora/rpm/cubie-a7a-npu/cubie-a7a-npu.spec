Name:           cubie-a7a-npu
Version:        0.1
Release:        6%{?dist}
Summary:        Allwinner A733 NPU kernel driver (vipcore) for the stock Fedora kernel
License:        GPL-2.0-only AND (MIT OR GPL-2.0-or-later)
BuildArch:      noarch
# DKMS version = package version-release: every build is a new DKMS version,
# so an update never keeps the module built from older sources.
%global dkms_name a733-vipcore
%global dkms_ver %{version}-%{release}
Source0:        a733-vipcore-%{version}.tar.gz
Source1:        60-cubie-a7a-npu.rules
Source2:        cubie-a7a-npu.sysusers
Source9:        cubie-a7a-dkms
BuildRequires:  systemd-rpm-macros
Requires:       dkms gcc make kmod
Requires:       kernel-devel
Requires:       cubie-a7a-board-support >= 0.6
Requires:       cubie-a7a-dtb >= 0.6

%description
The VeriSilicon VIPLite 2.0 kernel driver (vipcore) for the Allwinner A733's
VIP9000 NPU, built by DKMS against Fedora's own kernel. Sources from Radxa's
Allwinner BSP with a mainline platform file for the A733 (clocks, resets and
the PCK-600 NPU power domain from the device tree; needs cubie-a7a-dtb >= 0.6
for the npu node). The user-space VIPLite runtime is not part of this package.
/dev/vipcore is root and group vipcore only (mode 0660): the NPU can reach
any memory, so add only trusted users to the group.

%prep
%setup -q -n a733-vipcore-%{version}

%build

%install
mkdir -p %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}
cp -a . %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/
sed -i 's/@VERSION@/%{dkms_ver}/' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
grep -qx 'PACKAGE_VERSION="%{dkms_ver}"' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
install -Dpm0755 %{SOURCE9} %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
sed -i -e 's/@MODULE@/%{dkms_name}/g' -e 's/@VERSION@/%{dkms_ver}/g' \
    %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
install -Dpm 0644 %{SOURCE1} %{buildroot}%{_udevrulesdir}/60-cubie-a7a-npu.rules
install -Dpm 0644 %{SOURCE2} %{buildroot}%{_sysusersdir}/cubie-a7a-npu.conf

%post
%{_libexecdir}/cubie-a7a/dkms-%{dkms_name} add || :

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

%files
%doc PROVENANCE
%{_usrsrc}/%{dkms_name}-%{dkms_ver}/
%dir %{_libexecdir}/cubie-a7a
%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
%{_udevrulesdir}/60-cubie-a7a-npu.rules
%{_sysusersdir}/cubie-a7a-npu.conf

%changelog
* Thu Nov 12 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-6
- DKMS sources follow the vipcore tree: debugfs command-stream capture
  (os/linux/vip_drv_capture.c, video-memory and task hooks) compiled only
  in VIPCORE_CAPTURE=1 builds, plus its CAPTURE.md and the capture/ helper
  scripts (not executable, run with sh and python3). The module DKMS builds
  from this package is built without VIPCORE_CAPTURE and has no capture
  code; no driver behaviour change

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-5
- SPEED.md: the combined-load step names the Vulkan workload again (a CPU
  load until the GPU runs); no driver change

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-4
- SPEED.md: the combined-load step uses a CPU load, not a Vulkan workload
  (PowerVR is not part of the stack); no driver change

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-3
- Updated boards kept the first DKMS 0.1 build of vipcore; this release
  builds the current sources: user VMAs set up under the mmap write lock,
  NPU write access following the CPU's (0.1-2), the shared 512 KiB SRAM
  given to the NPU at probe (SYS_CFG+0x8 bit 1), alt_rate test parameter
- DKMS version is the package's version-release (was the version alone), so
  an update builds and installs the new sources instead of keeping the old
  build ("already installed, skip")
- Scriptlets through /usr/libexec/cubie-a7a/dkms-a733-vipcore: an update
  builds the new version, installs it in place of the old one (dkms
  uninstalls that through its kept dkms.conf, or a stand-in when an older
  package already removed its source) and drops the old version from DKMS;
  a failed build keeps the old modules

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-2
- Wrapped user memory and dma-bufs are NPU-writable only when the process
  may write them; wrapping a physical address needs CAP_SYS_RAWIO
- /dev/vipcore is 0660 root:vipcore (was 0666); vipcore group via sysusers.d

* Tue Nov 10 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-1
- First package
