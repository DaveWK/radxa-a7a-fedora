Name:           cubie-a7a-display
Version:        0.1
Release:        3%{?dist}
Summary:        Allwinner A733 HDMI display driver (sunxidrm) for the stock Fedora kernel
License:        GPL-2.0-or-later AND GPL-2.0-only
BuildArch:      noarch
# DKMS version = package version-release: every build is a new DKMS version,
# so an update never keeps the module built from older sources.
%global dkms_name a733-sunxi-drm
%global dkms_ver %{version}-%{release}
Source0:        a733-sunxi-drm-%{version}.tar.gz
Source1:        cubie-a7a-display-modprobe.conf
Source9:        cubie-a7a-dkms
Requires:       dkms gcc make kmod
Requires:       kernel-devel
# Bus master gates with a software copy (0.8); PCK-600 provider.
Requires:       cubie-a7a-board-support >= 0.9
# display-engine, tcon-top1, tcon-tv0 and hdmi nodes (binding stamp 15).
Requires:       cubie-a7a-dtb >= 0.10
# Loads sunxidrm after sun55i_pck600 under the display hang guard.
Requires:       cubie-a7a-hat >= 0.4

%description
The Allwinner sunxi-drm display driver (sunxidrm), HDMI path only, for the
Radxa Cubie A7A (Allwinner A733), built by DKMS against Fedora's own kernel:
display engine v352, tcon-tv0 behind tcon-top1 and the Synopsys DesignWare
HDMI 2.0 TX with its PHY, with the kernel's generic fbdev console. Sources
from the Allwinner BSP (see PROVENANCE); no HDCP 2.x, no DSI/LVDS/eDP.

The firmware does not hand over a running display, so the driver brings
HDMI up from reset. It is not loaded by its device-tree alias:
cubie-a7a-hat.service loads it after the PCK-600 power-domain driver, and a
boot that stops while it loads disables only the display on the next boot
(cubie_a7a.display=0 on the kernel command line skips it).

%prep
%setup -q -n a733-sunxi-drm-%{version}

%build

%install
mkdir -p %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}
cp -a . %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/
sed -i 's/@VERSION@/%{dkms_ver}/' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
grep -qx 'PACKAGE_VERSION="%{dkms_ver}"' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
install -Dpm0755 %{SOURCE9} %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
sed -i -e 's/@MODULE@/%{dkms_name}/g' -e 's/@VERSION@/%{dkms_ver}/g' \
    %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
install -Dpm0644 %{SOURCE1} %{buildroot}%{_prefix}/lib/modprobe.d/cubie-a7a-display.conf

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
%{_prefix}/lib/modprobe.d/cubie-a7a-display.conf

%changelog
* Wed Nov 18 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-3
- sunxidrm builds against Linux 7.4 (7.4.0-0.rc3.26.fc46) as well as 7.3:
  the fbdev helper header moved (compat/drm/drm_fb_helper.h), CRTC and
  plane initial state through .atomic_create_state where the kernel has no
  .reset, drm_encoder_init() in place of the removed
  drm_simple_encoder_init()
- The plane reset no longer frees an uninitialised pointer on its first
  call. Not yet run on a board with a 7.4 kernel

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-2
- DKMS version is the package's version-release (was the version alone), so
  an update builds and installs the new sources instead of keeping the old
  build ("already installed, skip")
- Scriptlets through /usr/libexec/cubie-a7a/dkms-a733-sunxi-drm: an update
  builds the new version, installs it in place of the old one (dkms
  uninstalls that through its kept dkms.conf, or a stand-in when an older
  package already removed its source) and drops the old version from DKMS;
  a failed build keeps the old modules

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-1
- First package: DKMS a733-sunxi-drm (sunxidrm, HDMI only), blacklisted from
  alias loading; cubie-a7a-hat 0.4 loads it
