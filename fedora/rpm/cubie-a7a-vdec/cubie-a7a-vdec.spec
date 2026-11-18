Name:           cubie-a7a-vdec
Version:        0.1
Release:        3%{?dist}
Summary:        Allwinner A733 video decoder (a733-cedrus) for the stock Fedora kernel
License:        GPL-2.0-only
BuildArch:      noarch
# DKMS version = package version-release: every build is a new DKMS version,
# so an update never keeps the module built from older sources.
%global dkms_name a733-cedrus
%global dkms_ver %{version}-%{release}
Source0:        a733-cedrus-%{version}.tar.gz
Source1:        cubie-a7a-vdec-modprobe.conf
Source2:        cubie-a7a-vdec-selftest
Source9:        cubie-a7a-dkms
Requires:       dkms gcc make kmod
Requires:       kernel-devel
# v4l2-vp9 and v4l2-jpeg helper modules.
Requires:       kernel-modules
# Bus master gates with a software copy (0.8), PCK-600 provider, cma=512M.
Requires:       cubie-a7a-board-support >= 0.10
# video-codec@1c0e000 enabled (binding stamp 16).
Requires:       cubie-a7a-dtb >= 0.11
# Loads a733-cedrus after sun55i_pck600 under the decoder hang guard.
Requires:       cubie-a7a-hat >= 0.5
# The decoder's users: GStreamer v4l2codecs (stateless decoders) and
# video4linux2 (the JPEG node); the selftest's software references.
Recommends:     gstreamer1-plugins-bad-free gstreamer1-plugins-good
Recommends:     gstreamer1-plugins-base-tools gstreamer1-plugin-libav
Recommends:     v4l-utils python3

%description
The cedrus stateless V4L2 video decoder of Fedora's kernel under another
module name (a733-cedrus) with the Allwinner A733 decoder block of the Radxa
Cubie A7A, built by DKMS against Fedora's own kernel. Every codec is built
in; module parameters choose which the device offers (modinfo a733-cedrus):
MPEG-2, H.264, H.265 8 bit and VP8 by default; H.265 10 bit (as 8-bit NV12),
VP9 and a baseline JPEG node on request. Output is linear NV12 for
GStreamer's v4l2codecs elements (v4l2slh264dec and the like). Nothing of it
has decoded on the board yet; see the module's TESTING.md.

It is not loaded by its device-tree alias: cubie-a7a-hat.service loads it
after the PCK-600 power-domain driver, and a boot that stops while it loads
disables only the decoder on the next boot (cubie_a7a.vdec=0 on the kernel
command line skips it). cubie-a7a-vdec-selftest decodes a short clip per
codec and compares it with a software decode.

%prep
%setup -q -n a733-cedrus-%{version}

%build

%install
mkdir -p %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}
cp -a . %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/
sed -i 's/@VERSION@/%{dkms_ver}/' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
grep -qx 'PACKAGE_VERSION="%{dkms_ver}"' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
install -Dpm0755 %{SOURCE9} %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
sed -i -e 's/@MODULE@/%{dkms_name}/g' -e 's/@VERSION@/%{dkms_ver}/g' \
    %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
install -Dpm0644 %{SOURCE1} %{buildroot}%{_prefix}/lib/modprobe.d/cubie-a7a-vdec.conf
install -Dpm0755 %{SOURCE2} %{buildroot}%{_bindir}/cubie-a7a-vdec-selftest

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
%doc PROVENANCE TESTING.md
%{_usrsrc}/%{dkms_name}-%{dkms_ver}/
%dir %{_libexecdir}/cubie-a7a
%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
%{_prefix}/lib/modprobe.d/cubie-a7a-vdec.conf
%{_bindir}/cubie-a7a-vdec-selftest

%changelog
* Wed Nov 18 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-3
- a733-cedrus is built for Linux 7.4 kernels too (was 7.3 only): the stock
  cedrus of 7.4-rc3 uses the same V4L2 stateless interfaces as 7.3.3's (it
  differs by an allocation helper and one compatible), and the sources
  build unchanged against 7.4.0-0.rc3.26.fc46. Not yet run on a board
  with that kernel

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-2
- DKMS version is the package's version-release (was the version alone), so
  an update builds and installs the new sources instead of keeping the old
  build ("already installed, skip")
- Scriptlets through /usr/libexec/cubie-a7a/dkms-a733-cedrus: an update
  builds the new version, installs it in place of the old one (dkms
  uninstalls that through its kept dkms.conf, or a stand-in when an older
  package already removed its source) and drops the old version from DKMS;
  a failed build keeps the old modules

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-1
- First package: DKMS a733-cedrus with the MPEG-2/H.264, H.265/VP8, VP9 and
  JPEG patch sets, every codec built in and offered per module parameter;
  blacklisted from alias loading, cubie-a7a-hat 0.5 loads it;
  cubie-a7a-vdec-selftest
