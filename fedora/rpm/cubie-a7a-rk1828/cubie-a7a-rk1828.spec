Name:           cubie-a7a-rk1828
Version:        0.1
Release:        2%{?dist}
Summary:        RK1828 coprocessor PCIe host driver (pcie-rkep) for the stock Fedora kernel
License:        GPL-2.0-only AND (GPL-2.0-or-later OR MIT)
BuildArch:      noarch
# DKMS version = package version-release: every build is a new DKMS version,
# so an update never keeps the module built from older sources.
%global dkms_name rk1828-pcie-rkep
%global dkms_ver %{version}-%{release}
Source0:        rk1828-pcie-rkep-%{version}.tar.gz
Source9:        cubie-a7a-dkms
Requires:       dkms gcc make kmod
Requires:       kernel-devel

%description
Rockchip's pcie-rkep host function driver for an RK1820/RK1828 coprocessor on
PCIe (PCI 1d87:182a), built by DKMS against Fedora's own kernel. It creates
/dev/pcie-rkep-* for the rknn3_transfer_proxy service. The rknn3 runtime is
not part of this package.

%prep
%setup -q -n rk1828-pcie-rkep-%{version}

%build

%install
mkdir -p %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}
cp -a . %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/
sed -i 's/@VERSION@/%{dkms_ver}/' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
grep -qx 'PACKAGE_VERSION="%{dkms_ver}"' %{buildroot}%{_usrsrc}/%{dkms_name}-%{dkms_ver}/dkms.conf
install -Dpm0755 %{SOURCE9} %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}
sed -i -e 's/@MODULE@/%{dkms_name}/g' -e 's/@VERSION@/%{dkms_ver}/g' \
    %{buildroot}%{_libexecdir}/cubie-a7a/dkms-%{dkms_name}

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

%changelog
* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-2
- DKMS version is the package's version-release (was the version alone), so
  an update builds and installs the new sources instead of keeping the old
  build ("already installed, skip")
- Scriptlets through /usr/libexec/cubie-a7a/dkms-rk1828-pcie-rkep: an update
  builds the new version, installs it in place of the old one (dkms
  uninstalls that through its kept dkms.conf, or a stand-in when an older
  package already removed its source) and drops the old version from DKMS;
  a failed build keeps the old modules

* Tue Nov 10 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-1
- First package
