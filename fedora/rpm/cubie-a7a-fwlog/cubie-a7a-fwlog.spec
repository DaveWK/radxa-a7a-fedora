Name:           cubie-a7a-fwlog
Version:        0.1
Release:        1%{?dist}
Summary:        Read the Radxa Cubie A7A firmware boot log from RAM
License:        BSD-2-Clause
Source0:        a7a-fwlog.c
Source1:        a7a-fwlog.service
Source2:        80-cubie-a7a-fwlog.preset
Source3:        fwlog.md

# It reads the Cubie A7A's (Allwinner A733) RAM; only meaningful there.
ExclusiveArch:  aarch64
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros
%{?systemd_requires}

%description
The oreboot + EDK2 firmware of the Radxa Cubie A7A keeps everything it prints
on UART0 in RAM (this boot and the previous one). a7a-fwlog prints it, like
coreboot's cbmem -c, so a boot can be read from Linux when nothing is
attached to the UART (e.g. under the 2x2.5 GbE HAT). a7a-fwlog.service copies
both logs into the journal at boot (journalctl -t a7a-fwlog).

%prep
%setup -q -c -T
cp -p %{SOURCE0} %{SOURCE3} .

%build
%{__cc} %{optflags} %{build_ldflags} -o a7a-fwlog a7a-fwlog.c

%install
install -Dpm0755 a7a-fwlog %{buildroot}%{_bindir}/a7a-fwlog
install -Dpm0644 %{SOURCE1} %{buildroot}%{_unitdir}/a7a-fwlog.service
install -Dpm0644 %{SOURCE2} %{buildroot}%{_presetdir}/80-cubie-a7a-fwlog.preset

%post
%systemd_post a7a-fwlog.service

%preun
%systemd_preun a7a-fwlog.service

%postun
%systemd_postun a7a-fwlog.service

%files
%doc fwlog.md
%{_bindir}/a7a-fwlog
%{_unitdir}/a7a-fwlog.service
%{_presetdir}/80-cubie-a7a-fwlog.preset

%changelog
* Wed Oct 07 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-1
- Initial package: a7a-fwlog reader and the boot-time journal unit
