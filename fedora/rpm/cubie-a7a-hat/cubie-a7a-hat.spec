Name:           cubie-a7a-hat
Version:        0.8
Release:        1%{?dist}
Summary:        Radxa Cubie A7A: router HAT (PCIe), NPU, GPU, display and video decoder bring-up service
License:        GPL-2.0-only
BuildArch:      noarch
Source0:        cubie-a7a-hat-enable
Source1:        cubie-a7a-hat.service
Source2:        80-cubie-a7a-hat.preset
Source3:        cubie-a7a-hat-modprobe.conf
Source4:        cubie-a7a-npu-selftest
BuildRequires:  systemd-rpm-macros
%{?systemd_requires}
Requires:       cubie-a7a-board-support >= 0.7
Requires:       kmod pciutils coreutils grep

%description
cubie-a7a-board-support keeps the A733 PCK-600 power-domain, SerDes and PCIe
drivers out of automatic loading until each has run on hardware. This package
loads them, the NPU driver (cubie-a7a-npu), the stock GPU driver (powervr)
the HDMI display driver (cubie-a7a-display) and the video decoder
(cubie-a7a-vdec), each of the last two under a separate marker, so that a
hang there disables only that driver, from a service that starts
after the network and sshd, one module at a time. The module being loaded is
recorded on disk first; if a boot stops there, later boots skip the service
and say so in the journal (journalctl -t cubie-a7a-hat), so the board stays
reachable. The Dual 2.5G Router HAT's PCIe switch, its two RTL8125B ports and
an RK1828 in its M.2 slot (cubie-a7a-rk1828) appear once the PCIe driver is in.
A driver can be left out: cubie_a7a.npu=0, cubie_a7a.gpu=0, cubie_a7a.display=0
or cubie_a7a.vdec=0 on the kernel command line, or blocked in modprobe.d
(install <module> /bin/false, or a blacklist line in /etc/modprobe.d); the
service skips it and only a failed modprobe fails the service.

%prep

%build

%install
install -Dpm0755 %{SOURCE0} %{buildroot}%{_libexecdir}/cubie-a7a/hat-enable
install -Dpm0644 %{SOURCE1} %{buildroot}%{_unitdir}/cubie-a7a-hat.service
install -Dpm0644 %{SOURCE2} %{buildroot}%{_presetdir}/80-cubie-a7a-hat.preset
install -Dpm0644 %{SOURCE3} %{buildroot}%{_prefix}/lib/modprobe.d/cubie-a7a-hat.conf
install -Dpm0755 %{SOURCE4} %{buildroot}%{_bindir}/cubie-a7a-npu-selftest

%post
%systemd_post cubie-a7a-hat.service

%preun
%systemd_preun cubie-a7a-hat.service

%postun
%systemd_postun cubie-a7a-hat.service

%files
%{_libexecdir}/cubie-a7a/hat-enable
%{_bindir}/cubie-a7a-npu-selftest
%{_unitdir}/cubie-a7a-hat.service
%{_presetdir}/80-cubie-a7a-hat.preset
%{_prefix}/lib/modprobe.d/cubie-a7a-hat.conf

%changelog
* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.8-1
- 0.6 behaviour restored (0.7 is withdrawn): powervr is in the module list
  again, cubie_a7a.gpu=0 skips it, and the package blacklists powervr from
  automatic loading as before. The GPU work is in progress, not dropped;
  while it hangs the board, the board's own block in /etc/modprobe.d makes
  the service skip powervr (since 0.6)

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.7-1
- PowerVR removed from the stack: powervr is no longer in the module list,
  cubie_a7a.gpu= is gone, and the package's own "blacklist powervr" moved to
  cubie-a7a-board-support (>= 0.11), which blocks the module outright

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.6-1
- Skip a module that modprobe.d blocks (install <module> /bin/false or
  /bin/true), that /etc or /run/modprobe.d blacklists, or that is in
  modprobe.blacklist=, and log why; a skipped module is not a failure (a
  board with /etc/modprobe.d blocking powervr ended the service failed)
- cubie_a7a.gpu=0 and cubie_a7a.npu=0 skip powervr and vipcore
- The exit status counts only modprobe calls that failed

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.5-1
- Load a733-cedrus (cubie-a7a-vdec) after the display, only with the
  PCK-600 driver bound, under its own marker (vdec-enable.trying) that is
  kept until the decoder's video device appears or 10 s pass;
  cubie_a7a.vdec=0 skips it, cubie_a7a.vdec_selftest=1 also runs
  cubie-a7a-vdec-selftest under the same marker

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.4-1
- Load sunxidrm (cubie-a7a-display) last, only with the PCK-600 driver bound,
  under its own marker (display-enable.trying) that is kept until the HDMI
  connector appears or 20 s pass; cubie_a7a.display=0 skips it

* Wed Nov 11 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.3-1
- cubie-a7a-npu-selftest: run the VIPLite sample and report versions and timing
- The service runs it once after vipcore loads, under the same hang guard

* Tue Nov 10 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.2-1
- Also load powervr (A733 GPU) after the power-domain driver

* Tue Nov 10 2026 DaveWK <13626476+DaveWK@users.noreply.github.com> - 0.1-1
- First package
