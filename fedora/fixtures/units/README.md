# Pinned-unit fixtures

These are the expected `systemd-analyze --root=<root> cat-config
systemd/system/<unit>` outputs for the two systemd-repart units, normalised to
`# /<path>` headers. The build-time check `devcard-policy.py unit-config`
compares the staged root's resolution byte for byte with these, so symlinks,
usr-merge, drop-ins, conditions and aliases are systemd's decisions, not ours.

- `root-*.cat-config`  the stock unit's own command line plus the no-discard
  drop-in `10-cubie-a7a-no-discard.conf` that mkdevcard.sh writes for each
  unit (the unpartitioned gap in front of the first partition holds the boot
  firmware, so systemd-repart must run with `--discard=no`).
- `initramfs-*.cat-config`  "Main configuration file ... not found": the dracut
  initramfs carries no systemd-repart unit (the discard protection lives on the
  root), so the resolved unit is absent.

Generated once from the intended state (systemd 262, 262.1-1.fc45) and reviewed;
a systemd update that changes any of these files fails the build until the pin is
updated. The manifest records their sha256 (fedora/devcard-manifest.py).