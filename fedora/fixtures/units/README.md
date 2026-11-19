# Staged systemd fixture regeneration

`repart-yes`, `repart-no`, and `repart-initramfs` each pin the real manager
result and the complete unit inventory. From an owned staged fixture tree:

```sh
python3 -I fedora/staged-systemd.py capture "$root" "$candidate_fixtures" yes
python3 -I fedora/staged-systemd.py capture "$no_grow_root" "$candidate_fixtures" no
python3 -I fedora/staged-systemd.py capture "$unpacked_initramfs" "$candidate_fixtures" initramfs
```

Generate into a separate existing directory. Review the effective commands
and every inventory difference before updating the pin; never capture a failed
overlay or automatically refresh pins during an image build.

The initial pins are seed fixtures made by
`python3 -I fedora/tests/staged-systemd.py --seed-pins "$candidate_fixtures"`.
They exercise the real loader against the stock repart fragment, its drop-ins,
the vendor wants link, both masks, and the no-repart initramfs case. They do
not attest to a real Fedora image's full symlink and drop-in inventory.

The older `*.cat-config` outputs are retained as source for the seed fixture
and for regression comparison with the former resolver.
