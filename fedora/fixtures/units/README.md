# Staged systemd inventory capture

No production pins are supplied yet. The separately gated task-000147
capture uses `DEVCARD_INVENTORY_CAPTURE=1`. It saves inventories, normalized
unit results and raw manager dumps under `$OUT.inventory/` and exits nonzero
before packing.

After independent review, pin each selected mode as
`repart-{yes,no,initramfs}.unit.txt` and `repart-{yes,no,initramfs}.inventory.json`.
For example, for `GROW_ROOT=yes`, review `unit-root.txt` and
`inventory-root.json` and pin them under `repart-yes`. If initramfs inventories
differ across supported profiles, do not silently bless or union them.
A normal build requires both pins for each checked mode and exact equality.

The synthetic `fedora/tests/staged-systemd.py` fixtures exercise the real
loader but are not deployment pins.

The older `*.cat-config` outputs are retained as source for the seed fixture
and for regression comparison with the former resolver.
