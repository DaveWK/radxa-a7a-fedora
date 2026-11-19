#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for fedora/devcard-policy.py (the parsers and image-policy
checks behind mkdevcard.sh and verify-devcard.sh).

Every parser is exercised with fixtures, including the empty and missing
cases.  Run: python3 -I fedora/tests/devcard-policy.py
"""

import importlib.util
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

sys.dont_write_bytecode = True
here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "devcard_policy", here.parent / "devcard-policy.py"
)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

FAILURES = []


def case(name, fn):
    try:
        fn()
    except AssertionError as exc:
        FAILURES.append(f"{name}: {exc}")
        print(f"FAIL {name}: {exc}")
    except Exception as exc:  # noqa: BLE001 - a test error is a failure
        FAILURES.append(f"{name}: {exc!r}")
        print(f"FAIL {name}: {exc!r}")
    else:
        print(f"ok   {name}")


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix="a7a-policy-") as tmp:
        yield Path(tmp)


MANIFEST = """\
# name bytes sha256 role
fw_patch_table_8800d80_u02.bin 1384 abc required
fmacfw_8800d80_u02.bin 358072 def required
"""


def aic_clean_root():
    with fixture() as root:
        assert policy.aic_find(root) == []


def aic_missing_root():
    with fixture() as root:
        assert policy.aic_find(root / "nope") == []


def aic_empty_firmware_dir():
    with fixture() as root:
        (root / "usr/lib/firmware").mkdir(parents=True)
        assert policy.aic_find(root) == []


def aic_linux_firmware_allowed():
    # Fedora's standard linux-firmware package is fine (Dave 2026-11-19).
    with fixture() as root:
        write(root / "usr/share/cubie-a7a/aic8800-d80-usb.manifest", MANIFEST)
        f = root / "usr/lib/firmware/aic/aic8800d80/fw_patch_table_8800d80_u02.bin.xz"
        write(f, "")
        assert policy.aic_find(root) == []


def aic_override_dir_rejected():
    with fixture() as root:
        f = root / "usr/lib/firmware/aic8800_fw/USB/aic8800D80/fw.bin"
        write(f, "")
        assert [str(p) for p in policy.aic_find(root)] == [str(f)]


def aic_stray_aic8800_path_rejected():
    with fixture() as root:
        f = root / "usr/lib/firmware/elsewhere/aic8800d80.bin"
        write(f, "")
        assert [str(p) for p in policy.aic_find(root)] == [str(f)]


def aic_manifest_name_elsewhere():
    with fixture() as root:
        write(root / "usr/share/cubie-a7a/aic8800-d80-usb.manifest", MANIFEST)
        f = root / "usr/lib/firmware/unrelated/fw_patch_table_8800d80_u02.bin"
        write(f, "")
        assert [str(p) for p in policy.aic_find(root)] == [str(f)]


def aic_manifest_missing():
    with fixture() as root:
        f = root / "usr/lib/firmware/unrelated/fw_patch_table_8800d80_u02.bin"
        write(f, "")
        # No manifest: only the path pattern applies, and this name is not one.
        assert policy.aic_find(root) == []


def aic_manifest_suffixes():
    with fixture() as root:
        write(root / "usr/share/cubie-a7a/aic8800-d80-usb.manifest", MANIFEST)
        f = root / "usr/lib/firmware/unrelated/fmacfw_8800d80_u02.bin.zst"
        write(f, "")
        assert [str(p) for p in policy.aic_find(root)] == [str(f)]


REPART_UNIT = "usr/lib/systemd/system/systemd-repart.service"
REPART_DROPIN = (
    "etc/systemd/system/systemd-repart.service.d/10-cubie-a7a-no-discard.conf"
)
GOOD_DROPIN = "[Service]\nExecStart=\nExecStart=systemd-repart --discard=no\n"


def build_repart_root(root, dropin=GOOD_DROPIN, etc_unit=None):
    write(root / REPART_UNIT, "[Service]\nExecStart=systemd-repart\n")
    if dropin is not None:
        write(root / REPART_DROPIN, dropin)
    if etc_unit is not None:
        p = root / "etc/systemd/system/systemd-repart.service"
        p.parent.mkdir(parents=True, exist_ok=True)
        if etc_unit == "/dev/null":
            p.symlink_to("/dev/null")
        else:
            p.write_text(etc_unit)


def repart_good_root():
    with fixture() as root:
        build_repart_root(root)
        ok, problems = policy.repart_root_ok(root)
        assert ok, problems


def repart_overlay_drops_dropin():
    # The fixture overlay scenario: the unit is there, the drop-in is gone.
    with fixture() as root:
        build_repart_root(root, dropin=None)
        ok, problems = policy.repart_root_ok(root)
        assert not ok, "a missing no-discard drop-in must fail the build check"
        assert any("systemd-repart.service" in p for p in problems), problems


def repart_overlay_replaces_dropin():
    with fixture() as root:
        build_repart_root(
            root,
            dropin="[Service]\nExecStart=\nExecStart=systemd-repart --discard=yes\n",
        )
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "a --discard=yes drop-in must fail"


def repart_other_dropin_sets_execstart():
    with fixture() as root:
        build_repart_root(root)
        write(
            root / "etc/systemd/system/systemd-repart.service.d/20-evil.conf",
            "[Service]\nExecStart=systemd-repart --discard=yes\n",
        )
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "another drop-in setting ExecStart must fail"


def repart_etc_unit_override():
    with fixture() as root:
        build_repart_root(root, etc_unit="[Service]\nExecStart=systemd-repart\n")
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "a regular-file /etc unit override must fail"


def repart_masked_unit_ok():
    with fixture() as root:
        build_repart_root(root, etc_unit="/dev/null")
        ok, problems = policy.repart_root_ok(root)
        assert ok, problems


def repart_conf_without_unit():
    with fixture() as root:
        write(root / "etc/repart.d/50-root.conf", "[Partition]\nType=root\n")
        ok, problems = policy.repart_root_ok(root)
        assert not ok, "repart.d without systemd-repart.service must fail"


def repart_initramfs_cases():
    ok, _ = policy.repart_initramfs_ok("usr/lib/modules/x\n")
    assert ok, "an initramfs without systemd-repart is fine"
    ok, _ = policy.repart_initramfs_ok(
        "usr/lib/systemd/system/systemd-repart.service\n"
        "usr/lib/systemd/system/systemd-repart.service.d/10-cubie-a7a-no-discard.conf\n"
    )
    assert ok, "an initramfs with the drop-in is fine"
    ok, problem = policy.repart_initramfs_ok(
        "usr/lib/systemd/system/systemd-repart.service\n"
    )
    assert not ok, "an initramfs with systemd-repart and no drop-in must fail"
    assert "drop-in" in problem


def main():
    case("aic: clean root", aic_clean_root)
    case("aic: missing root", aic_missing_root)
    case("aic: empty firmware dir", aic_empty_firmware_dir)
    case("aic: linux-firmware files allowed", aic_linux_firmware_allowed)
    case("aic: override dir rejected", aic_override_dir_rejected)
    case("aic: stray aic8800 path rejected", aic_stray_aic8800_path_rejected)
    case("aic: manifest name under another directory", aic_manifest_name_elsewhere)
    case("aic: missing manifest", aic_manifest_missing)
    case("aic: manifest name with .zst suffix", aic_manifest_suffixes)
    case("repart: good root", repart_good_root)
    case("repart: overlay drops the drop-in", repart_overlay_drops_dropin)
    case("repart: overlay replaces the drop-in", repart_overlay_replaces_dropin)
    case("repart: another drop-in sets ExecStart", repart_other_dropin_sets_execstart)
    case("repart: /etc unit override", repart_etc_unit_override)
    case("repart: masked unit", repart_masked_unit_ok)
    case("repart: repart.d without the unit", repart_conf_without_unit)
    case("repart: initramfs listings", repart_initramfs_cases)
    if FAILURES:
        print(f"{len(FAILURES)} test(s) FAILED")
        return 1
    print("all devcard-policy tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
