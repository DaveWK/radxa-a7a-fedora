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


def aic_path_pattern():
    with fixture() as root:
        f = root / "usr/lib/firmware/aic/aic8800d80/fw.bin.xz"
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


def main():
    case("aic: clean root", aic_clean_root)
    case("aic: missing root", aic_missing_root)
    case("aic: empty firmware dir", aic_empty_firmware_dir)
    case("aic: path pattern", aic_path_pattern)
    case("aic: manifest name under another directory", aic_manifest_name_elsewhere)
    case("aic: missing manifest", aic_manifest_missing)
    case("aic: manifest name with .zst suffix", aic_manifest_suffixes)
    if FAILURES:
        print(f"{len(FAILURES)} test(s) FAILED")
        return 1
    print("all devcard-policy tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
