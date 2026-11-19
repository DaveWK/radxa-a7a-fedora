#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic staged-tree integrity fixtures."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

FEDORA = Path(__file__).resolve().parent.parent
SCRIPT = [sys.executable, "-I", str(FEDORA / "initramfs-policy.py")]


def check(args, rc, want=None):
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == rc, (result.returncode, result.stdout, result.stderr)
    if want:
        assert want in result.stderr, result.stderr
    return result.stdout


def root_selection(work, source):
    # Run the real STAGE1 prologue and module loop through its fresh bash -s
    # boundary, omitting unrelated mount, DNF and dracut work.
    stage = source.split("<<'STAGE1'\n", 1)[1].split("\nSTAGE1\n", 1)[0]
    prologue = stage.split("pkgs=(); ex=()", 1)[0]
    marker = "    # Recheck root module ownership/depmod selection after overlays."
    start = stage.rindex("while IFS= read -r k; do\n", 0, stage.index(marker))
    end = stage.index('done <"$W/kernel.txt"\n', stage.index(marker))
    module_loop = stage[start:end] + 'done <"$W/kernel.txt"\n'
    root = work / "kernel-root"
    version = "7.4.fixture"
    config = root / "usr/lib/modules" / version / "config"
    extra = config.parent / "extra"
    extra.mkdir(parents=True)
    config.write_text("CONFIG_PINCTRL_SUN60I_A733=y\n")
    (work / "kernel.txt").write_text(f"{version}\n")
    for module in ("sun60i-a733-serdes", "sun60i-a733-pcie", "sun55i-pck600"):
        (extra / f"{module}.ko").touch()
    stubs = work / "stubs"
    stubs.mkdir()
    chroot = stubs / "chroot"
    chroot.write_text(r"""#!/usr/bin/env bash
[[ ! -v TMPDIR ]] || exit 98
[[ $1 == "$ROOT" ]] || exit 99
case "$2" in
modinfo)
    [[ $3 == -k && $5 == -n ]] || exit 99
    if [[ $6 == dwmac-sun55i && $MODE == wrong-selection ]]; then
        printf '/lib/modules/%s/kernel/%s.ko.zst\n' "$4" "$6"
    else
        printf '/lib/modules/%s/extra/%s.ko.zst\n' "$4" "$6"
    fi
    ;;
test)
    [[ $3 == -f && $4 == /lib/modules/*/extra/*.ko.zst && $MODE != missing-file ]]
    ;;
*) exit 99 ;;
esac
""")
    chroot.chmod(0o755)

    def launch(mode):
        return subprocess.run(
            ["bash", "-s", "--", "fixture-package", "--", "fixture-exclude"],
            input=prologue + module_loop,
            env={
                "PATH": f"{stubs}:{os.environ['PATH']}",
                "TMPDIR": str(work),
                "TOP": str(FEDORA.parent),
                "ROOT": str(root),
                "W": str(work),
                "MODE": mode,
            },
            capture_output=True,
            text=True,
        )

    good = launch("good")
    if good.returncode:
        sys.stderr.write(good.stderr)
        raise SystemExit(good.returncode)
    for mode in ("wrong-selection", "missing-file"):
        bad = launch(mode)
        assert bad.returncode == 1 and "board kmods incomplete" in bad.stderr, bad
    config.write_text("# pinctrl is not set\n")
    bad = launch("good")
    assert bad.returncode == 1 and "board kmods incomplete" in bad.stderr, bad


def cases(work):
    root = work / "root"
    bootdir = root / "boot"
    bootdir.mkdir(parents=True)
    kernels = work / "kernel.txt"
    kernels.write_text("fixture\n")
    good = bootdir / "initramfs-fixture.img"
    good.write_bytes(b"fixture initramfs bytes")
    check([*SCRIPT, "set", str(root), str(kernels)], 0)
    record = work / "digests.json"
    args = [str(root), str(kernels), str(record)]
    check([*SCRIPT, "capture-digest", *args], 0)
    check([*SCRIPT, "verify-digest", *args], 0)
    # In particular, valid zstd is not evidence of valid newc.
    compressed = subprocess.run(
        ["zstd", "-qc", "--check"],
        input=b"not a newc archive",
        capture_output=True,
        check=True,
    ).stdout
    good.write_bytes(compressed)
    check(["zstd", "-t", "--check", "--", str(good)], 0)
    good.write_bytes(compressed[:-1])
    check(["zstd", "-t", "--check", "--", str(good)], 1)
    good.write_bytes(b"replacement initramfs bytes")
    check([*SCRIPT, "verify-digest", *args], 1, "digest differs")
    extra = bootdir / "initramfs-extra.img"
    extra.write_bytes(b"extra")
    check([*SCRIPT, "set", str(root), str(kernels)], 1, "initramfs-extra.img")
    check([*SCRIPT, "overlay", str(root)], 1, "overlay writes an initramfs entry")
    extra.unlink()
    good.unlink()
    good.symlink_to("absent")
    check([*SCRIPT, "set", str(root), str(kernels)], 1, "not a regular file")

    overlay = work / "overlay"
    overlay.mkdir()
    check([*SCRIPT, "overlay", str(overlay)], 0)
    firmware = overlay / "usr/lib/firmware"
    firmware.mkdir(parents=True)
    (firmware / "replacement.bin").touch()
    check([*SCRIPT, "overlay", str(overlay)], 1, "overlay writes firmware")
    link_overlay = work / "link-overlay"
    link_overlay.mkdir()
    (link_overlay / "usr").symlink_to(overlay / "usr")
    check(
        [*SCRIPT, "overlay", str(link_overlay)], 1, "expected a real staged directory"
    )

    extra = root / "usr/lib/modules/fixture/extra"
    extra.mkdir(parents=True)
    args = [*SCRIPT, "root-modules", str(root), "fixture", "--board", "sun60i-a733-ccu"]
    check(args, 0)
    for name in ("pinctrl-sun60i-a733.ko", "aic-btusb.ko.zst"):
        bad = extra / name
        bad.touch()
        check(args, 1, "forbidden module")
        bad.unlink()
    stage = (FEDORA / "mkdevcard.sh").read_text()
    order = [
        'devcard-policy.py" aic-provenance',
        'env -u TMPDIR chroot "$ROOT" dracut --force',
        'initramfs-policy.py" capture-digest',
        'initramfs-policy.py" overlay',
        'cp -a --no-preserve=ownership "$OVERLAY"',
        '--report "$W/aic-provenance-final.tsv"',
        'cubie_check_root_kmods "$ROOT" "$k"',
        'initramfs-policy.py" verify-digest',
        "zstd -t --check --",
        "mkfs.ext4 -q",
    ]
    indexes = [stage.index(command) for command in order]
    assert indexes == sorted(indexes)
    assert stage.count('devcard-policy.py" aic-provenance') == 2
    assert "/usr/libexec/cubie-a7a/kernel check" not in stage
    root_selection(work, stage)
    print("staged initramfs paths, overlay veto and root module checks passed")


def main():
    with tempfile.TemporaryDirectory(prefix="a7a-initramfs-") as tmp:
        cases(Path(tmp))


if __name__ == "__main__":
    main()
