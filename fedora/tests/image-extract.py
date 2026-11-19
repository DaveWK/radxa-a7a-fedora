#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for fedora/image-extract.py and IMG-bound verification.

Builds a small GPT disk image with ESP and ext4 root (including post-overlay
content and a GROW_ROOT=no masked initramfs/unit layout), then checks that
partition and root extraction read IMG's own bytes without trusting or
requiring the staging directory and without modifying IMG.
Run: python3 -I fedora/tests/image-extract.py
"""

import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
here = Path(__file__).resolve().parent
tool = here.parent / "image-extract.py"
spec = importlib.util.spec_from_file_location("image_extract", tool)
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)

policy_spec = importlib.util.spec_from_file_location(
    "devcard_policy", here.parent / "devcard-policy.py"
)
policy = importlib.util.module_from_spec(policy_spec)
policy_spec.loader.exec_module(policy)

FAILURES = []
ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
ROOT_TYPE = "B921B045-1DF0-41C3-AF44-4C6F280D3FAE"


def case(name, fn):
    try:
        fn()
    except AssertionError as exc:
        FAILURES.append(f"{name}: {exc}")
        print(f"FAIL {name}: {exc}")
    except Exception as exc:  # a test error is a failure
        FAILURES.append(f"{name}: {exc!r}")
        print(f"FAIL {name}: {exc!r}")
    else:
        print(f"ok   {name}")


def run(*args):
    return subprocess.run(
        [sys.executable, "-I", str(tool), *map(str, args)],
        capture_output=True,
        text=True,
    )


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _cpio(tree, out_img):
    entries = sorted(p.relative_to(tree).as_posix() for p in tree.rglob("*"))
    res = subprocess.run(
        ["cpio", "-o", "-H", "newc", "--quiet"],
        input=("\n".join(entries) + ("\n" if entries else "")).encode(),
        cwd=tree,
        capture_output=True,
        check=True,
    )
    out_img.write_bytes(res.stdout)


def make_image(root, overlay_repart_initramfs=False):
    """Build a GPT disk image with ESP + ext4 root containing post-overlay files."""
    stage = root / "stage"
    (stage / "usr/lib/firmware/aic/aic8800d80").mkdir(parents=True)
    (stage / "usr/lib/firmware/aic/aic8800d80/fw.bin.xz").write_text("fedora")
    (stage / "etc/systemd/system").mkdir(parents=True)
    (stage / "etc/motd").write_text("staged\n")
    marker = stage / "opt/vendor/runtime.bin"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("overlay")

    # Build a real initramfs inside /boot to test post-overlay GROW_ROOT=no checks.
    initrd_src = root / "initrd-src"
    (initrd_src / "usr/lib/modules").mkdir(parents=True)
    (initrd_src / "usr/lib/modules/placeholder").write_text("ok\n")
    if overlay_repart_initramfs:
        (initrd_src / "usr/lib/systemd/system").mkdir(parents=True)
        (initrd_src / "usr/lib/systemd/system/systemd-repart.service").write_text(
            "[Service]\nExecStart=systemd-repart\n"
        )
    (stage / "boot").mkdir(parents=True, exist_ok=True)
    _cpio(initrd_src, stage / "boot/initramfs-7.4.0.img")

    root_img = root / "root.part"
    subprocess.run(["truncate", "-s", "16M", str(root_img)], check=True)
    subprocess.run(
        ["mkfs.ext4", "-q", "-F", "-L", "root", "-d", str(stage), str(root_img)],
        check=True,
        stderr=subprocess.DEVNULL,
    )
    # Match this rootless test user's ownership even on mkfs-created entries,
    # so rdump MUST succeed without an ownership-error exception.
    for entry in ("/", "/lost+found"):
        for field, value in (("uid", os.getuid()), ("gid", os.getgid())):
            subprocess.run(
                ["debugfs", "-w", "-R", f"sif {entry} {field} {value}", root_img],
                check=True,
                capture_output=True,
            )
    esp_img = root / "esp.part"
    subprocess.run(["truncate", "-s", "1M", str(esp_img)], check=True)
    subprocess.run(
        ["mkfs.fat", "-F", "32", "-n", "EFI", str(esp_img)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    disk = root / "disk.img"
    subprocess.run(["truncate", "-s", "64M", str(disk)], check=True)
    esp_start, esp_sectors = 32768, 2048
    root_start = esp_start + esp_sectors
    root_sectors = os.path.getsize(root_img) // 512
    subprocess.run(
        ["sfdisk", "--quiet", "--no-reread", "--no-tell-kernel", str(disk)],
        input=(
            "label: gpt\n"
            f"start={esp_start}, size={esp_sectors}, type={ESP_TYPE}, name=EFI\n"
            f"start={root_start}, size={root_sectors}, type={ROOT_TYPE}, name=root\n"
        ),
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    for src, start in ((esp_img, esp_start), (root_img, root_start)):
        with open(disk, "r+b") as out, open(src, "rb") as infile:
            out.seek(start * 512)
            shutil.copyfileobj(infile, out, length=os.path.getsize(src))
    return disk, root_img, esp_img


def test_partitions():
    with tempfile.TemporaryDirectory(prefix="a7a-extract-") as td:
        disk, _, _ = make_image(Path(td))
        result = run("partitions", disk)
        assert result.returncode == 0, result.stderr
        rows = result.stdout.splitlines()
        assert len(rows) == 2, rows
        index, ptype, start, _ = rows[1].split()
        assert (index, ptype, int(start)) == ("1", ROOT_TYPE, 34816), rows


def test_extract_partition_bound_to_image():
    with tempfile.TemporaryDirectory(prefix="a7a-extract-") as td:
        root = Path(td)
        disk, root_img, esp_img = make_image(root)
        before = sha256(disk)
        got_root = root / "out-root.img"
        got_esp = root / "out-esp.img"
        assert run("extract-partition", disk, got_root, ROOT_TYPE[:8]).returncode == 0
        assert run("extract-partition", disk, got_esp, ESP_TYPE[:8]).returncode == 0
        assert sha256(got_root) == sha256(root_img)
        assert sha256(got_esp) == sha256(esp_img)
        assert sha256(disk) == before, "extraction must not modify IMG"


def test_extract_root_ignores_mutated_or_deleted_staging():
    with tempfile.TemporaryDirectory(prefix="a7a-extract-") as td:
        root = Path(td)
        disk, _, _ = make_image(root)
        # Mutate and delete the staging directory after IMG is built.
        (root / "stage/etc/motd").write_text("tampered-staging\n")
        shutil.rmtree(root / "stage")
        part = root / "root.part"
        assert run("extract-partition", disk, part, ROOT_TYPE).returncode == 0
        dest = root / "tree"
        assert run("extract-root", part, dest).returncode == 0
        assert (dest / "etc/motd").read_text() == "staged\n"
        assert (dest / "opt/vendor/runtime.bin").read_text() == "overlay"


def test_grow_root_no_catches_post_overlay_initramfs_from_img():
    # Even if a stale pre-overlay listing existed, extracting IMG and checking
    # its initramfs with --forbid-repart catches an overlay-injected repart unit.
    with tempfile.TemporaryDirectory(prefix="a7a-extract-") as td:
        root = Path(td)
        disk, _, _ = make_image(root, overlay_repart_initramfs=True)
        part = root / "root.part"
        dest = root / "tree"
        assert run("extract-partition", disk, part, ROOT_TYPE).returncode == 0
        assert run("extract-root", part, dest).returncode == 0
        ok, problems = policy.repart_initramfs_ok(
            dest / "boot/initramfs-7.4.0.img", forbid_repart=True
        )
        assert (
            not ok
        ), "post-overlay initramfs with systemd-repart must fail GROW_ROOT=no"
        assert any("systemd-repart" in p for p in problems), problems


def test_silent_partial_extraction():
    with tempfile.TemporaryDirectory(prefix="a7a-extract-") as td:
        work = Path(td)
        _, image, _ = make_image(work)
        wrapper = work / "bin/debugfs"
        wrapper.parent.mkdir()
        wrapper.write_text(
            "#!/bin/sh\n"
            f'"{shutil.which("debugfs")}" "$@" || exit $?\n'
            'if [ "$2" = "rdump / ." ]; then : > etc/motd; fi\n'
        )
        wrapper.chmod(0o755)
        res = subprocess.run(
            [sys.executable, "-I", str(tool), "extract-root", image, work / "out"],
            env={**os.environ, "PATH": f"{wrapper.parent}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )
        assert res.returncode != 0 and "size" in res.stderr, res.stderr


def test_verifier_rejects_damaged_inode():
    with tempfile.TemporaryDirectory(prefix="a7a-verifier-") as td:
        work = Path(td)
        disk, root, _ = make_image(work)

        # Flip one inode checksum bit, leaving GPT, the directory tree and
        # unrelated files intact. The fixture has ext4 metadata checksums.
        def info(command):
            return subprocess.check_output(
                ["debugfs", "-R", command, root], stderr=subprocess.DEVNULL, text=True
            )

        block, offset = re.search(
            r"located at block (\d+), offset (0x[0-9a-f]+)", info("imap /etc/motd")
        ).groups()
        blocksize = int(re.search(r"Block size:\s+(\d+)", info("stats")).group(1))
        pos = 34816 * 512 + int(block) * blocksize + int(offset, 16) + 0x7C
        with disk.open("r+b") as image:
            image.seek(pos)
            value = image.read(1)[0]
            image.seek(pos)
            image.write(bytes([value ^ 1]))
        # Sentinel stops even a broken verifier at the first post-extraction
        # operation. A generic later failure is NOT evidence for this gate.
        sentinel = work / "bin/rpm"
        sentinel.parent.mkdir()
        sentinel.write_text("#!/bin/sh\necho reached-rpm >&2\nexit 1\n")
        sentinel.chmod(0o755)
        result = subprocess.run(
            [here.parent / "verify-devcard.sh", disk, work / "verify"],
            env={**os.environ, "PATH": f"{sentinel.parent}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )
        assert (
            result.returncode != 0
            and "cannot read the root filesystem" in result.stderr
            and "reached-rpm" not in result.stderr
        ), result.stderr


def main():
    case(
        "extract-root: reject a silent short extraction", test_silent_partial_extraction
    )
    case(
        "verify-devcard rejects a corrupted inode before querying RPM",
        test_verifier_rejects_damaged_inode,
    )
    case("partitions: GPT rows", test_partitions)
    case(
        "extract-partition: bytes come from IMG", test_extract_partition_bound_to_image
    )
    case(
        "extract-root: ignores mutated/deleted staging tree",
        test_extract_root_ignores_mutated_or_deleted_staging,
    )
    case(
        "GROW_ROOT=no: catches post-overlay initramfs from IMG",
        test_grow_root_no_catches_post_overlay_initramfs_from_img,
    )
    if FAILURES:
        print(f"{len(FAILURES)} test(s) FAILED")
        return 1
    print("all image-extract tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
