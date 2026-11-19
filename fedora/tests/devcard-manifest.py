#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for fedora/devcard-manifest.py: the exact build manifest and its
verify, on a synthetic disk image built with the real tooling (mkfs.fat,
mkfs.ext4, mcopy, sfdisk). The write side records the build, the verify side
recomputes it and refuses any difference, named. Run:
python3 -I fedora/tests/devcard-manifest.py
"""

import hashlib
import runpy
import struct
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

sys.dont_write_bytecode = True
here = Path(__file__).resolve().parent
TOP = here.parent.parent
MANIFEST_PY = TOP / "fedora" / "devcard-manifest.py"
API = runpy.run_path(str(MANIFEST_PY))
PROFILE = ["--boot-modes", "protective", "--grow-root", "no", "--first-boot", ""]
ROOT_LBA = 163840
ESP_LBA = 32768
SECTOR = 512


FAILURES = []
ONLY = {n for n in os.environ.get("A7A_TEST_ONLY", "").split(",") if n}


def case(name, fn):
    if ONLY and fn.__name__ not in ONLY:
        return
    try:
        fn()
    except AssertionError as exc:
        FAILURES.append(f"{name}: {exc}")
        print(f"FAIL {name}: {exc}")
    except Exception as exc:
        FAILURES.append(f"{name}: {exc!r}")
        print(f"FAIL {name}: {exc!r}")
    else:
        print(f"ok   {name}")


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix="a7a-manifest-") as tmp:
        yield Path(tmp)


def run(*argv, env=None, shell=False):
    return subprocess.run(
        (
            [str(MANIFEST_PY.with_name("verify-devcard.sh")), *argv]
            if shell
            else [sys.executable, "-I", str(MANIFEST_PY), *argv]
        ),
        capture_output=True,
        text=True,
        env=env,
    )


def require(result, rc, word=""):
    assert result.returncode == rc and word in result.stderr, result
    assert "Traceback" not in result.stderr, result.stderr


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sudo_free(*args):
    return subprocess.run(args, check=True, capture_output=True)


def build_image(tmp):
    """A synthetic dev card: dtb shim/grub ESP, a root with an initramfs, one RPM."""
    esp = tmp / "esp"
    for d in ("efi/boot", "efi/fedora", "dtb/allwinner"):
        (esp / d).mkdir(parents=True)
    for rel in (
        "efi/boot/bootaa64.efi",
        "efi/boot/fbaa64.efi",
        "efi/fedora/bootaa64.csv",
        "efi/fedora/grub.cfg",
        "efi/fedora/grubaa64.efi",
        "efi/fedora/mmmaa64.efi",
        "efi/fedora/shim.efi",
        "efi/fedora/shimaa64.efi",
    ):
        (esp / rel).write_bytes(b"x")
    dtb_bytes = b"\xd0\x0d\xfe\xed fake dtb\n"
    (esp / "dtb/allwinner/sun60i-a733-cubie-a7a.dtb").write_bytes(dtb_bytes)
    (esp / "dtb/allwinner/sun60i-a733-cubie-a7a.dtb.cubie-a7a-dtb").write_bytes(
        (hashlib.sha256(dtb_bytes).hexdigest() + "\n").encode()
    )

    root = tmp / "root"
    for d in ("boot", "var/lib/cubie-a7a", "usr/lib/cubie-a7a/dtb"):
        (root / d).mkdir(parents=True)
    (root / "boot/initramfs-7.2.10-200.fc45.aarch64.img").write_bytes(
        b"fake-initramfs-bytes"
    )
    (root / "var/lib/cubie-a7a/firmware-dtb-version").write_bytes(b"0\n")
    (root / "usr/lib/cubie-a7a/dtb/VERSION").write_bytes(b"8\n")

    rpms = tmp / "rpms"
    (rpms / "noarch").mkdir(parents=True)
    rpm1 = rpms / "noarch/cubie-a7a-dtb-1.0-0.noarch.rpm"
    rpm1.write_bytes(b"fake dtb rpm bytes")
    records = [
        {
            "package": "cubie-a7a-dtb",
            "nevra": "cubie-a7a-dtb-1.0-0.noarch",
            "arch": "noarch",
            "path": str(rpm1),
            "sha256": hashlib.sha256(rpm1.read_bytes()).hexdigest(),
        }
    ]

    esp_img = tmp / "esp.img"
    root_img = tmp / "root.img"
    subprocess.run(
        ["mkfs.fat", "-F", "32", "-n", "EFI", "-C", str(esp_img), str(64 * 1024)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["mcopy", "-s", "-p", "-m", "-i", str(esp_img), str(esp / "dtb"), "::"],
        check=True,
    )
    subprocess.run(
        ["mcopy", "-s", "-p", "-m", "-i", str(esp_img), "efi", "::"],
        check=True,
        cwd=str(esp),
    )
    subprocess.run(["truncate", "-s", "64M", str(root_img)], check=True)
    subprocess.run(
        ["mkfs.ext4", "-q", "-L", "Fedora45-root", "-d", str(root), str(root_img)],
        check=True,
        capture_output=True,
    )

    img = tmp / "dev.img"
    subprocess.run(["truncate", "-s", "192M", str(img)], check=True)
    subprocess.run(
        ["sfdisk", "--quiet", "--no-reread", "--no-tell-kernel", str(img)],
        input=(
            "label: gpt\n"
            "first-lba: 34\n"
            'start=32768, size=131072, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI"\n'
            'start=163840, size=131072, type=B921B045-1DF0-41C3-AF44-4C6F280D3FAE, name="root"\n'
        ),
        text=True,
        check=True,
    )
    subprocess.run(
        [
            "dd",
            "if=" + str(esp_img),
            "of=" + str(img),
            "bs=1M",
            "seek=16",
            "conv=notrunc,sparse",
            "status=none",
        ],
        check=True,
    )
    subprocess.run(
        [
            "dd",
            "if=" + str(root_img),
            "of=" + str(img),
            "bs=512",
            "seek=163840",
            "conv=notrunc,sparse",
            "status=none",
        ],
        check=True,
    )
    return img, root, esp, json.dumps(records)


def seal_manifest(img, root, esp, rpms, manifest, *args):
    output = run("write", img, root, rpms, manifest, "--esp-dir", esp, *PROFILE, *args)
    require(output, 0)
    assert output.stdout.strip() == sha(manifest)
    return output.stdout.strip()


def manifest_roundtrip():
    with fixture() as tmp:
        img, root, esp, rpms = build_image(tmp)
        manifest = tmp / "manifest.json"
        expected = seal_manifest(img, root, esp, rpms, manifest)
        assert json.loads(manifest.read_text())["profile"] == {
            "boot_modes": "protective",
            "first_boot": "",
            "grow_root": "no",
        }
        env = os.environ.copy()
        env.pop("MAIN_BIN", None)
        require(
            run(
                img, manifest, "--expect-manifest-sha256", expected, shell=True, env=env
            ),
            0,
        )
        require(run(img, manifest, shell=True, env=env), 2, "--expect-manifest-sha256")
        require(
            run(
                "verify",
                img,
                manifest,
                "--expect-manifest-sha256",
                expected,
                env={**env, "PATH": str(tmp)},
            ),
            1,
            "required verifier tool missing: sfdisk",
        )
        env.pop("TMPDIR", None)
        require(
            run("verify", img, manifest, "--expect-manifest-sha256", expected, env=env),
            1,
            "TMPDIR",
        )
        require(run("check-fat", tmp / "esp.img"), 0)
        bad_fat = tmp / "not-fat.img"
        bad_fat.write_bytes(b"garbage" * 128)
        require(run("check-fat", bad_fat), 1, "packed ESP fsck.fat -n")


def patch_byte(path, offset):
    with path.open("r+b") as f:
        f.seek(offset)
        byte = f.read(1)
        assert byte
        f.seek(offset)
        f.write(bytes([byte[0] ^ 1]))
    return byte


def write_region(path, offset, data):
    with path.open("r+b") as f:
        f.seek(offset)
        f.write(data)


def pack_part(img, part, offset):
    with img.open("r+b") as dst, part.open("rb") as src:
        dst.seek(offset * SECTOR)
        shutil.copyfileobj(src, dst)


def reset_outer(img, data):
    data = json.loads(json.dumps(data))
    data["image_sha256"] = sha(img)
    for part in data["gpt"]["partitions"]:
        part["sha256"] = API["_sha256_region"](
            img, part["start"] * SECTOR, part["size"] * SECTOR
        )
    return data


def manifest_refuses_differences():
    with fixture() as tmp:
        img, root, esp, rpms = build_image(tmp)
        manifest = tmp / "manifest.json"
        original_digest = seal_manifest(img, root, esp, rpms, manifest)
        original = json.loads(manifest.read_text())

        def verify(m=manifest, expected=original_digest, image=img):
            return run("verify", image, m, "--expect-manifest-sha256", expected)

        for off, name in (
            (ESP_LBA * SECTOR + 200000, "partition[0].sha256"),
            (ROOT_LBA * SECTOR + 100000, "partition[1].sha256"),
            (256 * SECTOR + 3, "gap mismatch"),
            (img.stat().st_size - 128 * SECTOR, "image_sha256"),
        ):
            old = patch_byte(img, off)
            require(verify(), 1, name)
            write_region(img, off, old)

        swapped = tmp / "swapped.json"
        off = img.stat().st_size - 128 * SECTOR
        old = patch_byte(img, off)
        digest = seal_manifest(img, root, esp, rpms, swapped)
        require(verify(swapped, digest), 0)
        require(verify(swapped), 1, "expected manifest sha256")
        write_region(img, off, old)

        edited = tmp / "edited.json"
        for field in ("dtb", "rpms", "initramfs", "profile", "firmware"):
            data = json.loads(manifest.read_text())
            del data[field]
            edited.write_text(json.dumps(data))
            require(verify(edited, sha(edited)), 1, field)
        mutations = (
            (lambda d: d["dtb"].update(unknown=True), "unknown"),
            (lambda d: d["gpt"]["partitions"][0].update(index=7), ".index"),
            (lambda d: d["gpt"].update(sectorsize=4096), "512-byte sectors"),
            (lambda d: d.update(initramfs=[]), "initramfs"),
            (lambda d: d["initramfs"].append(d["initramfs"][0]), "duplicate"),
            (
                lambda d: d["initramfs"][0].update(path="boot/../initramfs-x.img"),
                "initramfs.path",
            ),
            (lambda d: d["initramfs"][0].update(sha256="0" * 64), "initramfs boot/"),
            (
                lambda d: d["dtb"].update(firmware_stamp_sha256="0" * 64),
                "dtb.firmware_stamp_sha256",
            ),
        )
        for change, label in mutations:
            data = json.loads(manifest.read_text())
            change(data)
            edited.write_text(json.dumps(data))
            require(verify(edited, sha(edited)), 1, label)
        for raw in (b"[]", b"{", b'{"schema":2,"schema":2}', b"{\xff}"):
            edited.write_bytes(raw)
            require(verify(edited, sha(edited)), 1, "manifest")
        # Hold trusted per-file expectations fixed; recompute only outer hashes
        # to prove that each targeted filesystem check itself sees the mutation.
        esp_part = tmp / "esp-mut.img"
        for mutation in ("changed", "added", "missing"):
            shutil.copyfile(tmp / "esp.img", esp_part)
            payload = tmp / "replacement.efi"
            payload.write_bytes(b"replacement")
            path = "::/efi/fedora/shim.efi"
            if mutation == "changed":
                sudo_free("mcopy", "-o", "-i", esp_part, payload, path)
            if mutation == "added":
                sudo_free("mcopy", "-i", esp_part, payload, "::/efi/fedora/extra.efi")
            if mutation == "missing":
                sudo_free("mdel", "-i", esp_part, path)
            pack_part(img, esp_part, ESP_LBA)
            edited.write_text(json.dumps(reset_outer(img, original)))
            name = "extra.efi" if mutation == "added" else "shim.efi"
            require(verify(edited, sha(edited)), 1, f"esp.files efi/fedora/{name}")
        shutil.copyfile(tmp / "esp.img", esp_part)
        marker = tmp / "marker"
        marker.write_text("0" * 64 + "\n")
        sudo_free("mcopy", "-o", "-i", esp_part, marker, f'::/{API["ESP_DTB_MARK"]}')
        pack_part(img, esp_part, ESP_LBA)
        data = reset_outer(img, original)
        for entry in data["esp"]["files"]:
            if entry["path"] == API["ESP_DTB_MARK"]:
                entry["sha256"] = sha(marker)
        edited.write_text(json.dumps(data))
        require(verify(edited, sha(edited)), 1, "dtb ESP payload marker")
        pack_part(img, tmp / "esp.img", ESP_LBA)
        root_part = tmp / "root-mut.img"
        for which, command, label in (
            ("missing", f'rm /{API["FW_DTB_STAMP"]}', API["FW_DTB_STAMP"]),
            ("edited", f'rm /{API["PKG_DTB_VERSION"]}', "dtb.package_stamp_sha256"),
        ):
            shutil.copyfile(tmp / "root.img", root_part)
            sudo_free("debugfs", "-w", "-R", command, root_part)
            if which == "edited":
                (tmp / "stamp").write_text("42\n")
                sudo_free(
                    "debugfs",
                    "-w",
                    "-R",
                    f'write {tmp / "stamp"} /{API["PKG_DTB_VERSION"]}',
                    root_part,
                )
            pack_part(img, root_part, ROOT_LBA)
            edited.write_text(json.dumps(reset_outer(img, original)))
            require(verify(edited, sha(edited)), 1, label)
        pack_part(img, tmp / "root.img", ROOT_LBA)
        require(verify(), 0)


def receipt_bindings():
    with fixture() as tmp:
        img, root, esp, rpms = build_image(tmp)
        manifest = tmp / "manifest.json"
        expected = seal_manifest(img, root, esp, rpms, manifest)
        data = json.loads(manifest.read_text())
        selection = tmp / "rpm-snapshot.json"
        selection.write_text(
            json.dumps({"run_id": "test-run", "rpms": json.loads(rpms)})
        )
        initramfs = tmp / "initramfs-digests.json"
        initramfs.write_text(
            json.dumps({Path(e["path"]).name: e["sha256"] for e in data["initramfs"]})
        )
        receipt = tmp / "receipt.json"
        source = subprocess.check_output(
            ["git", "--no-optional-locks", "-C", TOP, "rev-parse", "HEAD"], text=True
        ).strip()
        args = [
            img,
            manifest,
            receipt,
            selection,
            initramfs,
            *PROFILE,
            "--source-commit",
            source,
            "--run-id",
            "test-run",
            "--started-utc",
            "2026-11-19T01:02:03Z",
            "--finished-utc",
            "2026-11-19T01:04:05Z",
            "--expect-manifest-sha256",
            expected,
            "--expect-snapshot-sha256",
            sha(selection),
        ]
        require(run("seal", *args), 0)
        require(run("check-receipt", *args), 0)
        original = json.loads(receipt.read_text())
        for field, change in (
            ("source_commit", lambda r: r.update(source_commit="f" * 40)),
            ("profile", lambda r: r["profile"].update(grow_root="yes")),
            ("dtb", lambda r: r["dtb"].update(package_stamp_sha256="0" * 64)),
        ):
            item = json.loads(json.dumps(original))
            change(item)
            receipt.write_text(json.dumps(item))
            require(run("check-receipt", *args), 1, f"receipt.{field}")
        changed = json.loads(manifest.read_text())
        changed["rpms"][0]["sha256"] = "0" * 64
        manifest.write_text(json.dumps(changed))
        changed_args = [sha(manifest) if arg == expected else arg for arg in args]
        require(run("check-receipt", *changed_args), 1, "manifest.rpms")
        require(run("seal", *changed_args), 1, "manifest.rpms")
        selection.write_text("[]\n")
        require(run("check-receipt", *changed_args), 1, "rpm-snapshot.json sha256")


def firmware_binding():
    with fixture() as tmp:
        img, root, esp, rpms = build_image(tmp)
        firmware = tmp / "firmware.bin"
        main_bin = tmp / "main.bin"
        main = b"A7AFWLOG" + struct.pack("<III", 0x52800040, 0x72B04000, 0x52A80280)
        main_bin.write_bytes(main)
        firmware.write_bytes(b"0123eGON.BT0" + main + b"oreboot,firmware-log")
        seek = 300
        write_region(img, seek * SECTOR, firmware.read_bytes())
        manifest = tmp / "manifest.json"
        expected = seal_manifest(
            img,
            root,
            esp,
            rpms,
            manifest,
            "--firmware-sha256",
            sha(firmware),
            "--firmware-seek",
            str(seek),
            "--firmware-size",
            str(firmware.stat().st_size),
        )
        base = ["verify", img, manifest, "--expect-manifest-sha256", expected]
        require(run(*base, "--firmware", firmware, "--main-bin", main_bin), 0)
        require(run(*base, "--firmware", tmp / "missing.bin"), 1, "firmware: missing")
        require(
            run(*base, "--firmware", firmware, "--main-bin", tmp / "missing.bin"),
            1,
            "MAIN_BIN: missing",
        )
        main_bin.write_bytes(main + b"unembedded")
        require(
            run(*base, "--firmware", firmware, "--main-bin", main_bin),
            1,
            "not embedded",
        )
        data = json.loads(manifest.read_text())
        data["firmware"]["seek_lba"] -= 1
        manifest.write_text(json.dumps(data))
        require(
            run("verify", img, manifest, "--expect-manifest-sha256", sha(manifest)),
            1,
            "firmware.sha256 at recorded seek",
        )


def main():
    case(
        "manifest and CLI: roundtrip, mandatory pin/scratch/tools, FAT",
        manifest_roundtrip,
    )
    case(
        "manifest: regions, pair swaps, schema, ESP, initramfs and DTB stamp reds",
        manifest_refuses_differences,
    )
    case(
        "receipt: exact source, profile, inputs and DTB record binding",
        receipt_bindings,
    )
    case("firmware: seek, required requested files and embedded main", firmware_binding)
    if FAILURES:
        print(f"{len(FAILURES)} test(s) FAILED")
        return 1
    print("all devcard-manifest tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
