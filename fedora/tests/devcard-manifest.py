#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for fedora/devcard-manifest.py: the exact build manifest and its
verify, on a synthetic disk image built with the real tooling (mkfs.fat,
mkfs.ext4, mcopy, sfdisk). The write side records the build, the verify side
recomputes it and refuses any difference, named. Run:
python3 -I fedora/tests/devcard-manifest.py
"""

import hashlib
import importlib.util
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


def synthetic_pins(work):
    pins = work / "pins"
    pins.mkdir()
    for mode in ("yes", "no", "initramfs"):
        (pins / f"repart-{mode}.unit.txt").write_text("fixture\n")
        (pins / f"repart-{mode}.inventory.json").write_text(
            '{"schema":1,"entries":{}}\n'
        )
    return pins


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


def run(*argv):
    return subprocess.run(
        ["python3", "-I", str(MANIFEST_PY), *argv],
        capture_output=True,
        text=True,
    )


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


def _needed():
    for tool in ("mkfs.fat", "mkfs.ext4", "mcopy", "mdir", "sfdisk", "debugfs"):
        if shutil.which(tool) is None:
            return tool
    return None


def manifest_roundtrip():
    missing = _needed()
    if missing:
        print(f"  (skipped: {missing} absent)")
        return
    with fixture() as tmp:
        img, root, esp, rpms = build_image(tmp)
        em = tmp / "esp-model.json"
        r = run("esp-model", str(esp), str(em))
        assert r.returncode == 0, r.stderr
        manifest = tmp / "devcard-manifest.json"
        r = run(
            "write",
            str(img),
            str(root),
            str(rpms),
            str(synthetic_pins(tmp)),
            str(manifest),
            "--esp-model",
            str(em),
        )
        assert r.returncode == 0, r.stderr
        manifest_sha = r.stdout.strip()
        assert len(manifest_sha) == 64, manifest_sha
        assert manifest_sha == hashlib.sha256(manifest.read_bytes()).hexdigest()

        r = run("verify", str(img), str(manifest))
        assert r.returncode == 0, (r.stderr, r.stdout)


def manifest_refuses_differences():
    missing = _needed()
    if missing:
        print(f"  (skipped: {missing} absent)")
        return
    with fixture() as tmp:
        img, root, esp, rpms = build_image(tmp)
        em = tmp / "esp-model.json"
        run("esp-model", str(esp), str(em))
        manifest = tmp / "devcard-manifest.json"
        r = run(
            "write",
            str(img),
            str(root),
            str(rpms),
            str(synthetic_pins(tmp)),
            str(manifest),
            "--esp-model",
            str(em),
        )
        assert r.returncode == 0, r.stderr

        def verify():
            return run("verify", str(img), str(manifest))

        # one byte in the ESP partition, named as partition[0]
        bad = tmp / "bad-esp.img"
        shutil.copy(img, bad)
        with bad.open("r+b") as f:
            f.seek(16 * 1024 * 1024 + 200000)
            f.write(b"Y")
        r = run("verify", str(bad), str(manifest))
        assert r.returncode == 1 and "partition[0].sha256" in r.stderr, r.stderr
        # one byte in the root partition, named as partition[1]
        bad = tmp / "bad-root.img"
        shutil.copy(img, bad)
        with bad.open("r+b") as f:
            f.seek(163840 * 512 + 100000)
            f.write(b"Z")
        r = run("verify", str(bad), str(manifest))
        assert r.returncode == 1 and "partition[1].sha256" in r.stderr, r.stderr

        # a tampered manifest (whole-image sha256 rewritten) is refused
        data = json.loads(manifest.read_text())
        data["image_sha256"] = "0" * 64
        tampered = tmp / "badm.json"
        tampered.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        r = run("verify", str(img), str(tampered))
        assert r.returncode == 1 and "image_sha256" in r.stderr, r.stderr

        # a manifest claiming a missing ESP file is refused
        data = json.loads(manifest.read_text())
        data["esp"]["files"] = [
            e for e in data["esp"]["files"] if e["path"] != "efi/fedora/shim.efi"
        ]
        tampered = tmp / "badm-missing.json"
        tampered.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        r = run("verify", str(img), str(tampered))
        assert r.returncode == 1 and "esp.files" in r.stderr, r.stderr

        # a manifest claiming an extra ESP file is refused
        data = json.loads(manifest.read_text())
        data["esp"]["files"].append(
            {"path": "efi/fedora/extra.efi", "type": "file", "sha256": "0" * 64}
        )
        tampered = tmp / "badm-extra.json"
        tampered.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        r = run("verify", str(img), str(tampered))
        assert r.returncode == 1 and "esp.files" in r.stderr, r.stderr

        # a manifest claiming a different initramfs is refused
        data = json.loads(manifest.read_text())
        data["initramfs"][0]["sha256"] = "0" * 64
        tampered = tmp / "badm-initramfs.json"
        tampered.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        r = run("verify", str(img), str(tampered))
        assert r.returncode == 1 and "initramfs" in r.stderr, r.stderr


def main():
    case("manifest: write/verify roundtrip on a synthetic image", manifest_roundtrip)
    case(
        "manifest: every difference is refused and named", manifest_refuses_differences
    )
    if FAILURES:
        print(f"{len(FAILURES)} test(s) FAILED")
        return 1
    print("all devcard-manifest tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
