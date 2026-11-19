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
    """B3: fault wrapper matches ANY `rdump` form (074f9b6 and head) and logs injection."""
    real_debugfs = shutil.which("debugfs")
    assert real_debugfs, "need debugfs"
    for mode in ("truncate", "drop"):
        with tempfile.TemporaryDirectory(prefix="a7a-extract-") as td:
            work = Path(td)
            _, image, _ = make_image(work)
            inject_log = work / "inject.log"
            wrapper = work / "bin/debugfs"
            wrapper.parent.mkdir()
            wrapper.write_text(
                f"#!{sys.executable}\n"
                "import os, shlex, subprocess, sys\n"
                "from pathlib import Path\n"
                f"real = {real_debugfs!r}\n"
                f"mode = {mode!r}\n"
                f"log_path = Path({str(inject_log)!r})\n"
                "data = sys.stdin.buffer.read() if not sys.stdin.isatty() else None\n"
                "res = subprocess.run([real] + sys.argv[1:], input=data, capture_output=True)\n"
                "sys.stdout.buffer.write(res.stdout)\n"
                "sys.stderr.buffer.write(res.stderr)\n"
                "if res.returncode != 0:\n"
                "    sys.exit(res.returncode)\n"
                "cmd = None\n"
                "args = sys.argv[1:]\n"
                "for idx, tok in enumerate(args):\n"
                "    if tok == '-R' and idx + 1 < len(args):\n"
                "        cmd = args[idx + 1]\n"
                "        break\n"
                "if cmd and cmd.lstrip().startswith('rdump '):\n"
                "    parts = shlex.split(cmd)\n"
                "    dst = Path(parts[2])\n"
                "    if mode == 'truncate':\n"
                "        target = dst / 'etc/motd'\n"
                "        target.write_bytes(b'')\n"
                "    else:\n"
                "        target = dst / 'opt/vendor/runtime.bin'\n"
                "        target.unlink()\n"
                "    with log_path.open('a') as fh:\n"
                "        fh.write(f'injected:{mode}:{cmd}:{target.resolve()}\\n')\n"
                "sys.exit(0)\n"
            )
            wrapper.chmod(0o755)
            res = subprocess.run(
                [sys.executable, "-I", str(tool), "extract-root", image, work / "out"],
                env={**os.environ, "PATH": f"{wrapper.parent}:{os.environ['PATH']}"},
                capture_output=True,
                text=True,
            )
            assert inject_log.is_file(), f"fault wrapper never fired for mode={mode}"
            log_text = inject_log.read_text()
            assert f"injected:{mode}:rdump " in log_text, log_text
            assert res.returncode != 0, (
                f"extract-root silently accepted {mode} fault "
                f"(injected: {log_text.strip()})"
            )


def test_silent_truncated_inventory():
    """S0-3: silently truncated debugfs `ls -l -p` (exit 0, banner-only stderr) fails."""
    real_debugfs = shutil.which("debugfs")
    assert real_debugfs, "need debugfs"
    with tempfile.TemporaryDirectory(prefix="a7a-inv-") as td:
        work = Path(td)
        _, image, _ = make_image(work)
        inject_log = work / "inject-ls.log"
        wrapper = work / "bin/debugfs"
        wrapper.parent.mkdir()
        # Truncate root `ls -l -p <2>` after `.`, `..`, and one valid entry (`lost+found`),
        # exit 0, normal version banner only. Matches both -R (999648a) and -f - (head).
        wrapper.write_text(
            f"#!{sys.executable}\n"
            "import subprocess, sys\n"
            "from pathlib import Path\n"
            f"real = {real_debugfs!r}\n"
            f"log_path = Path({str(inject_log)!r})\n"
            "args = sys.argv[1:]\n"
            "stdin_bytes = sys.stdin.buffer.read() if not sys.stdin.isatty() else b''\n"
            "res = subprocess.run([real] + args, input=stdin_bytes, capture_output=True)\n"
            "is_root_ls = any('ls -l -p <2>' in a for a in args) or b'ls -l -p <2>' in stdin_bytes\n"
            "if is_root_ls and res.returncode == 0:\n"
            "    kept = []\n"
            "    valid_rows = 0\n"
            "    for line in res.stdout.splitlines(keepends=True):\n"
            "        if line.startswith(b'debugfs: ls -l -p'):\n"
            "            kept.append(line)\n"
            "            continue\n"
            "        if line.startswith(b'/'):\n"
            "            kept.append(line)\n"
            "            valid_rows += 1\n"
            "            if valid_rows == 3:\n"
            "                break\n"
            "    with log_path.open('a') as fh:\n"
            "        fh.write(f'injected:ls-trunc:rows={valid_rows}:args={args!r}\\n')\n"
            "    sys.stdout.buffer.write(b''.join(kept))\n"
            "    sys.stderr.buffer.write(res.stderr)\n"
            "    sys.exit(0)\n"
            "sys.stdout.buffer.write(res.stdout)\n"
            "sys.stderr.buffer.write(res.stderr)\n"
            "sys.exit(res.returncode)\n"
        )
        wrapper.chmod(0o755)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = f"{wrapper.parent}:{old_path}"
        try:
            assert hasattr(extract, "_inventory"), "base lacks _inventory"
            try:
                got = extract._inventory(image)
                raise AssertionError(
                    f"_inventory accepted silently truncated ls -l -p: {sorted(got)}"
                )
            except ValueError:
                pass
        finally:
            os.environ["PATH"] = old_path
        assert (
            inject_log.is_file()
            and "injected:ls-trunc:rows=3" in inject_log.read_text()
        )


def test_truncated_sfdisk_json():
    """S0-14: silently truncated `sfdisk -J` JSON (exit 0, no stderr) fails closed."""
    real_sfdisk = shutil.which("sfdisk")
    assert real_sfdisk, "need sfdisk"
    with tempfile.TemporaryDirectory(prefix="a7a-sfdisk-") as td:
        work = Path(td)
        disk, _, _ = make_image(work)
        inject_log = work / "inject-sfdisk.log"
        wrapper = work / "bin/sfdisk"
        wrapper.parent.mkdir()
        wrapper.write_text(
            f"#!{sys.executable}\n"
            "import subprocess, sys\n"
            "from pathlib import Path\n"
            f"real = {real_sfdisk!r}\n"
            f"log_path = Path({str(inject_log)!r})\n"
            "res = subprocess.run([real] + sys.argv[1:], capture_output=True)\n"
            "lines = res.stdout.splitlines(keepends=True)\n"
            "cut = b''.join(lines[:10])\n"
            "with log_path.open('a') as fh:\n"
            "    fh.write(f'injected:sfdisk-trunc:bytes={len(cut)}\\n')\n"
            "sys.stdout.buffer.write(cut)\n"
            "sys.exit(0)\n"
        )
        wrapper.chmod(0o755)
        res = subprocess.run(
            [sys.executable, "-I", str(tool), "partitions", disk],
            env={**os.environ, "PATH": f"{wrapper.parent}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )
        assert (
            inject_log.is_file() and "injected:sfdisk-trunc:" in inject_log.read_text()
        )
        assert res.returncode != 0, "truncated sfdisk JSON must fail closed"


def test_image_firmware_truncation_and_list_refusal():
    """S0-7: image-firmware.py rejects silent debugfs/lsinitrd truncation and check --list."""
    fw_tool = here.parent / "image-firmware.py"
    real_debugfs = shutil.which("debugfs")
    real_lsinitrd = shutil.which("lsinitrd")
    assert real_debugfs and real_lsinitrd, "need debugfs and lsinitrd"
    with tempfile.TemporaryDirectory(prefix="a7a-fw-trunc-") as td:
        work = Path(td)
        # Build a GPT image whose root has an allowed file AND a forbidden rtl_nic file.
        stage = work / "stage"
        (stage / "usr/lib/firmware/open").mkdir(parents=True)
        (stage / "usr/lib/firmware/open/a_allowed.fw").write_text("ok\n")
        (stage / "usr/lib/firmware/rtl_nic").mkdir(parents=True)
        (stage / "usr/lib/firmware/rtl_nic/rtl8125b-2.fw").write_text("blob\n")
        allow_file = work / "allow.txt"
        allow_file.write_text("open/a_allowed.fw\n")

        root_img = work / "root.img"
        subprocess.run(["truncate", "-s", "8M", str(root_img)], check=True)
        subprocess.run(["mkfs.ext4", "-q", "-d", str(stage), str(root_img)], check=True)
        disk = work / "disk.img"
        sectors = root_img.stat().st_size // 512
        total = (34816 + sectors + 2048) * 512
        subprocess.run(["truncate", "-s", str(total), str(disk)], check=True)
        subprocess.run(
            ["sfdisk", "--quiet", "--no-reread", "--no-tell-kernel", str(disk)],
            input=f"label: gpt\nfirst-lba: 34\nstart=34816, size={sectors}, type={ROOT_TYPE}\n",
            text=True,
            check=True,
        )
        with disk.open("r+b") as dst:
            dst.seek(34816 * 512)
            dst.write(root_img.read_bytes())

        # Control: real image-firmware check catches rtl_nic (exit 1).
        ctrl = subprocess.run(
            [
                sys.executable,
                "-I",
                str(fw_tool),
                "check",
                "--image",
                str(disk),
                "--allow",
                str(allow_file),
            ],
            capture_output=True,
            text=True,
        )
        assert ctrl.returncode == 1, (ctrl.returncode, ctrl.stdout, ctrl.stderr)

        # Case 1 (S0-7a): debugfs wrapper truncates ls of /usr/lib/firmware after
        # `.`, `..`, and `open` (hiding `rtl_nic`), exit 0, banner-only stderr.
        inject_dbg = work / "inject-dbg.log"
        dbg_wrap = work / "bin-dbg/debugfs"
        dbg_wrap.parent.mkdir()
        dbg_wrap.write_text(
            f"#!{sys.executable}\n"
            "import subprocess, sys\n"
            "from pathlib import Path\n"
            f"real = {real_debugfs!r}\n"
            f"log_path = Path({str(inject_dbg)!r})\n"
            "args = sys.argv[1:]\n"
            "stdin_bytes = sys.stdin.buffer.read() if not sys.stdin.isatty() else b''\n"
            "res = subprocess.run([real] + args, input=stdin_bytes, capture_output=True)\n"
            "is_fw_ls = any('ls ' in a and '/usr/lib/firmware\"' in a for a in args) or b'ls -l -p \"/usr/lib/firmware\"' in stdin_bytes\n"
            "if is_fw_ls and res.returncode == 0:\n"
            "    kept = []\n"
            "    for line in res.stdout.splitlines(keepends=True):\n"
            "        if line.startswith(b'debugfs: ls '):\n"
            "            kept.append(line)\n"
            "            continue\n"
            "        if line.startswith(b'/'):\n"
            "            if b'/rtl_nic/' in line:\n"
            "                break\n"
            "            kept.append(line)\n"
            "    with log_path.open('a') as fh:\n"
            "        fh.write(f'injected:fw-debugfs-trunc:args={args!r}\\n')\n"
            "    sys.stdout.buffer.write(b''.join(kept))\n"
            "    sys.stderr.buffer.write(res.stderr)\n"
            "    sys.exit(0)\n"
            "sys.stdout.buffer.write(res.stdout)\n"
            "sys.stderr.buffer.write(res.stderr)\n"
            "sys.exit(res.returncode)\n"
        )
        dbg_wrap.chmod(0o755)
        r_dbg = subprocess.run(
            [
                sys.executable,
                "-I",
                str(fw_tool),
                "check",
                "--image",
                str(disk),
                "--allow",
                str(allow_file),
            ],
            env={**os.environ, "PATH": f"{dbg_wrap.parent}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )
        assert (
            inject_dbg.is_file()
            and "injected:fw-debugfs-trunc:" in inject_dbg.read_text()
        )
        assert r_dbg.returncode == 2, (
            f"image-firmware check --image accepted truncated debugfs listing "
            f"(rc={r_dbg.returncode}):\n{r_dbg.stdout}\n{r_dbg.stderr}"
        )

        # Case 2 (S0-7b): lsinitrd wrapper truncates after 1 allowed row (hiding rtl_nic),
        # exit 0, no stderr.
        rd_root = work / "rd-root"
        (rd_root / "boot").mkdir(parents=True)
        rd_tree = work / "rd-tree"
        (rd_tree / "usr/lib/firmware/open").mkdir(parents=True)
        (rd_tree / "usr/lib/firmware/open/a_allowed.fw").write_text("ok\n")
        (rd_tree / "usr/lib/firmware/rtl_nic").mkdir(parents=True)
        (rd_tree / "usr/lib/firmware/rtl_nic/rtl8125b-2.fw").write_text("blob\n")
        rd_img = rd_root / "boot/initramfs-7.4.0.img"
        entries = sorted(p.relative_to(rd_tree).as_posix() for p in rd_tree.rglob("*"))
        cpio_out = subprocess.run(
            ["cpio", "-o", "-H", "newc", "--quiet"],
            input=("\n".join(entries) + "\n").encode(),
            cwd=rd_tree,
            capture_output=True,
            check=True,
        ).stdout
        rd_img.write_bytes(cpio_out)

        inject_ls = work / "inject-lsinitrd.log"
        ls_wrap = work / "bin-ls/lsinitrd"
        ls_wrap.parent.mkdir()
        rule = "=" * 72
        row = "-rw-r--r--   1 root     root            3 Nov 19 06:00 usr/lib/firmware/open/a_allowed.fw"
        ls_wrap.write_text(
            "#!/bin/sh\n"
            f'echo "injected:fw-lsinitrd-trunc:$*" >> "{inject_ls}"\n'
            f'printf "%s\\n%s\\n" "{rule}" "{row}"\n'
            "exit 0\n"
        )
        ls_wrap.chmod(0o755)
        r_ls = subprocess.run(
            [
                sys.executable,
                "-I",
                str(fw_tool),
                "check",
                "--root",
                str(rd_root),
                "--initramfs",
                "--allow",
                str(allow_file),
            ],
            env={**os.environ, "PATH": f"{ls_wrap.parent}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )
        assert (
            inject_ls.is_file()
            and "injected:fw-lsinitrd-trunc:" in inject_ls.read_text()
        )
        assert r_ls.returncode == 2, (
            f"image-firmware check --initramfs accepted truncated lsinitrd "
            f"(rc={r_ls.returncode}):\n{r_ls.stdout}\n{r_ls.stderr}"
        )

        # Case 3 (S0-7c): `check --list` has no positive completeness signal -> refused.
        raw_list = work / "paths.list"
        raw_list.write_text("/usr/lib/firmware/open/a_allowed.fw\n")
        r_list = subprocess.run(
            [
                sys.executable,
                "-I",
                str(fw_tool),
                "check",
                "--list",
                str(raw_list),
                "--allow",
                str(allow_file),
            ],
            capture_output=True,
            text=True,
        )
        assert (
            r_list.returncode == 2 and "positive completeness signal" in r_list.stderr
        ), (
            r_list.returncode,
            r_list.stdout,
            r_list.stderr,
        )


def test_selinux_label_verify_rejects_truncation():
    """S0-13: selinux-label.py --verify fails closed on silent debugfs -f truncation."""
    label_tool = here.parent / "selinux-label.py"
    real_debugfs = shutil.which("debugfs")
    assert real_debugfs, "need debugfs"
    with tempfile.TemporaryDirectory(prefix="a7a-selinux-trunc-") as td:
        work = Path(td)
        root = work / "root"
        fc = root / "etc/selinux/targeted/contexts/files/file_contexts"
        fc.parent.mkdir(parents=True)
        fc.write_text("/.* system_u:object_r:default_t:s0\n")
        (root / "etc/motd").write_text("hello\n")
        img = work / "root.img"
        subprocess.run(["truncate", "-s", "8M", str(img)], check=True)
        subprocess.run(["mkfs.ext4", "-q", "-d", str(root), str(img)], check=True)

        # Label and verify cleanly first.
        r_w = subprocess.run(
            [
                sys.executable,
                "-I",
                str(label_tool),
                str(root),
                str(img),
                str(work / "w1"),
            ],
            capture_output=True,
            text=True,
        )
        assert r_w.returncode == 0, r_w.stderr
        r_v = subprocess.run(
            [
                sys.executable,
                "-I",
                str(label_tool),
                "--verify",
                str(root),
                str(img),
                str(work / "v1"),
            ],
            capture_output=True,
            text=True,
        )
        assert r_v.returncode == 0, r_v.stderr

        # Wrap debugfs -f so only the FIRST ea_get executes; exit 0, banner-only stderr.
        inject_log = work / "inject-selinux.log"
        wrap = work / "bin/debugfs"
        wrap.parent.mkdir()
        wrap.write_text(
            f"#!{sys.executable}\n"
            "import subprocess, sys\n"
            "from pathlib import Path\n"
            f"real = {real_debugfs!r}\n"
            f"log_path = Path({str(inject_log)!r})\n"
            "args = sys.argv[1:]\n"
            "if '-f' in args:\n"
            "    idx = args.index('-f')\n"
            "    script_path = Path(args[idx + 1])\n"
            "    first = script_path.read_text().splitlines()[:1]\n"
            "    trunc = script_path.with_name('trunc.debugfs')\n"
            "    trunc.write_text('\\n'.join(first) + '\\n')\n"
            "    args[idx + 1] = str(trunc)\n"
            "    with log_path.open('a') as fh:\n"
            "        fh.write(f'injected:selinux-debugfs-trunc:lines=1\\n')\n"
            "res = subprocess.run([real] + args, capture_output=True)\n"
            "sys.stdout.buffer.write(res.stdout)\n"
            "sys.stderr.buffer.write(res.stderr)\n"
            "sys.exit(res.returncode)\n"
        )
        wrap.chmod(0o755)
        r_trunc = subprocess.run(
            [
                sys.executable,
                "-I",
                str(label_tool),
                "--verify",
                str(root),
                str(img),
                str(work / "v2"),
            ],
            env={**os.environ, "PATH": f"{wrap.parent}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )
        assert (
            inject_log.is_file()
            and "injected:selinux-debugfs-trunc:" in inject_log.read_text()
        )
        assert (
            r_trunc.returncode != 0
            and "wrong or missing image labels" in r_trunc.stderr
        ), (
            r_trunc.returncode,
            r_trunc.stdout,
            r_trunc.stderr,
        )


def test_verifier_rejects_truncated_rpm_qa():
    """S0-8: verify-devcard.sh rejects silently truncated `rpm -qa` before layout checks."""
    real_rpm = shutil.which("rpm")
    assert real_rpm, "need rpm"
    keys = sorted(
        Path("/usr/share/pki/rpm-gpg").glob("RPM-GPG-KEY-fedora-*-primary")
    ) or sorted(Path("/etc/pki/rpm-gpg").glob("RPM-GPG-KEY-fedora-*-primary"))
    assert len(keys) >= 2, f"need >=2 Fedora GPG keys for 2-entry fixture rpmdb: {keys}"
    with tempfile.TemporaryDirectory(prefix="a7a-rpmqa-trunc-") as td:
        work = Path(td)
        stage = work / "stage"
        (stage / "etc").mkdir(parents=True)
        (stage / "etc/motd").write_text("ok\n")
        for key in keys[:2]:
            subprocess.run(
                ["rpmkeys", "--root", str(stage), "--import", str(key)],
                check=True,
                capture_output=True,
            )
        root_img = work / "root.img"
        subprocess.run(["truncate", "-s", "8M", str(root_img)], check=True)
        subprocess.run(
            [
                str(here.parent / "run-build-ns.sh"),
                "user",
                "mkfs.ext4",
                "-q",
                "-E",
                "root_owner=0:0",
                "-d",
                str(stage),
                str(root_img),
            ],
            check=True,
        )
        esp_img = work / "esp.img"
        subprocess.run(
            ["mkfs.fat", "-F", "32", "-C", str(esp_img), "1024"],
            check=True,
            capture_output=True,
        )
        disk = work / "disk.img"
        esp_sectors = esp_img.stat().st_size // 512
        root_sectors = root_img.stat().st_size // 512
        root_start = 32768 + esp_sectors
        total = (root_start + root_sectors + 2048) * 512
        subprocess.run(["truncate", "-s", str(total), str(disk)], check=True)
        subprocess.run(
            ["sfdisk", "--quiet", "--no-reread", "--no-tell-kernel", str(disk)],
            input=(
                "label: gpt\nfirst-lba: 34\n"
                f"start=32768, size={esp_sectors}, type={ESP_TYPE}\n"
                f"start={root_start}, size={root_sectors}, type={ROOT_TYPE}\n"
            ),
            text=True,
            check=True,
        )
        with disk.open("r+b") as dst:
            dst.seek(32768 * 512)
            dst.write(esp_img.read_bytes())
            dst.seek(root_start * 512)
            dst.write(root_img.read_bytes())

        inject_log = work / "inject-rpmqa.log"
        wrap = work / "bin/rpm"
        wrap.parent.mkdir()
        wrap.write_text(
            f"#!{sys.executable}\n"
            "import subprocess, sys\n"
            "from pathlib import Path\n"
            f"real = {real_rpm!r}\n"
            f"log_path = Path({str(inject_log)!r})\n"
            "res = subprocess.run([real] + sys.argv[1:], capture_output=True, text=True)\n"
            "if '-qa' in sys.argv[1:] and res.returncode == 0:\n"
            "    first = res.stdout.splitlines()[:1]\n"
            "    with log_path.open('a') as fh:\n"
            "        fh.write(f'injected:rpmqa-trunc:total={len(res.stdout.splitlines())}\\n')\n"
            "    sys.stdout.write('\\n'.join(first) + '\\n')\n"
            "    sys.exit(0)\n"
            "sys.stdout.write(res.stdout)\n"
            "sys.stderr.write(res.stderr)\n"
            "sys.exit(res.returncode)\n"
        )
        wrap.chmod(0o755)
        res = subprocess.run(
            [here.parent / "verify-devcard.sh", disk, work / "verify"],
            env={**os.environ, "PATH": f"{wrap.parent}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )
        assert (
            inject_log.is_file() and "injected:rpmqa-trunc:" in inject_log.read_text()
        )
        assert (
            res.returncode != 0
            and "rpm package listing" in res.stderr
            and "== layout" not in res.stdout
        ), f"verify-devcard accepted truncated rpm -qa:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"


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
        "extract-root: reject a silent short extraction (B3)",
        test_silent_partial_extraction,
    )
    case(
        "extract-root: reject silently truncated debugfs inventory (S0-3)",
        test_silent_truncated_inventory,
    )
    case(
        "partitions: reject silently truncated sfdisk JSON (S0-14)",
        test_truncated_sfdisk_json,
    )
    case(
        "image-firmware: reject truncated debugfs/lsinitrd and refuse check --list (S0-7)",
        test_image_firmware_truncation_and_list_refusal,
    )
    case(
        "selinux-label --verify: reject silently truncated debugfs -f (S0-13)",
        test_selinux_label_verify_rejects_truncation,
    )
    case(
        "verify-devcard rejects silently truncated rpm -qa before layout checks (S0-8)",
        test_verifier_rejects_truncated_rpm_qa,
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
