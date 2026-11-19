#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for fedora/stage-aic8800.py and cubie-a7a-aic8800-usb.spec.

A fixture AIC8800_SRC holds the reviewed driver inputs, an unlisted aic_btusb
directory and, in one case, a firmware file.  Staging must copy only the listed
inputs (verifying their recorded SHA256s), build an archive rooted at
aic8800-usb-VERSION, and refuse firmware; the payload check must accept a real
built RPM with only listed outputs and reject firmware or unlisted paths.
Run: python3 -I fedora/tests/aic-staging.py
"""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
here = Path(__file__).resolve().parent
repo_fedora = here.parent
tool = repo_fedora / "stage-aic8800.py"
spec = importlib.util.spec_from_file_location("stage_aic8800", tool)
stage_aic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_aic)

FAILURES = []

# A7A_TEST_ONLY=fn1,fn2 runs only the named test functions (red/green runs).
ONLY = {n for n in os.environ.get("A7A_TEST_ONLY", "").split(",") if n}


def case(name, fn):
    if ONLY and fn.__name__ not in ONLY:
        return
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


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


LISTED_FILES = (
    "COPYING",
    "Makefile",
    "dkms.conf",
    "aic8800/Makefile",
    "aic8800/aic_load_fw/foo.c",
    "aic8800/aic8800_fdrv/bar.c",
    "include/aic_fw_request.h",
)


def fixture_src(root, firmware=False):
    src = root / "src"
    write(
        src / "dkms.conf",
        'PACKAGE_NAME="cubie-a7a-aic8800-usb"\nPACKAGE_VERSION="@VERSION@"\n',
    )
    write(src / "Makefile", "obj-m += aic8800/\n")
    write(src / "COPYING", "GPL-2.0-only\n")
    write(src / "aic8800/Makefile", "obj-m += aic_load_fw/ aic8800_fdrv/\n")
    write(src / "aic8800/aic_load_fw/foo.c", "int foo;\n")
    write(src / "aic8800/aic8800_fdrv/bar.c", "int bar;\n")
    write(src / "include/aic_fw_request.h", "/* header */\n")
    # Present in an external tree but not a reviewed input for this package.
    write(src / "aic_btusb/bt.c", "int bt;\n")
    if firmware:
        write(src / "fw/aic8800D80/fmacfw_8800d80_u02.bin", "binary")
    return src


def fixture_list(root, src):
    list_path = root / "inputs.list"
    lines = [f"{sha256(src / rel)}  {rel}" for rel in sorted(LISTED_FILES)]
    write(list_path, "# fixture driver inputs\n" + "\n".join(lines) + "\n")
    return list_path


def run(*args):
    return stage_aic.main(list(map(str, args)))


def test_stage_copies_only_listed_inputs():
    with tempfile.TemporaryDirectory(prefix="a7a-stage-") as td:
        root = Path(td)
        src = fixture_src(root)
        list_path = fixture_list(root, src)
        out = root / "out"
        (out / "SOURCES").mkdir(parents=True)
        code = run("stage", src, out, "0.4", "--list", list_path)
        assert code == 0
        staged = out / "aic8800-usb-0.4"
        for rel in LISTED_FILES:
            assert (staged / rel).is_file(), rel
        assert not (staged / "aic_btusb").exists(), "unlisted tree must not be staged"
        assert not list(staged.rglob("*.bin"))
        manifest = (out / "SOURCES/aic8800-usb-0.4.inputs.sha256").read_text()
        for rel in ("COPYING", "include/aic_fw_request.h"):
            assert f"{sha256(staged / rel)}  {rel}\n" in manifest, rel
        tarball = out / "SOURCES/aic8800-usb-0.4.tar.gz"
        assert tarball.is_file()
        with tarfile.open(tarball, "r:gz") as tf:
            names = sorted(m.name for m in tf.getmembers() if m.isfile())
        expected = sorted(f"aic8800-usb-0.4/{rel}" for rel in LISTED_FILES)
        assert names == expected, names


def test_stage_refuses_firmware_in_source():
    with tempfile.TemporaryDirectory(prefix="a7a-stage-") as td:
        root = Path(td)
        src = fixture_src(root, firmware=True)
        list_path = fixture_list(root, src)
        out = root / "out"
        (out / "SOURCES").mkdir(parents=True)
        code = run("stage", src, out, "0.4", "--list", list_path)
        assert code == 1, "firmware in the driver source must fail the build"
        assert not (out / "SOURCES/aic8800-usb-0.4.tar.gz").exists()


def test_stage_refuses_compressed_firmware_in_source():
    with tempfile.TemporaryDirectory(prefix="a7a-stage-") as td:
        root = Path(td)
        src = fixture_src(root)
        list_path = fixture_list(root, src)
        write(src / "aic8800/extra.bin.xz", "compressed")
        out = root / "out"
        (out / "SOURCES").mkdir(parents=True)
        assert run("stage", src, out, "0.4", "--list", list_path) == 1


def test_stage_refuses_sha256_mismatch():
    with tempfile.TemporaryDirectory(prefix="a7a-stage-") as td:
        root = Path(td)
        src = fixture_src(root)
        list_path = fixture_list(root, src)
        write(src / "aic8800/aic8800_fdrv/bar.c", "int tampered;\n")
        out = root / "out"
        (out / "SOURCES").mkdir(parents=True)
        assert run("stage", src, out, "0.4", "--list", list_path) == 1


def test_stage_refuses_missing_listed_input():
    with tempfile.TemporaryDirectory(prefix="a7a-stage-") as td:
        root = Path(td)
        src = fixture_src(root)
        list_path = fixture_list(root, src)
        (src / "aic8800/aic8800_fdrv/bar.c").unlink()
        out = root / "out"
        (out / "SOURCES").mkdir(parents=True)
        assert run("stage", src, out, "0.4", "--list", list_path) == 1


def test_stage_refuses_unsafe_or_firmware_list():
    with tempfile.TemporaryDirectory(prefix="a7a-stage-") as td:
        root = Path(td)
        src = fixture_src(root)
        out = root / "out"
        (out / "SOURCES").mkdir(parents=True)
        for line in (
            f"{'0' * 64}  ../escape.c\n",
            f"{'0' * 64}  fw/aic8800D80/fmacfw.bin\n",
        ):
            bad = root / "bad.list"
            write(bad, line)
            try:
                run("stage", src, out, "0.4", "--list", bad)
            except SystemExit:
                continue
            raise AssertionError(f"bad list entry was not refused: {line!r}")


class FakeRpm:
    """Answers rpm -qp/-qlp without building anything."""

    def __init__(self, dkms_ver, paths):
        self.dkms_ver = dkms_ver
        self.paths = paths

    def __call__(self, argv, **kwargs):
        if "--qf" in argv:
            fmt = argv[argv.index("--qf") + 1]
            if "FILENAMES" in fmt:
                body = "\n".join(self.paths)
                out = f"{body}\n---END-RPM-PAYLOAD {len(self.paths)}\n"
                return type("R", (), {"stdout": out, "stderr": "", "returncode": 0})()
            return type(
                "R", (), {"stdout": self.dkms_ver + "\n", "stderr": "", "returncode": 0}
            )()
        return type(
            "R",
            (),
            {"stdout": "\n".join(self.paths) + "\n", "stderr": "", "returncode": 0},
        )()


def _clean_rpm_paths(dkms_ver):
    base = f"/usr/src/cubie-a7a-aic8800-usb-{dkms_ver}"
    dirs = [
        base,
        f"{base}/aic8800",
        f"{base}/aic8800/aic_load_fw",
        f"{base}/aic8800/aic8800_fdrv",
        f"{base}/include",
    ]
    files = [f"{base}/{rel}" for rel in LISTED_FILES]
    return sorted(dirs + files + list(stage_aic.SPEC_OUTPUTS))


def test_payload_clean_passes():
    with tempfile.TemporaryDirectory(prefix="a7a-stage-") as td:
        root = Path(td)
        src = fixture_src(root)
        list_path = fixture_list(root, src)
        paths = _clean_rpm_paths("0.4-2.fc45")
        original = stage_aic.subprocess.run
        stage_aic.subprocess.run = FakeRpm("0.4-2.fc45", paths)
        try:
            assert stage_aic.payload(Path("fake.rpm"), list_path) == 0
        finally:
            stage_aic.subprocess.run = original


def test_payload_rejects_firmware():
    with tempfile.TemporaryDirectory(prefix="a7a-stage-") as td:
        root = Path(td)
        src = fixture_src(root)
        list_path = fixture_list(root, src)
        for extra in (
            "/usr/lib/firmware/aic8800_fw/USB/aic8800D80/fmacfw.bin",
            "/usr/lib/firmware/aic/aic8800d80/fmacfw_8800d80_u02.bin.xz",
            "/usr/src/cubie-a7a-aic8800-usb-0.4-2.fc45/aic8800/stray_fw_blob.txt",
        ):
            paths = _clean_rpm_paths("0.4-2.fc45") + [extra]
            original = stage_aic.subprocess.run
            stage_aic.subprocess.run = FakeRpm("0.4-2.fc45", paths)
            try:
                assert stage_aic.payload(Path("fake.rpm"), list_path) == 1, extra
            finally:
                stage_aic.subprocess.run = original


def test_payload_rejects_unlisted_output():
    with tempfile.TemporaryDirectory(prefix="a7a-stage-") as td:
        root = Path(td)
        src = fixture_src(root)
        list_path = fixture_list(root, src)
        for extra in (
            "/usr/src/cubie-a7a-aic8800-usb-0.4-2.fc45/aic_btusb/bt.c",
            "/usr/share/cubie-a7a/unexpected.txt",
        ):
            paths = _clean_rpm_paths("0.4-2.fc45") + [extra]
            original = stage_aic.subprocess.run
            stage_aic.subprocess.run = FakeRpm("0.4-2.fc45", paths)
            try:
                assert stage_aic.payload(Path("fake.rpm"), list_path) == 1, extra
            finally:
                stage_aic.subprocess.run = original


def test_real_rpmbuild_from_fixture():
    if not shutil.which("rpmbuild"):
        return
    with tempfile.TemporaryDirectory(prefix="a7a-stage-rpm-") as td:
        root = Path(td)
        src = fixture_src(root)
        list_path = fixture_list(root, src)
        out = root / "rpmbuild"
        for sub in ("SOURCES", "SPECS", "BUILD", "RPMS", "SRPMS", "tmp"):
            (out / sub).mkdir(parents=True)
        assert run("stage", src, out, "0.4", "--list", list_path) == 0
        pkg_dir = repo_fedora / "rpm/cubie-a7a-aic8800-usb"
        for name in (
            "cubie-a7a-wifi-firmware",
            "aic8800-d80-usb.manifest",
            "60-cubie-a7a-aic8800.rules",
            "cubie-a7a-aic8800-modprobe.conf",
            "cubie-a7a-aic-udev",
        ):
            shutil.copy2(pkg_dir / name, out / "SOURCES" / name)
        shutil.copy2(repo_fedora / "WIFI-FIRMWARE.md", out / "SOURCES/WIFI-FIRMWARE.md")
        shutil.copy2(repo_fedora / "rpm/cubie-a7a-dkms", out / "SOURCES/cubie-a7a-dkms")
        shutil.copy2(list_path, out / "SOURCES/driver-inputs.list")
        spec_dst = out / "SPECS/cubie-a7a-aic8800-usb.spec"
        shutil.copy2(pkg_dir / "cubie-a7a-aic8800-usb.spec", spec_dst)
        res = subprocess.run(
            [
                "rpmbuild",
                "--define",
                f"_topdir {out}",
                "--define",
                f"_tmppath {out / 'tmp'}",
                "--define",
                "dist .fc45",
                "-bb",
                str(spec_dst),
            ],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, res.stderr
        rpms = list((out / "RPMS").rglob("cubie-a7a-aic8800-usb-*.rpm"))
        assert len(rpms) == 1, rpms
        assert stage_aic.payload(rpms[0], list_path) == 0


def _fixture_repo_copy(root, src):
    """Copy fedora/ into ROOT/repo/fedora with fixture driver-inputs.list."""
    repo_fed = root / "repo/fedora"
    shutil.copytree(
        repo_fedora,
        repo_fed,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    list_dst = repo_fed / "rpm/cubie-a7a-aic8800-usb/driver-inputs.list"
    shutil.copy2(fixture_list(root, src), list_dst)
    return repo_fed


def test_build_rpms_reused_dir_older_rpm_does_not_satisfy_check():
    """A reused output directory holding an older clean matching RPM must not
    satisfy the payload check when the current build writes a bad RPM."""
    if not shutil.which("rpmbuild"):
        return
    with tempfile.TemporaryDirectory(prefix="a7a-build-reused-") as td:
        root = Path(td)
        src = fixture_src(root)
        repo_fed = _fixture_repo_copy(root, src)
        spec_path = repo_fed / "rpm/cubie-a7a-aic8800-usb/cubie-a7a-aic8800-usb.spec"
        orig_spec = spec_path.read_text()
        out = root / "out"

        # Step 1: build an older clean RPM (Release: 1%{?dist}) into OUT.
        spec_v1 = orig_spec.replace(
            "Release:        2%{?dist}", "Release:        1%{?dist}"
        )
        assert spec_v1 != orig_spec
        spec_path.write_text(spec_v1)
        env = os.environ.copy()
        env["AIC8800_SRC"] = str(src)
        r1 = subprocess.run(
            ["bash", str(repo_fed / "build-rpms.sh"), str(out)],
            env=env,
            capture_output=True,
            text=True,
        )
        assert r1.returncode == 0, f"v1 build failed:\n{r1.stdout}\n{r1.stderr}"
        v1_rpms = list(
            (Path(r1.stdout.strip()) / "out").rglob("cubie-a7a-aic8800-usb-0.4-1.*.rpm")
        )
        assert len(v1_rpms) == 1, v1_rpms

        # A successful build subprocess which produced no *current* binary
        # cannot be certified using an old file. Deliberately suppress this
        # single output; use the real builder for every other operation.
        wrapper = root / "bin/rpmbuild"
        wrapper.parent.mkdir()
        real = shutil.which("rpmbuild")
        wrapper.write_text(
            "#!/bin/bash\n"
            'if [[ " ${*} " == *" -bb "* && "${!#}" == */cubie-a7a-aic8800-usb.spec ]]; then exit 0; fi\n'
            f'exec "{real}" "$@"\n'
        )
        wrapper.chmod(0o755)
        env["PATH"] = f"{wrapper.parent}:{env['PATH']}"
        spec_path.write_text(orig_spec)
        r2 = subprocess.run(
            ["bash", str(repo_fed / "build-rpms.sh"), str(out)],
            env=env,
            capture_output=True,
            text=True,
        )
        assert (
            r2.returncode != 0
        ), "an old clean RPM satisfied the check without a current build output"
        assert "expected one current" in r2.stderr, r2.stderr


def test_build_rpms_stale_spec_not_rebuilt_when_skipped():
    """A previous run's AIC source/spec does not rebuild when staging is skipped."""
    if not shutil.which("rpmbuild"):
        return
    with tempfile.TemporaryDirectory(prefix="a7a-build-stale-") as td:
        root = Path(td)
        src = fixture_src(root)
        repo_fed = _fixture_repo_copy(root, src)
        out = root / "out"

        # Step 1: build with AIC8800_SRC so run 1 holds its RPMs and spec.
        env_with = os.environ.copy()
        env_with["AIC8800_SRC"] = str(src)
        r1 = subprocess.run(
            ["bash", str(repo_fed / "build-rpms.sh"), str(out)],
            env=env_with,
            capture_output=True,
            text=True,
        )
        assert r1.returncode == 0, f"initial build failed:\n{r1.stdout}\n{r1.stderr}"
        first = Path(r1.stdout.strip())
        assert (first / "rpmbuild/SPECS/cubie-a7a-aic8800-usb.spec").is_file()

        # Step 2: run without AIC8800_SRC; staging is skipped so AIC must NOT rebuild.
        env_without = os.environ.copy()
        env_without.pop("AIC8800_SRC", None)
        r2 = subprocess.run(
            ["bash", str(repo_fed / "build-rpms.sh"), str(out)],
            env=env_without,
            capture_output=True,
            text=True,
        )
        assert (
            r2.returncode == 0
        ), f"skipped-AIC build failed:\n{r2.stdout}\n{r2.stderr}"
        second = Path(r2.stdout.strip())
        assert first != second
        rebuilt = list(second.rglob("cubie-a7a-aic8800-usb-*.rpm"))
        assert rebuilt == [], f"stale AIC spec was rebuilt after skip: {rebuilt}"


def test_payload_rejects_silent_truncation():
    """S0-5: silently truncated rpm payload listing (exit 0, no stderr) fails closed."""
    if not shutil.which("rpmbuild"):
        return
    real_rpm = shutil.which("rpm")
    assert real_rpm, "need rpm"
    with tempfile.TemporaryDirectory(prefix="a7a-payload-trunc-") as td:
        root = Path(td)
        src = fixture_src(root)
        list_path = fixture_list(root, src)
        out = root / "rpmbuild"
        for sub in ("SOURCES", "SPECS", "BUILD", "RPMS", "SRPMS", "tmp"):
            (out / sub).mkdir(parents=True)
        assert run("stage", src, out, "0.4", "--list", list_path) == 0
        pkg_dir = repo_fedora / "rpm/cubie-a7a-aic8800-usb"
        for name in (
            "cubie-a7a-wifi-firmware",
            "aic8800-d80-usb.manifest",
            "60-cubie-a7a-aic8800.rules",
            "cubie-a7a-aic8800-modprobe.conf",
            "cubie-a7a-aic-udev",
        ):
            shutil.copy2(pkg_dir / name, out / "SOURCES" / name)
        shutil.copy2(repo_fedora / "WIFI-FIRMWARE.md", out / "SOURCES/WIFI-FIRMWARE.md")
        shutil.copy2(repo_fedora / "rpm/cubie-a7a-dkms", out / "SOURCES/cubie-a7a-dkms")
        shutil.copy2(list_path, out / "SOURCES/driver-inputs.list")
        spec_dst = out / "SPECS/cubie-a7a-aic8800-usb.spec"
        shutil.copy2(pkg_dir / "cubie-a7a-aic8800-usb.spec", spec_dst)
        res = subprocess.run(
            [
                "rpmbuild",
                "--define",
                f"_topdir {out}",
                "--define",
                f"_tmppath {out / 'tmp'}",
                "--define",
                "dist .fc45",
                "-bb",
                str(spec_dst),
            ],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, res.stderr
        rpms = list((out / "RPMS").rglob("cubie-a7a-aic8800-usb-*.rpm"))
        assert len(rpms) == 1, rpms
        rpm_file = rpms[0]

        inject_log = root / "inject-rpm.log"
        wrapper = root / "bin/rpm"
        wrapper.parent.mkdir()
        # Match BOTH `rpm -qlp` (074f9b6/999648a) and `rpm -qp --qf ...FILENAMES...` (head):
        # output only the /usr/src/ driver rows, exit 0, no stderr.
        wrapper.write_text(
            f"#!{sys.executable}\n"
            "import subprocess, sys\n"
            "from pathlib import Path\n"
            f"real = {real_rpm!r}\n"
            f"log_path = Path({str(inject_log)!r})\n"
            "args = sys.argv[1:]\n"
            "res = subprocess.run([real] + args, capture_output=True, text=True)\n"
            "is_listing = ('-qlp' in args) or any('FILENAMES' in a for a in args)\n"
            "if is_listing and res.returncode == 0:\n"
            "    kept = [l for l in res.stdout.splitlines() if l.startswith('/usr/src/')]\n"
            "    with log_path.open('a') as fh:\n"
            "        fh.write(f'injected:rpm-trunc:rows={len(kept)}:args={args!r}\\n')\n"
            "    sys.stdout.write('\\n'.join(kept) + '\\n')\n"
            "    sys.exit(0)\n"
            "sys.stdout.write(res.stdout)\n"
            "sys.stderr.write(res.stderr)\n"
            "sys.exit(res.returncode)\n"
        )
        wrapper.chmod(0o755)
        check = subprocess.run(
            [
                sys.executable,
                "-I",
                str(repo_fedora / "stage-aic8800.py"),
                "payload",
                str(rpm_file),
                "--list",
                str(list_path),
            ],
            env={**os.environ, "PATH": f"{wrapper.parent}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )
        assert inject_log.is_file() and "injected:rpm-trunc:" in inject_log.read_text()
        assert check.returncode != 0, (
            f"stage-aic8800 payload silently accepted truncated listing:\n"
            f"{check.stdout}\n{check.stderr}"
        )


def test_mkdevcard_ignores_stale_rpms_and_rejects_truncated_manifest():
    """Should-fix + S0-6: mkdevcard selects ONLY this run's checked manifest RPMs."""
    if not shutil.which("rpmbuild"):
        return
    with tempfile.TemporaryDirectory(prefix="a7a-manifest-sel-") as td:
        root = Path(td)
        src = fixture_src(root)
        repo_fed = _fixture_repo_copy(root, src)
        repo_top = repo_fed.parent
        out = root / "out"

        # Step 1: build WITH AIC8800_SRC into the first run.
        env_with = os.environ.copy()
        env_with["AIC8800_SRC"] = str(src)
        r1 = subprocess.run(
            ["bash", str(repo_fed / "build-rpms.sh"), str(out)],
            env=env_with,
            capture_output=True,
            text=True,
        )
        assert r1.returncode == 0, f"run 1 failed:\n{r1.stdout}\n{r1.stderr}"
        first = Path(r1.stdout.strip())
        stale_aic = list((first / "out/noarch").glob("cubie-a7a-aic8800-usb-*.rpm"))
        assert len(stale_aic) == 1, stale_aic

        # Step 2: build WITHOUT AIC8800_SRC under the same buildroot.
        env_without = os.environ.copy()
        env_without.pop("AIC8800_SRC", None)
        r2 = subprocess.run(
            ["bash", str(repo_fed / "build-rpms.sh"), str(out)],
            env=env_without,
            capture_output=True,
            text=True,
        )
        assert r2.returncode == 0, f"run 2 failed:\n{r2.stdout}\n{r2.stderr}"
        second = Path(r2.stdout.strip())
        assert first != second
        # The previous run is untouched and has a same-named DTB.
        assert stale_aic[0].is_file()
        real_dtb = next((second / "repo/noarch").glob("cubie-a7a-dtb-*.rpm"))
        stale_dtb = first / "repo/noarch" / real_dtb.name
        assert stale_dtb.is_file()

        # Stub run-build-ns.sh in the fixture copy so mkdevcard.sh stops cleanly at STAGE1
        # after recording its exact PACKAGES (including BOARD_RPMS) argument vector.
        recorded = root / "recorded-stage1-args.txt"
        stage_script = root / "stage-one.sh"
        stub = repo_fed / "run-build-ns.sh"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            f'printf "%s\\n" "$@" > "{recorded}"\n'
            f'cat > "{stage_script}"\n'
            "exit 42\n"
        )
        stub.chmod(0o755)

        def run_mkdevcard(tag, extra=""):
            recorded.unlink(missing_ok=True)
            env = env_without.copy()
            env["WORK"] = str(repo_top / "build" / f"work-{tag}")
            env["OUT"] = str(repo_top / "build" / f"img-{tag}.img")
            env["EXTRA_PACKAGES"] = extra
            return subprocess.run(
                ["bash", str(repo_fed / "mkdevcard.sh"), "none", str(second)],
                env=env,
                cwd=repo_top,
                capture_output=True,
                text=True,
            )

        valid_specs = ["perf", "kernel-core-0:7.3.3-300.fc45.aarch64"]
        res = run_mkdevcard("clean", "\t".join(valid_specs))
        assert res.returncode == 42, f"mkdevcard did not reach STAGE1:\n{res.stderr}"
        selected = recorded.read_text().splitlines()
        assert str(real_dtb.resolve()) in selected, selected
        stage = stage_script.read_text()
        assert (
            "--repofrompath" not in stage
        ), "board RPM directory is still a DNF source"
        check = 'check-installed-rpms "$ROOT" "$RPM_RECORDS"'
        assert stage.index("dnf5 -y install") < stage.index(check)
        assert all(spec in selected for spec in valid_specs), selected
        assert not any(
            "cubie-a7a-aic8800-usb" in arg for arg in selected
        ), f"mkdevcard selected stale AIC RPM after skip: {selected}"
        assert (
            str(stale_dtb) not in selected
        ), f"mkdevcard selected stale DTB RPM: {selected}"

        violations = []
        (repo_top / "existing-file").touch()
        for index, extra in enumerate(
            (
                str(stale_aic[0]),
                "./existing-file",
                "existing-file",
                "bare.rpm",
                "https://example.invalid/board.rpm",
                "existing-*",
                "--disable-gpgcheck",
                "perf\n--disable-gpgcheck",
            )
        ):
            denied = run_mkdevcard(f"extra-{index}", extra)
            if denied.returncode != 1 or "EXTRA_PACKAGES:" not in denied.stderr:
                forwarded = (
                    recorded.read_text().splitlines() if recorded.exists() else []
                )
                violations.append(
                    f"EXTRA_PACKAGES accepted {extra!r} (exit {denied.returncode}, "
                    f"forwarded={extra in forwarded})"
                )
        assert not violations, "; ".join(violations)
        # The harness captures the actual stage script without building an image.
        overlay_copy = stage.index('cp -a --no-preserve=ownership "$OVERLAY"')
        assert (
            stage.index(check) < overlay_copy < stage.rindex(check)
        ), "installed-RPM gates do not bracket the overlay copy"

        # Step 3: truncated RPM snapshot fails closed.
        manifest = second / "rpm-snapshot.json"
        orig_manifest = manifest.read_text()
        manifest.chmod(0o644)
        manifest.write_text("\n".join(orig_manifest.splitlines()[:8]) + "\n")
        res_trunc = run_mkdevcard("trunc")
        assert (
            res_trunc.returncode != 42 and res_trunc.returncode != 0
        ), "mkdevcard accepted a truncated RPM snapshot"

        # Step 4: tampered RPM bytes fail SHA-256 verification before STAGE1.
        manifest.write_text(orig_manifest)
        manifest.chmod(0o444)
        real_dtb.chmod(0o644)
        with real_dtb.open("ab") as fh:
            fh.write(b"\x00")
        res_tamper = run_mkdevcard("tamper")
        assert res_tamper.returncode == 1 and "sha256 mismatch" in res_tamper.stderr


def _policy(*args, env=None):
    return subprocess.run(
        [sys.executable, "-I", "-B", str(repo_fedora / "devcard-policy.py"), *args],
        capture_output=True,
        text=True,
        env=env,
    )


def _fwrepo(root):
    fwrepo = root / "fwrepo"
    (fwrepo / "tools/a7a-fwlog").mkdir(parents=True)
    (fwrepo / "tools/a7a-fwlog/a7a-fwlog.c").write_text("int main(void){return 0;}\n")
    (fwrepo / "docs").mkdir(parents=True)
    (fwrepo / "docs/fwlog.md").write_text("# fwlog\n")
    return fwrepo


def _fake_fwlog_binary(work, srpm, out_dir):
    """A binary cubie-a7a-fwlog RPM whose SOURCERPM names SRPM (no aarch64 build)."""
    vr = subprocess.run(
        ["rpm", "-qp", "--qf", "%{VERSION} %{RELEASE}", str(srpm)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    top = work / f"fake-{os.getpid()}-{len(list(work.iterdir()))}"
    for d in ("SPECS", "SOURCES", "BUILD", "RPMS", "SRPMS", "tmp"):
        (top / d).mkdir(parents=True)
    spec = top / "SPECS/cubie-a7a-fwlog.spec"
    spec.write_text(
        f"Name: cubie-a7a-fwlog\nVersion: {vr[0]}\nRelease: {vr[1]}\n"
        "Summary: test\nLicense: GPL-2.0-only\n"
        "%description\ntest\n%install\nmkdir -p %{buildroot}/usr/bin\n"
        "echo hi > %{buildroot}/usr/bin/a7a-fwlog\n%files\n/usr/bin/a7a-fwlog\n"
    )
    subprocess.run(
        [
            "rpmbuild",
            "--define",
            f"_topdir {top}",
            "--define",
            f"_tmppath {top}/tmp",
            "--target",
            "aarch64-redhat-linux",
            "-bb",
            str(spec),
        ],
        check=True,
        capture_output=True,
    )
    built = next((top / "RPMS/aarch64").glob("cubie-a7a-fwlog-*.rpm"))
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / built.name
    shutil.copy2(built, dest)
    return dest


def test_rpm_manifests_bound_to_one_run():
    """Should-fix 4a / F6 B5: one run_id, the recorded SRPM and the noarch digest."""
    if not shutil.which("rpmbuild") or not shutil.which("dtc"):
        raise AssertionError("rpmbuild and dtc are required")
    with tempfile.TemporaryDirectory(prefix="a7a-runid-") as td:
        root = Path(td)
        out = root / "rpmbuild"
        fwrepo = _fwrepo(root)
        env = {**os.environ, "FWREPO": str(fwrepo), "AIC8800_SRC": str(root / "no")}
        r_bld = subprocess.run(
            ["bash", str(repo_fedora / "build-rpms.sh"), str(out)],
            env=env,
            capture_output=True,
            text=True,
        )
        assert r_bld.returncode == 0, r_bld.stderr
        run = Path(r_bld.stdout.strip())
        outputs, checks = run / "out", run / "rpm-checks"
        assert not (checks / "checked-aarch64-rpms.json").exists()
        noarch = checks / "checked-rpms.json"
        data = json.loads(noarch.read_text())
        srpm = run / data["srpm"]["relpath"]
        assert data["srpm"]["package"] == "cubie-a7a-fwlog" and srpm.is_file(), data
        assert data["srpm"]["sha256"] == sha256(srpm)

        # Missing aarch64 manifest for an FWREPO run is refused.
        r = _policy("select-rpms", str(outputs), str(checks))
        assert r.returncode != 0, "missing aarch64 manifest accepted"

        staged = _policy("stage-srpm", str(noarch), str(root / "priv"))
        assert staged.returncode == 0, staged.stderr
        copy, msha = staged.stdout.strip().split("\t")
        assert msha == sha256(noarch) and sha256(copy) == sha256(srpm)
        fake = _fake_fwlog_binary(root, Path(copy), outputs / "aarch64")
        bind = [
            "write-rpm-manifest",
            str(outputs),
            str(checks / "checked-aarch64-rpms.json"),
            "--kind",
            "aarch64",
            "--bind-noarch",
            str(noarch),
        ]
        r = _policy(*bind, str(fake))
        assert r.returncode != 0, "aarch64 manifest without --bind-noarch-sha256"
        r = _policy(*bind, "--bind-noarch-sha256", "0" * 64, str(fake))
        assert r.returncode != 0 and "changed during the run" in r.stderr, r.stderr
        r = _policy(*bind, "--bind-noarch-sha256", msha, str(fake))
        assert r.returncode == 0, r.stderr
        r = _policy("select-rpms", str(outputs), str(checks))
        assert r.returncode == 0 and "cubie-a7a-fwlog\t" in r.stdout, r.stderr

        # A stale aarch64 manifest (other run_id) and a changed noarch manifest
        # are refused by select-rpms (mkdevcard's consumer).
        arch = checks / "checked-aarch64-rpms.json"
        good = arch.read_text()
        stale = json.loads(good)
        stale["run_id"] = "20000101T000000Z-aaaaaaaa"
        arch.write_text(json.dumps(stale))
        r = _policy("select-rpms", str(outputs), str(checks))
        assert r.returncode != 0 and "does not match" in r.stderr, r.stderr
        arch.write_text(good)
        saved = noarch.read_text()
        noarch.write_text(saved.replace("\n", "\n\n", 1))
        r = _policy("select-rpms", str(outputs), str(checks))
        assert r.returncode != 0 and "bound to a different" in r.stderr, r.stderr
        noarch.write_text(saved)

        # A binary RPM built from another SRPM is refused at write time.
        renamed = outputs / "aarch64/other.rpm"
        spec_top = root / "other-src"
        for d in ("SPECS", "SOURCES", "BUILD", "RPMS", "SRPMS", "tmp"):
            (spec_top / d).mkdir(parents=True)
        (spec_top / "SPECS/x.spec").write_text(
            "Name: cubie-a7a-fwlog\nVersion: 9\nRelease: 9\nSummary: t\n"
            "License: GPL-2.0-only\n%description\nt\n"
            "%files\n"
        )
        subprocess.run(
            [
                "rpmbuild",
                "--define",
                f"_topdir {spec_top}",
                "--define",
                f"_tmppath {spec_top}/tmp",
                "--target",
                "aarch64-redhat-linux",
                "-bb",
                str(spec_top / "SPECS/x.spec"),
            ],
            check=True,
            capture_output=True,
        )
        shutil.copy2(next((spec_top / "RPMS/aarch64").glob("*.rpm")), renamed)
        r = _policy(*bind, "--bind-noarch-sha256", msha, str(renamed))
        assert r.returncode != 0 and "not the bound" in r.stderr, r.stderr
        renamed.unlink()

        # FWREPO=none: a new sealed run contains no aarch64 records or source.
        r_none = subprocess.run(
            ["bash", str(repo_fedora / "build-rpms.sh"), str(out)],
            env={**env, "FWREPO": "none"},
            capture_output=True,
            text=True,
        )
        assert r_none.returncode == 0, r_none.stderr
        none_run = Path(r_none.stdout.strip())
        assert none_run != run
        assert not (none_run / "rpm-checks").exists()
        r = _policy("load-rpm-run", str(none_run))
        assert r.returncode == 0 and "cubie-a7a-fwlog" not in r.stdout


def _aarch64_rebuild_fixture(root):
    """build-rpms.sh output plus a stubbed build-aarch64-rpms.sh environment.

    run-build-ns.sh runs its command directly; mount is a no-op; chroot
    emulates `rpmbuild --rebuild /sources/NAME` by logging NAME and producing
    a binary RPM built from that SRPM (no aarch64 toolchain needed).  With
    STUB_MUTATE set it rewrites checked-rpms.json mid-rebuild with a new
    run_id, as a concurrent build-rpms.sh run would.
    """
    repo_fed = root / "repo/fedora"
    shutil.copytree(
        repo_fedora,
        repo_fed,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    (repo_fed / "run-build-ns.sh").write_text('#!/usr/bin/env bash\nshift\nexec "$@"\n')
    out = root / "rpmbuild"
    env = {
        **os.environ,
        "FWREPO": str(_fwrepo(root)),
        "AIC8800_SRC": str(root / "no"),
        "DNF_CACHE": str(root / "cache"),
    }
    r = subprocess.run(
        ["bash", str(repo_fed / "build-rpms.sh"), str(out)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    run = Path(r.stdout.strip())
    stubs = root / "stubs"
    stubs.mkdir()
    (stubs / "mount").write_text("#!/bin/sh\nexit 0\n")
    (stubs / "dnf5").write_text("#!/bin/sh\nexit 0\n")
    log = root / "rebuilt.log"
    (stubs / "chroot").write_text(
        f"#!{sys.executable}\n"
        "import json, os, shutil, subprocess, sys\n"
        "sys.dont_write_bytecode = True\n"
        "from pathlib import Path\n"
        f"sys.path.insert(0, {str(here)!r})\n"
        "br = Path(sys.argv[1])\n"
        "name = Path(sys.argv[-1]).name\n"
        f"open({str(log)!r}, 'a').write(name + '\\n')\n"
        f"Path({str(log.with_suffix('.args.json'))!r}).write_text(json.dumps(sys.argv[2:]))\n"
        "if os.environ.get('STUB_MUTATE'):\n"
        "    m = br.parent / 'rpm-checks/checked-rpms.json'\n"
        "    d = json.loads(m.read_text())\n"
        "    d['run_id'] = '20000101T000000Z-bbbbbbbb'\n"
        "    m.write_text(json.dumps(d, indent=2, sort_keys=True) + '\\n')\n"
        "import importlib.util\n"
        f"spec = importlib.util.spec_from_file_location('t', {str(Path(__file__).resolve())!r})\n"
        "t = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(t)\n"
        "work = br / 'stubwork'\n"
        "work.mkdir(exist_ok=True)\n"
        "binary = t._fake_fwlog_binary(work, br / 'sources' / name, br / 'work/RPMS/aarch64')\n"
        "if os.environ.get('STUB_EXTRA'):\n"
        "    extra = br / 'work/RPMS/noarch/unexpected.rpm'\n"
        "    extra.parent.mkdir()\n"
        "    shutil.copyfile(binary, extra)\n"
    )
    for s in stubs.iterdir():
        s.chmod(0o755)
    env["PATH"] = f"{stubs}:{os.environ['PATH']}"
    return repo_fed, run, env, log


def test_aarch64_rebuild_uses_only_the_bound_srpm():
    """F6 B5: an extra file in srpms/ is never rebuilt or bound."""
    if not os.path.exists("/proc/sys/fs/binfmt_misc/qemu-aarch64"):
        raise AssertionError("build-aarch64-rpms.sh needs a qemu-aarch64 binfmt entry")
    with tempfile.TemporaryDirectory(prefix="a7a-aarch64-") as td:
        root = Path(td)
        repo_fed, out, env, log = _aarch64_rebuild_fixture(root)
        bound = next((out / "srpms").glob("cubie-a7a-fwlog-*.src.rpm"))
        stale = out / "srpms/cubie-a7a-fwlog-0.0-0.src.rpm"
        shutil.copy2(bound, stale)
        r = subprocess.run(
            ["bash", str(repo_fed / "build-aarch64-rpms.sh"), str(out)],
            env=env,
            capture_output=True,
            text=True,
        )
        rebuilt = log.read_text().split() if log.exists() else []
        assert rebuilt == [bound.name], f"rebuilt {rebuilt}, bound {bound.name}"
        assert r.returncode == 0, r.stderr
        rpmbuild_args = json.loads(log.with_suffix(".args.json").read_text())
        assert ("--define", "debug_package %{nil}") in zip(
            rpmbuild_args, rpmbuild_args[1:]
        ), rpmbuild_args
        r = _policy("load-rpm-run", str(out))
        assert r.returncode == 0 and "cubie-a7a-fwlog\t" in r.stdout, r.stderr


def test_aarch64_rebuild_refuses_run_change():
    """F6 B5: a noarch run change during the aarch64 rebuild is refused."""
    if not os.path.exists("/proc/sys/fs/binfmt_misc/qemu-aarch64"):
        raise AssertionError("build-aarch64-rpms.sh needs a qemu-aarch64 binfmt entry")
    with tempfile.TemporaryDirectory(prefix="a7a-aarch64-") as td:
        root = Path(td)
        repo_fed, out, env, log = _aarch64_rebuild_fixture(root)
        r = subprocess.run(
            ["bash", str(repo_fed / "build-aarch64-rpms.sh"), str(out)],
            env={**env, "STUB_MUTATE": "1"},
            capture_output=True,
            text=True,
        )
        assert log.exists(), "the rebuild did not run"
        assert r.returncode != 0, f"a mid-rebuild run change was bound:\n{r.stderr}"
        assert not (out / "rpm-checks/checked-aarch64-rpms.json").exists()
        assert not (out / "rpm-snapshot.json").exists()


def test_aarch64_rebuild_refuses_any_extra_rpm():
    """An extra output outside aarch64/ must not disappear from the gate."""
    with tempfile.TemporaryDirectory(prefix="a7a-aarch64-") as td:
        repo_fed, out, env, log = _aarch64_rebuild_fixture(Path(td))
        r = subprocess.run(
            ["bash", str(repo_fed / "build-aarch64-rpms.sh"), str(out)],
            env={**env, "STUB_EXTRA": "1"},
            capture_output=True,
            text=True,
        )
        assert log.exists(), "the rebuild did not run"
        assert r.returncode == 1, f"unexpected RPM was ignored (exit {r.returncode})"
        assert "expected exactly one aarch64 image RPM" in r.stderr, r.stderr
        assert "work/RPMS/noarch/unexpected.rpm" in r.stderr, r.stderr
        assert not (out / "rpm-snapshot.json").exists()


def main():
    case("stage: copies only the listed inputs", test_stage_copies_only_listed_inputs)
    case("stage: refuses firmware in the source", test_stage_refuses_firmware_in_source)
    case(
        "stage: refuses compressed firmware in the source",
        test_stage_refuses_compressed_firmware_in_source,
    )
    case("stage: refuses a SHA256 mismatch", test_stage_refuses_sha256_mismatch)
    case(
        "stage: refuses a missing listed input", test_stage_refuses_missing_listed_input
    )
    case(
        "stage: refuses an unsafe or firmware list entry",
        test_stage_refuses_unsafe_or_firmware_list,
    )
    case("payload: clean passes", test_payload_clean_passes)
    case("payload: rejects firmware", test_payload_rejects_firmware)
    case("payload: rejects an unlisted output", test_payload_rejects_unlisted_output)
    case("rpmbuild: fixture RPM passes payload check", test_real_rpmbuild_from_fixture)
    case(
        "payload: silently truncated rpm listing fails closed (S0-5)",
        test_payload_rejects_silent_truncation,
    )
    case(
        "build-rpms: reused OUT with older clean RPM does not hide bad build",
        test_build_rpms_reused_dir_older_rpm_does_not_satisfy_check,
    )
    case(
        "build-rpms: stale spec not rebuilt after AIC staging skipped",
        test_build_rpms_stale_spec_not_rebuilt_when_skipped,
    )
    case(
        "mkdevcard: consumes only checked manifest RPMs, never stale globs (Should-fix/S0-6)",
        test_mkdevcard_ignores_stale_rpms_and_rejects_truncated_manifest,
    )
    case(
        "build-rpms: noarch and aarch64 manifests bound to one run_id (Should-fix 4a)",
        test_rpm_manifests_bound_to_one_run,
    )
    case(
        "build-aarch64-rpms: only the bound SRPM is rebuilt (F6 B5)",
        test_aarch64_rebuild_uses_only_the_bound_srpm,
    )
    case(
        "build-aarch64-rpms: a mid-rebuild run change is refused (F6 B5)",
        test_aarch64_rebuild_refuses_run_change,
    )
    case(
        "build-aarch64-rpms: refuses every unexpected binary output",
        test_aarch64_rebuild_refuses_any_extra_rpm,
    )
    if FAILURES:
        print(f"{len(FAILURES)} test(s) FAILED")
        return 1
    print("all aic-staging tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
