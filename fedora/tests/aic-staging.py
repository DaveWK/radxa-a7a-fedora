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
            return type("R", (), {"stdout": self.dkms_ver + "\n", "returncode": 0})()
        return type(
            "R", (), {"stdout": "\n".join(self.paths) + "\n", "returncode": 0}
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
        v1_rpms = list((out / "RPMS").rglob("cubie-a7a-aic8800-usb-0.4-1.*.rpm"))
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
    """A stale spec left in a reused OUT/SPECS must not rebuild after staging
    was skipped (AIC8800_SRC unset)."""
    if not shutil.which("rpmbuild"):
        return
    with tempfile.TemporaryDirectory(prefix="a7a-build-stale-") as td:
        root = Path(td)
        src = fixture_src(root)
        repo_fed = _fixture_repo_copy(root, src)
        out = root / "out"

        # Step 1: build with AIC8800_SRC so OUT/SPECS and OUT/SOURCES hold AIC files.
        env_with = os.environ.copy()
        env_with["AIC8800_SRC"] = str(src)
        r1 = subprocess.run(
            ["bash", str(repo_fed / "build-rpms.sh"), str(out)],
            env=env_with,
            capture_output=True,
            text=True,
        )
        assert r1.returncode == 0, f"initial build failed:\n{r1.stdout}\n{r1.stderr}"
        # Remove the AIC RPMs from OUT/RPMS and OUT/SRPMS, leaving stale SPECS + SOURCES.
        for p in list((out / "RPMS").rglob("cubie-a7a-aic8800-usb-*.rpm")) + list(
            (out / "SRPMS").rglob("cubie-a7a-aic8800-usb-*.rpm")
        ):
            p.unlink()
        assert (out / "SPECS/cubie-a7a-aic8800-usb.spec").is_file()

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
        rebuilt = list((out / "RPMS").rglob("cubie-a7a-aic8800-usb-*.rpm")) + list(
            (out / "SRPMS").rglob("cubie-a7a-aic8800-usb-*.rpm")
        )
        assert rebuilt == [], f"stale AIC spec was rebuilt after skip: {rebuilt}"


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
        "build-rpms: reused OUT with older clean RPM does not hide bad build",
        test_build_rpms_reused_dir_older_rpm_does_not_satisfy_check,
    )
    case(
        "build-rpms: stale spec not rebuilt after AIC staging skipped",
        test_build_rpms_stale_spec_not_rebuilt_when_skipped,
    )
    if FAILURES:
        print(f"{len(FAILURES)} test(s) FAILED")
        return 1
    print("all aic-staging tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
