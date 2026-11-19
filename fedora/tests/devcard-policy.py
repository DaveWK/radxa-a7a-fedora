#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for fedora/devcard-policy.py (the build-time image-policy checks
behind mkdevcard.sh and the retained build helpers).

The checks that used to reconstruct archive and filesystem formats (cpio, zstd,
systemd drop-in precedence, ext4 and FAT listings) were removed when verify
moved to an exact build manifest; their tests were removed with them. What
remains, and is exercised here: the AIC8800 firmware provenance, the
RPM-bound ESP admission, the dnf
repository parser, and the small parsers (dumpe2fs, BLS loader, shadow,
passwd, rpmdb-list cross-check, absence).  Run: python3 -I fedora/tests/devcard-policy.py
"""

import hashlib
import importlib.util
import os
import shutil
import sqlite3
import subprocess
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
    except Exception as exc:  # a test error is a failure, not a pass
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


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


MANIFEST = """\
# name bytes sha256 role
fw_patch_table_8800d80_u02.bin 1384 abc required
fmacfw_8800d80_u02.bin 358072 def required
"""


def ownership_tsv(root, entries):
    """A recorded TSV ownership FILE for entries under ROOT."""
    lines = []
    for item in entries:
        rel, pkg = item[0], item[1]
        linkto = item[2] if len(item) > 2 else ""
        is_fedora = item[3] if len(item) > 3 else True
        digest = "" if linkto else sha256(root / rel)
        flag = "1" if is_fedora else "0"
        lines.append(f"{pkg}\t{rel}\t{digest}\t8\t{linkto}\t{flag}")
    path = root / "ownership.tsv"
    path.write_text("\n".join(lines) + "\n")
    return path


def ownership_rpm_dump(root, entries, pkg="linux-firmware"):
    """A recorded ``rpm -qlv --dump`` FILE for (rel, linkto) pairs under ROOT."""
    lines = [f"# package: {pkg}"]
    for rel, linkto in entries:
        if linkto:
            lines.append(
                f"/{rel} {len(linkto)} 1792368000 {'0' * 64} 0120777 root root 0 0 0 {linkto}"
            )
        else:
            p = root / rel
            size = p.stat().st_size
            lines.append(
                f"/{rel} {size} 1792368000 {sha256(p)} 0100644 root root 0 0 0 X"
            )
    path = root / "ownership.dump"
    path.write_text("\n".join(lines) + "\n")
    return path


def aic_overlay_refuses_firmware_paths():
    with fixture() as tmp:
        overlay = tmp / "overlay"
        bad1 = overlay / "usr/lib/firmware/aic8800_fw/USB/aic8800D80/fw.bin"
        bad2 = overlay / "usr/lib/firmware/aic/aic8800d80/new.bin"
        bad3 = overlay / "lib/firmware/aic/aic8800d80/via-usrmerge.bin"
        bad4 = overlay / "lib/firmware/aic8800_fw/via-usrmerge.bin"
        good = overlay / "opt/vendor/runtime/lib.so"
        for p in (bad1, bad2, bad3, bad4, good):
            write(p, "")
        hits = policy.aic_overlay_inputs(overlay)
        assert hits == sorted([str(bad1), str(bad2), str(bad3), str(bad4)]), hits


def aic_overlay_refuses_symlink():
    with fixture() as tmp:
        overlay = tmp / "overlay"
        link = overlay / "usr/lib/firmware/aic/aic8800d80/fmacfw.bin.xz"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to("/opt/evil.bin")
        assert policy.aic_overlay_inputs(overlay) == [str(link)]


def aic_overlay_missing_dir():
    with fixture() as tmp:
        assert policy.aic_overlay_inputs(tmp / "nope") == []


def aic_overlay_other_firmware_allowed():
    with fixture() as tmp:
        overlay = tmp / "overlay"
        write(overlay / "usr/lib/firmware/rtl_nic/rtl8125b-2.fw", "")
        assert policy.aic_overlay_inputs(overlay) == []


def aic_overlay_refuses_manifest_names_outside_aic_dirs():
    with fixture() as tmp:
        overlay = tmp / "overlay"
        bad_fw = overlay / "usr/lib/firmware/other/fmacfw_8800d80_u02.bin"
        bad_fw_xz = overlay / "usr/lib/firmware/fw_patch_table_8800d80_u02.bin.xz"
        bad_opt = overlay / "opt/vendor/fw_ble_scan_ad_filter.bin"
        good_rtl = overlay / "usr/lib/firmware/rtl_nic/rtl8125b-2.fw"
        good_opt = overlay / "opt/vendor/runtime/lib.so"
        for p in (bad_fw, bad_fw_xz, bad_opt, good_rtl, good_opt):
            write(p, "x")
        hits = policy.aic_overlay_inputs(overlay)
        assert hits == sorted([str(bad_fw), str(bad_fw_xz), str(bad_opt)]), hits
        custom_man = tmp / "custom.manifest"
        write(custom_man, "custom_aic_fw.bin 1 " + ("a" * 64) + " required\n")
        bad_custom = overlay / "usr/lib/firmware/vendor/custom_aic_fw.bin.zst"
        write(bad_custom, "y")
        hits2 = policy.aic_overlay_inputs(overlay, manifest=custom_man)
        assert str(bad_custom) in hits2, hits2
        assert (
            policy.main(["aic-overlay", str(overlay), "--manifest", str(custom_man)])
            == 1
        )


def aic_provenance_fedora_owned_passes():
    with fixture() as root:
        f = root / "usr/lib/firmware/aic/aic8800d80/fw_patch_table_8800d80_u02.bin.xz"
        write(f, "fedora-bytes")
        rel = f.relative_to(root).as_posix()
        own = ownership_tsv(root, [(rel, "linux-firmware")])
        problems, records = policy.aic_problems(root, own)
        assert problems == [], problems
        assert [r[1] for r in records] == [rel]
        dump = ownership_rpm_dump(root, [(rel, "")])
        problems, records = policy.aic_problems(root, dump)
        assert problems == [], problems
        assert [r[1] for r in records] == [rel]


def aic_provenance_clean_root():
    with fixture() as root:
        own = root / "ownership.tsv"
        own.write_text("")
        assert policy.aic_problems(root, own) == ([], [])


def aic_provenance_overlay_added_file_fails():
    with fixture() as root:
        fedora = root / "usr/lib/firmware/aic/aic8800d80/fw_patch.bin.xz"
        write(fedora, "fedora")
        added_same_dir = root / "usr/lib/firmware/aic/aic8800d80/extra.bin"
        write(added_same_dir, "ours-same-dir")
        added_override = root / "usr/lib/firmware/aic8800_fw/USB/aic8800D80/fw.bin"
        write(added_override, "ours-override")
        own = ownership_tsv(
            root, [(fedora.relative_to(root).as_posix(), "linux-firmware")]
        )
        problems, _ = policy.aic_problems(root, own)
        assert len(problems) == 2, problems
        assert all("owned by no installed package" in p for p in problems), problems
        assert any("extra.bin" in p for p in problems), problems
        assert any("aic8800_fw" in p for p in problems), problems


def aic_provenance_overlay_replacement_fails():
    with fixture() as root:
        f = root / "usr/lib/firmware/aic/aic8800d80/fw_patch.bin.xz"
        write(f, "fedora-bytes")
        own = ownership_tsv(root, [(f.relative_to(root).as_posix(), "linux-firmware")])
        write(f, "replaced-bytes")
        problems, _ = policy.aic_problems(root, own)
        assert len(problems) == 1, problems
        assert "modified" in problems[0], problems


def aic_provenance_non_fedora_package_fails():
    with fixture() as root:
        f = root / "usr/lib/firmware/aic/aic8800d80/fw_patch.bin.xz"
        write(f, "local-rpm-bytes")
        own = ownership_tsv(
            root, [(f.relative_to(root).as_posix(), "cubie-a7a-aic8800-usb", "", False)]
        )
        problems, _ = policy.aic_problems(root, own)
        assert len(problems) == 1, problems
        assert "non-Fedora package" in problems[0], problems


def aic_provenance_stray_and_manifest_paths_fail():
    with fixture() as root:
        write(root / "usr/share/cubie-a7a/aic8800-d80-usb.manifest", MANIFEST)
        stray = root / "usr/lib/firmware/elsewhere/aic8800d80.bin"
        man = root / "usr/lib/firmware/unrelated/fmacfw_8800d80_u02.bin.zst"
        write(stray, "x")
        write(man, "y")
        own = root / "ownership.tsv"
        own.write_text("")
        problems, _ = policy.aic_problems(root, own)
        assert len(problems) == 2, problems
        assert any("elsewhere" in p for p in problems), problems
        assert any("unrelated" in p for p in problems), problems


def aic_provenance_symlink_cases():
    with fixture() as root:
        target = root / "usr/lib/firmware/aic/aic8800d80/real.bin"
        write(target, "bytes")
        link = root / "usr/lib/firmware/aic/aic8800d80/link.bin"
        link.symlink_to(target.name)
        trel = target.relative_to(root).as_posix()
        lrel = link.relative_to(root).as_posix()
        own = ownership_tsv(
            root, [(trel, "linux-firmware"), (lrel, "linux-firmware", target.name)]
        )
        problems, _ = policy.aic_problems(root, own)
        assert problems == [], problems
        dump = ownership_rpm_dump(root, [(trel, ""), (lrel, target.name)])
        problems, _ = policy.aic_problems(root, dump)
        assert problems == [], problems
        own_only_target = ownership_tsv(root, [(trel, "linux-firmware")])
        problems, _ = policy.aic_problems(root, own_only_target)
        assert len(problems) == 1 and "owned by no installed package" in problems[0]


def aic_provenance_symlink_outside_fails():
    with fixture() as root:
        link = root / "usr/lib/firmware/aic/aic8800d80/link.bin"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to("../../../../../etc/hosts")
        lrel = link.relative_to(root).as_posix()
        own = ownership_tsv(
            root, [(lrel, "linux-firmware", "../../../../../etc/hosts")]
        )
        problems, _ = policy.aic_problems(root, own)
        assert len(problems) == 1, problems
        assert "symlink" in problems[0], problems


def aic_provenance_missing_rpmdb_fails_closed():
    with fixture() as root:
        assert policy.main(["aic-provenance", str(root)]) == 1


def _build_test_aic_rpm(work, name="fake-aic", vendor="Fedora Project"):
    """Build a small noarch RPM owning an AIC8800 file, entirely under WORK."""
    rb = work / f"rpmbuild-{name}"
    for sub in ("SPECS", "SOURCES", "BUILD", "RPMS", "SRPMS", "tmp"):
        (rb / sub).mkdir(parents=True, exist_ok=True)
    spec = rb / "SPECS" / f"{name}.spec"
    spec.write_text(
        f"Name: {name}\n"
        "Version: 1.0\n"
        "Release: 1\n"
        "Summary: Fixture AIC package\n"
        "License: MIT\n"
        f"Vendor: {vendor}\n"
        "BuildArch: noarch\n"
        "%description\nFixture\n"
        "%install\n"
        "mkdir -p %{buildroot}/usr/lib/firmware/aic/aic8800d80\n"
        "printf 'fixture-aic-bytes' > %{buildroot}/usr/lib/firmware/aic/aic8800d80/fmacfw_8800d80_u02.bin\n"
        "%files\n"
        "/usr/lib/firmware/aic/aic8800d80/fmacfw_8800d80_u02.bin\n"
    )
    subprocess.run(
        [
            "rpmbuild",
            "--define",
            f"_topdir {rb}",
            "--define",
            f"_tmppath {rb / 'tmp'}",
            "-bb",
            str(spec),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return next((rb / "RPMS").rglob(f"{name}-*.rpm"))


def _rpmdb_fixture(work, blobs):
    """Populate an isolated database with header blobs only; install nothing."""
    root = work / "root"
    root.mkdir()
    subprocess.run(["rpm", "--root", root, "--initdb"], check=True)
    db = root / "usr/lib/sysimage/rpm/rpmdb.sqlite"
    with sqlite3.connect(db) as dst:
        dst.executemany("INSERT INTO Packages(blob) VALUES(?)", blobs)
    subprocess.run(["rpm", "--root", root, "--rebuilddb"], check=True)
    return root


def aic_provenance_offline_rpmdb_fedora_and_modified():
    with fixture() as work:
        db = Path("/usr/lib/sysimage/rpm/rpmdb.sqlite")
        with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as src:
            rows = src.execute(
                "SELECT blob FROM Packages JOIN Name USING(hnum) WHERE key='linux-firmware'"
            ).fetchall()
        assert rows, "need Fedora linux-firmware"
        root = _rpmdb_fixture(work, rows)
        rel = Path("usr/lib/firmware/aic/aic8800d80")
        dst = root / rel
        shutil.copytree(Path("/") / rel, dst)
        problems, _ = policy.aic_problems(root)
        assert problems, "a package whose key is absent must fail"
        key = work / "fedora.asc"
        for release in (44, 45, 46):
            source = Path(
                f"/usr/share/pki/rpm-gpg/RPM-GPG-KEY-fedora-{release}-primary"
            )
            if source.is_file():
                shutil.copyfile(source, key)
                subprocess.run(["rpmkeys", "--root", root, "--import", key], check=True)
        problems, records = policy.aic_problems(root)
        assert not problems and records, problems
        assert policy.main(["aic-provenance", str(root)]) == 0
        # An overlay can carry an rpmdb without touching the firmware directory.
        # The real signer/ownership check must still reject the changed root.
        db_rel = Path("usr/lib/sysimage/rpm/rpmdb.sqlite")
        overlay = work / "overlay"
        overlay.mkdir()
        subprocess.run(["rpm", "--root", overlay, "--initdb"], check=True)
        veto = subprocess.run(
            [
                sys.executable,
                "-I",
                str(here.parent / "initramfs-policy.py"),
                "overlay",
                str(overlay),
            ],
            capture_output=True,
            text=True,
        )
        assert veto.returncode == 0, veto.stderr
        staged_db = root / db_rel
        original_db = staged_db.read_bytes()
        staged_db.write_bytes((overlay / db_rel).read_bytes())
        assert policy.main(["aic-provenance", str(root)]) == 1
        staged_db.write_bytes(original_db)
        assert policy.main(["aic-provenance", str(root)]) == 0
        with next(p for p in dst.iterdir() if p.is_file()).open("ab") as target:
            target.write(b"changed")
        problems, _ = policy.aic_problems(root)
        assert any("modified" in p for p in problems), problems


def aic_provenance_offline_unsigned():
    import rpm

    with fixture() as work:
        unsigned = _build_test_aic_rpm(work)
        ts = rpm.TransactionSet(str(work))
        with unsigned.open("rb") as f:
            header = ts.hdrFromFdno(f.fileno())
        root = _rpmdb_fixture(work, [(header.unload(),)])
        write(
            root / "usr/lib/firmware/aic/aic8800d80/fmacfw_8800d80_u02.bin",
            "fixture-aic-bytes",
        )
        problems, _ = policy.aic_problems(root)
        assert len(problems) == 1 and "non-Fedora" in problems[0], problems


def aic_provenance_report_written():
    with fixture() as root:
        f = root / "usr/lib/firmware/aic/aic8800d80/fw.bin.xz"
        write(f, "bytes")
        own = ownership_tsv(root, [(f.relative_to(root).as_posix(), "linux-firmware")])
        report = root / "report.tsv"
        rc = policy.main(
            [
                "aic-provenance",
                str(root),
                "--ownership",
                str(own),
                "--report",
                str(report),
            ]
        )
        assert rc == 0, rc
        assert report.read_text().startswith("linux-firmware\t"), report.read_text()


def aic_manifest_names_cases():
    with fixture() as root:
        write(root / "usr/share/cubie-a7a/aic8800-d80-usb.manifest", MANIFEST)
        names = policy.aic_manifest_names(root)
        assert names == [
            "fw_patch_table_8800d80_u02.bin",
            "fmacfw_8800d80_u02.bin",
        ], names
        assert policy.aic_manifest_names(root / "nope") == []


def enabled_repos_cases():
    with fixture() as root:
        d = root / "yum.repos.d"
        write(
            d / "fedora.repo",
            "[fedora]\nname=Fedora\nenabled=1\n[gcc]\nenabled=0\n",
        )
        write(d / "updates.repo", "[updates]\nenabled = 1\n[rawhide]\nenabled=0\n")
        write(d / "empty.repo", "")
        ids = policy.enabled_repo_ids([d, root / "missing"])
        assert ids == ["fedora", "updates"], ids


def enabled_repos_empty():
    with fixture() as root:
        d = root / "yum.repos.d"
        d.mkdir(parents=True)
        assert policy.enabled_repo_ids([d]) == []
        assert policy.enabled_repo_ids([root / "missing"]) == []


def dumpe2fs_cases():
    text = (
        "Block count:       123456\nFree blocks:       1000\nBlock size:        4096\n"
    )
    assert policy.format_dumpe2fs(text) == "0.47 GiB, 0.00 GiB free"
    assert policy.format_dumpe2fs("") == "0.00 GiB, 0.00 GiB free"


def loader_entry_cases():
    with fixture() as root:
        entry = root / "entry.conf"
        write(
            entry,
            "title Fedora\nversion 7.3.4\nlinux /vmlinuz\n"
            "initrd /initramfs.img\noptions root=UUID=x ro\n",
        )
        assert policy.loader_field(entry, "linux") == "/vmlinuz"
        assert policy.loader_field(entry, "initrd") == "/initramfs.img"
        assert policy.loader_field(entry, "options") == "root=UUID=x ro"
        assert policy.loader_field(entry, "missing") == ""
        assert policy.loader_field(root / "nope.conf", "linux") == ""


def loader_entry_empty_and_ws():
    with fixture() as root:
        entry = root / "entry.conf"
        write(entry, "")
        assert policy.loader_field(entry, "options") == ""
        write(entry, "options\n")
        assert policy.loader_field(entry, "options") == ""
        write(entry, "options   a=b\tc d\n")
        assert policy.loader_field(entry, "options") == "a=b c d"


def shadow_cases():
    text = (
        "root:$6$salt$hash:19000:0:99999:7:::\n"
        "bin:*:19000:0:99999:7:::\n"
        "bob:$6$x$y:19000:0:99999:7:::\n"
    )
    salt, root_hash, others = policy.shadow_fields(text)
    assert salt == "salt", salt
    assert root_hash == "$6$salt$hash", root_hash
    assert others == ["bob"], others
    assert policy.shadow_fields("") == ("", "", [])
    assert policy.shadow_fields("root:*:1:0:99999:7:::\n") == ("", "*", [])


def passwd_sole_root_cases():
    good = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n"
    assert policy.passwd_sole_root(good)
    assert not policy.passwd_sole_root("")
    assert not policy.passwd_sole_root(
        "root:x:0:0:root:/root:/bin/bash\nadmin:x:0:0::/root:/bin/sh\n"
    )
    assert not policy.passwd_sole_root(
        "root:x:0:0:root:/root:/bin/bash\ndave:x:1000:1000::/home/dave:/bin/bash\n"
    )
    assert policy.passwd_sole_root(
        "root:x:0:0:root:/root:/bin/bash\ndave:x:500:500::/home/dave:/bin/sh\n"
    )


def passwd_malformed_ids_fail():
    root = "root:x:0:0:root:/root:/bin/bash\n"
    assert policy.passwd_sole_root(
        root + "daemon:x:4294967294:4294967294::/:/bin/false\n"
    )
    for uid, gid in (("4294967295", "0"), ("20", "4294967295"), ("9" * 5000, "1")):
        assert not policy.passwd_sole_root(
            root + f"daemon:x:{uid}:{gid}::/:/bin/false\n"
        )
    assert not policy.passwd_sole_root(
        "root:x:oops:0:root:/root:/bin/bash\n"
    ), "a malformed UID must fail, not read as 0"
    assert not policy.passwd_sole_root(
        "root:x:0:oops:root:/root:/bin/bash\n"
    ), "a malformed GID must fail"
    assert not policy.passwd_sole_root(
        "root:x:0:0:root:/root:/bin/bash\ndave:x:1000::/home/dave:/bin/sh\n"
    ), "a missing GID must fail"
    assert not policy.passwd_sole_root("root:x:-1:0:root:/root:/bin/bash\n")
    with fixture() as root:
        p = root / "passwd"
        write(p, "root:x:oops:0:root:/root:/bin/bash\n")
        assert policy.main(["passwd-sole-root", str(p)]) == 1
        write(p, "root:x:0:0:root:/root:/bin/bash\n")
        assert policy.main(["passwd-sole-root", str(p)]) == 0


def verify_rpmdb_list_cases():
    """S0-8: verify-rpmdb-list rejects silently truncated `rpm -qa` output."""
    import rpm

    with fixture() as work:
        unsigned = _build_test_aic_rpm(work)
        ts = rpm.TransactionSet(str(work))
        with unsigned.open("rb") as f:
            hdr = ts.hdrFromFdno(f.fileno())
        root = _rpmdb_fixture(work, [(hdr.unload(),)])
        keys = sorted(
            Path("/usr/share/pki/rpm-gpg").glob("RPM-GPG-KEY-fedora-*-primary")
        ) or sorted(Path("/etc/pki/rpm-gpg").glob("RPM-GPG-KEY-fedora-*-primary"))
        assert keys, "need Fedora GPG key for fixture rpmdb"
        subprocess.run(
            ["rpmkeys", "--root", str(root), "--import", str(keys[0])],
            check=True,
            capture_output=True,
        )
        res = subprocess.run(
            [
                "rpm",
                "--root",
                str(root),
                "-qa",
                "--qf",
                "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH} %{RSAHEADER:pgpsig}\n",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        lines = sorted(res.stdout.splitlines())
        assert len(lines) >= 2, lines
        full_file = work / "packages-full.txt"
        full_file.write_text("\n".join(lines) + "\n")
        assert policy.verify_rpmdb_list(root, full_file) == len(lines)

        trunc_file = work / "packages-trunc.txt"
        trunc_file.write_text(lines[0] + "\n")
        try:
            policy.verify_rpmdb_list(root, trunc_file)
            raise AssertionError("verify_rpmdb_list accepted truncated rpm -qa list")
        except policy.PolicyError as exc:
            assert "mismatch" in str(exc), exc


def absence_check_cases():
    """S0-10: absence-check detects matches and fails closed on unreadable dirs."""
    with fixture() as root:
        ok, problems = policy.check_absence(
            root, "no-entries", ["home", "work", "data"]
        )
        assert ok, problems
        ok, problems = policy.check_absence(root, "no-regular-files", ["dev"])
        assert ok, problems
        ok, problems = policy.check_absence(
            root, "no-glob", ["etc/repart.d"], pattern="*.conf", recursive=True
        )
        assert ok, problems

        write(root / "home/stray", "x")
        ok, _ = policy.check_absence(root, "no-entries", ["home", "work", "data"])
        assert not ok
        write(root / "dev/kmsg", "oops")
        ok, _ = policy.check_absence(root, "no-regular-files", ["dev"])
        assert not ok
        write(root / "etc/repart.d/50-root.conf", "[Partition]\n")
        ok, _ = policy.check_absence(
            root, "no-glob", ["etc/repart.d"], pattern="*.conf", recursive=True
        )
        assert not ok
        write(
            root / "usr/lib/udev/rules.d/85-nm-unmanaged.rules",
            'ENV{NM_UNMANAGED}="1"\n',
        )
        ok, problems = policy.check_absence(
            root,
            "no-text",
            ["etc/udev/rules.d", "usr/lib/udev/rules.d"],
            pattern=r"NM_UNMANAGED",
            allow_basenames=["85-nm-unmanaged.rules"],
        )
        assert ok, problems
        write(root / "etc/udev/rules.d/99-bad.rules", 'ENV{NM_UNMANAGED}="1"\n')
        ok, _ = policy.check_absence(
            root,
            "no-text",
            ["etc/udev/rules.d", "usr/lib/udev/rules.d"],
            pattern=r"NM_UNMANAGED",
            allow_basenames=["85-nm-unmanaged.rules"],
        )
        assert not ok

        if os.geteuid() != 0:
            locked = root / "etc/ssh"
            write(locked / "ssh_host_ed25519_key", "secret")
            locked.chmod(0o000)
            try:
                try:
                    policy.check_absence(
                        root, "no-glob", ["etc/ssh"], pattern="ssh_host_*"
                    )
                    raise AssertionError("unreadable etc/ssh must raise PolicyError")
                except policy.PolicyError:
                    pass
            finally:
                locked.chmod(0o755)


# --- build-time systemd checks ------------------------------------------------


def _build_test_dtb_rpm(work, dtb_bytes, override=False, version=True):
    """A noarch cubie-a7a-dtb RPM owning the DTB, VERSION (8) and (optional) override."""
    rb = work / "rpmbuild-dtb"
    for sub in ("SPECS", "SOURCES", "BUILD", "RPMS", "SRPMS", "tmp"):
        (rb / sub).mkdir(parents=True, exist_ok=True)
    (rb / "SOURCES" / "fake.dtb").write_bytes(dtb_bytes)
    override_line = (
        "touch %{buildroot}/usr/lib/cubie-a7a/dtb/esp-override\n" if override else ""
    )
    version_line = (
        "echo 8 > %{buildroot}/usr/lib/cubie-a7a/dtb/VERSION\n" if version else ""
    )
    spec = rb / "SPECS" / "cubie-a7a-dtb.spec"
    spec.write_text(
        "Name: cubie-a7a-dtb\n"
        "Version: 1.0\n"
        "Release: 1\n"
        "Summary: Fixture DTB package\n"
        "License: MIT\n"
        "BuildArch: noarch\n"
        "%description\nFixture\n"
        "%install\n"
        "mkdir -p %{buildroot}/usr/lib/cubie-a7a/dtb/allwinner\n"
        "cp %{_sourcedir}/fake.dtb %{buildroot}/usr/lib/cubie-a7a/dtb/allwinner/sun60i-a733-cubie-a7a.dtb\n"
        + version_line
        + override_line
        + "%files\n"
        "/usr/lib/cubie-a7a/dtb/allwinner/sun60i-a733-cubie-a7a.dtb\n"
        + ("/usr/lib/cubie-a7a/dtb/VERSION\n" if version else "")
        + ("/usr/lib/cubie-a7a/dtb/esp-override\n" if override else "")
    )
    subprocess.run(
        [
            "rpmbuild",
            "--define",
            f"_topdir {rb}",
            "--define",
            f"_tmppath {rb / 'tmp'}",
            "-bb",
            str(spec),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return next((rb / "RPMS").rglob("cubie-a7a-dtb-*.rpm"))


def _esp_fixture_tree(root, dtb_bytes, marker, with_dtb=True):
    """Write the expected ESP entries (base + DTB) under root/esp."""
    esp = root / "esp"
    dirs = ["efi/boot", "efi/fedora"]
    if with_dtb:
        dirs.append("dtb/allwinner")
    for d in dirs:
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
        write(esp / rel, "x")
    if with_dtb:
        (esp / policy.ESP_DTB).write_bytes(dtb_bytes)
        (esp / policy.ESP_DTB_MARK).write_bytes(marker)
    return esp


def _esp_staged_root(
    root, version, fw_stamp="0\n", dtb=b"\xd0\x0d\xfe\xed packaged dtb\n"
):
    """The ESP admission inputs in the staged root: two stamps and installed DTB."""
    (root / "var/lib/cubie-a7a").mkdir(parents=True)
    (root / "usr/lib/cubie-a7a/dtb").mkdir(parents=True)
    (root / "var/lib/cubie-a7a/firmware-dtb-version").write_text(fw_stamp)
    (root / "usr/lib/cubie-a7a/dtb/VERSION").write_text(version)
    (root / policy.PKG_DTB).parent.mkdir()
    (root / policy.PKG_DTB).write_bytes(dtb)


def esp_staged_cases():
    if shutil.which("rpmbuild") is None or shutil.which("rpm") is None:
        print("  (skipped: rpm absent)")
        return
    with fixture() as work:
        dtb_bytes = b"\xd0\x0d\xfe\xed packaged dtb\n"
        marker = (sha256_bytes(dtb_bytes) + "\n").encode()
        rpm = _build_test_dtb_rpm(work, dtb_bytes)
        root = work / "root"
        _esp_staged_root(root, "8\n")
        esp = _esp_fixture_tree(root, dtb_bytes, marker)
        ok, problems = policy.esp_staged(root, esp, rpm)
        assert ok, problems
        # An extra ESP file is refused.
        write(esp / "efi/fedora/extra.efi", "y")
        ok, problems = policy.esp_staged(root, esp, rpm)
        assert not ok and problems == ["ESP extra=['efi/fedora/extra.efi']"], problems
        (esp / "efi/fedora/extra.efi").unlink()
        # A DTB not matching the RPM payload is refused.
        (esp / "dtb/allwinner/sun60i-a733-cubie-a7a.dtb").write_bytes(b"tampered")
        ok, problems = policy.esp_staged(root, esp, rpm)
        assert not ok and problems == [
            f"ESP {policy.ESP_DTB} sha256 {sha256_bytes(b'tampered')} is not the packaged DTB's {sha256_bytes(dtb_bytes)}"
        ], problems
        (esp / "dtb/allwinner/sun60i-a733-cubie-a7a.dtb").write_bytes(dtb_bytes)
        # A VERSION not owned/matching the RPM payload is refused.
        (root / "usr/lib/cubie-a7a/dtb/VERSION").write_text("7\n")
        ok, problems = policy.esp_staged(root, esp, rpm)
        assert not ok and problems == [
            f"{policy.PKG_DTB_VERSION} differs from the cubie-a7a-dtb RPM payload"
        ], problems


def esp_override_and_root_cases():
    with fixture() as work:
        dtb = b"\xd0\x0d\xfe\xed packaged dtb\n"
        marker = (sha256_bytes(dtb) + "\n").encode()
        rpm = _build_test_dtb_rpm(work / "unforced", dtb)
        forced = _build_test_dtb_rpm(work / "forced", dtb, override=True)
        no_version = _build_test_dtb_rpm(work / "no-version", dtb, version=False)
        root = work / "root"
        _esp_staged_root(root, "8\n", fw_stamp="8\n")
        plain = _esp_fixture_tree(work / "plain", dtb, marker, with_dtb=False)
        with_dtb = _esp_fixture_tree(work / "with-dtb", dtb, marker)
        version = root / policy.PKG_DTB_VERSION
        override = root / policy.PKG_ESP_OVERRIDE
        installed_dtb = root / policy.PKG_DTB
        ok, problems = policy.esp_staged(root, plain, rpm)
        assert ok, problems

        def refuse(label, path, reason, esp=plain, package=rpm):
            try:
                passed, errors = policy.esp_staged(root, esp, package)
            except policy.PolicyError as exc:
                passed, errors = False, [str(exc)]
            assert not passed and len(errors) == 1, (label, errors)
            assert str(path) in errors[0] and reason in errors[0], (label, errors)

        missing = work / "missing"
        refuse("no ESP", missing, "missing or non-directory ESP", esp=missing)
        version.unlink()
        refuse("missing VERSION", policy.PKG_DTB_VERSION, "No such file or directory")
        version.write_text("8\n")
        refuse(
            "unowned VERSION",
            policy.PKG_DTB_VERSION,
            f"{no_version} does not own",
            package=no_version,
        )
        for kind in ("directory", "live symlink", "dangling symlink"):
            if kind == "directory":
                override.mkdir()
            else:
                override.symlink_to(
                    version if kind == "live symlink" else work / "absent"
                )
            refuse(
                kind,
                policy.PKG_ESP_OVERRIDE,
                "exists but is not owned by cubie-a7a-dtb",
            )
            if kind == "directory":
                override.rmdir()
            else:
                override.unlink()
        installed_dtb.write_bytes(b"wrong")
        mismatch = "differs from the cubie-a7a-dtb RPM payload"
        refuse("wrong root DTB with no ESP DTB", policy.PKG_DTB, mismatch)
        (root / policy.FW_DTB_STAMP).write_text("0\n")
        refuse("wrong root DTB with ESP DTB", policy.PKG_DTB, mismatch, esp=with_dtb)
        installed_dtb.write_bytes(dtb)
        (root / policy.FW_DTB_STAMP).write_text("8\n")
        override.write_bytes(b"wrong")
        refuse(
            "malformed owned override",
            policy.PKG_ESP_OVERRIDE,
            mismatch,
            esp=with_dtb,
            package=forced,
        )
        override.write_bytes(b"")
        ok, problems = policy.esp_staged(root, with_dtb, forced)
        assert ok, problems


def esp_selected_rpm_digest_case():
    with fixture() as work:
        dtb = b"\xd0\x0d\xfe\xed packaged dtb\n"
        rpm = _build_test_dtb_rpm(work, dtb)
        root = work / "root"
        _esp_staged_root(root, "8\n", fw_stamp="8\n")
        esp = _esp_fixture_tree(work, dtb, b"", with_dtb=False)
        args = [
            sys.executable,
            "-I",
            policy.__file__,
            "esp-staged",
            str(root),
            "--esp-dir",
            str(esp),
            "--dtb-rpm",
            str(rpm),
            "--dtb-rpm-sha256",
        ]
        good = subprocess.run(
            args + [sha256_bytes(rpm.read_bytes())], capture_output=True, text=True
        )
        assert good.returncode == 0, good.stderr
        bad = subprocess.run(args + ["0" * 64], capture_output=True, text=True)
        assert (
            bad.returncode == 1
            and bad.stderr.strip()
            == f"esp-staged: sha256 mismatch for snapshot RPM: {rpm}"
        ), f"selected RPM {rpm}: expected digest refusal, got exit {bad.returncode}: {bad.stderr}"

        stamp = root / policy.FW_DTB_STAMP
        stamp.write_text("invalid\n")
        bad = subprocess.run(args + ["0" * 64], capture_output=True, text=True)
        assert (
            bad.returncode == 1
            and f"malformed DTB stamp {policy.FW_DTB_STAMP}:" in bad.stderr
        ), f"{stamp}: expected stamp refusal before RPM digest, got exit {bad.returncode}: {bad.stderr}"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def main():
    case("aic-overlay: refuses firmware paths", aic_overlay_refuses_firmware_paths)
    case("aic-overlay: refuses symlink", aic_overlay_refuses_symlink)
    case("aic-overlay: missing directory", aic_overlay_missing_dir)
    case("aic-overlay: other firmware allowed", aic_overlay_other_firmware_allowed)
    case(
        "aic-overlay: refuses manifest names outside AIC dirs",
        aic_overlay_refuses_manifest_names_outside_aic_dirs,
    )
    case("aic-provenance: Fedora-owned files pass", aic_provenance_fedora_owned_passes)
    case("aic-provenance: clean root", aic_provenance_clean_root)
    case(
        "aic-provenance: overlay-added file fails",
        aic_provenance_overlay_added_file_fails,
    )
    case(
        "aic-provenance: overlay replacement fails",
        aic_provenance_overlay_replacement_fails,
    )
    case(
        "aic-provenance: non-Fedora package fails",
        aic_provenance_non_fedora_package_fails,
    )
    case(
        "aic-provenance: stray and manifest paths fail",
        aic_provenance_stray_and_manifest_paths_fail,
    )
    case("aic-provenance: symlink ownership", aic_provenance_symlink_cases)
    case("aic-provenance: symlink outside fails", aic_provenance_symlink_outside_fails)
    case(
        "aic-provenance: missing rpmdb fails closed",
        aic_provenance_missing_rpmdb_fails_closed,
    )
    case(
        "aic-provenance: offline rpmdb Fedora linux-firmware, modified & key-removed",
        aic_provenance_offline_rpmdb_fedora_and_modified,
    )
    case(
        "aic-provenance: offline rpmdb unsigned RPM fails",
        aic_provenance_offline_unsigned,
    )
    case("aic-provenance: report written", aic_provenance_report_written)
    case("aic-manifest names", aic_manifest_names_cases)
    case("enabled repos: populated and missing dirs", enabled_repos_cases)
    case("enabled repos: empty and missing", enabled_repos_empty)
    case("dumpe2fs: sizes and empty", dumpe2fs_cases)
    case("loader entry: fields, missing file", loader_entry_cases)
    case("loader entry: empty and whitespace", loader_entry_empty_and_ws)
    case("shadow: root, others, empty", shadow_cases)
    case("passwd: sole root policy", passwd_sole_root_cases)
    case("passwd: malformed uid/gid fails", passwd_malformed_ids_fail)
    case(
        "verify-rpmdb-list: silent rpm -qa truncation fails closed",
        verify_rpmdb_list_cases,
    )
    case("absence-check: matches and unreadable dirs fail closed", absence_check_cases)
    case("esp-staged: the RPM-bound ESP admission (green/red)", esp_staged_cases)
    case(
        "esp-staged: root DTB and override ownership in both branches",
        esp_override_and_root_cases,
    )
    case(
        "esp-staged: the selected DTB RPM digest and admission order",
        esp_selected_rpm_digest_case,
    )
    if FAILURES:
        print(f"{len(FAILURES)} test(s) FAILED")
        return 1
    print("all devcard-policy tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
