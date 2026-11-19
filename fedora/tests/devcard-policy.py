#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for fedora/devcard-policy.py (the parsers and image-policy
checks behind mkdevcard.sh and verify-devcard.sh).

Every parser is exercised with fixtures, including the empty and missing
cases.  The AIC8800 provenance tests use recorded ownership lists (both TSV
and ``rpm -qlv --dump`` format) because host tests do not install RPMs;
``_live_ownership`` reads the real rpm database the same way.
Run: python3 -I fedora/tests/devcard-policy.py
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


def case(name, fn):
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
    """A recorded TSV ownership FILE for entries under ROOT.

    Each entry is ``(rel, pkg)``, ``(rel, pkg, linkto)``, or
    ``(rel, pkg, linkto, is_fedora)``.
    """
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
        # Explicit --manifest adds custom entries outside AIC dirs too.
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
        # Owned symlink to owned target passes (both TSV and rpm --dump).
        own = ownership_tsv(
            root, [(trel, "linux-firmware"), (lrel, "linux-firmware", target.name)]
        )
        problems, _ = policy.aic_problems(root, own)
        assert problems == [], problems
        dump = ownership_rpm_dump(root, [(trel, ""), (lrel, target.name)])
        problems, _ = policy.aic_problems(root, dump)
        assert problems == [], problems
        # Unowned symlink pointing to a Fedora-owned file must fail.
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
    # Read the host's signed header verbatim, without querying the host with
    # librpm. rpm and rpmkeys see only our disposable target root.
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


def repart_indented_override_drops_flag():
    with fixture() as root:
        build_repart_root(
            root,
            dropin="[Service]\n  ExecStart=\n  ExecStart=systemd-repart\n",
        )
        ok, problems = policy.repart_root_ok(root)
        assert not ok, "an indented override without --discard=no must fail"
        assert any("systemd-repart.service" in p for p in problems), problems


def repart_reset_then_new_execstart_without_flag():
    with fixture() as root:
        build_repart_root(
            root,
            dropin="[Service]\nExecStart=\nExecStart=systemd-repart --discard=yes\n",
        )
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "a reset followed by ExecStart without --discard=no must fail"


def repart_discard_no_then_yes_fails():
    with fixture() as root:
        build_repart_root(
            root,
            dropin="[Service]\nExecStart=\nExecStart=systemd-repart --discard=no --discard=yes\n",
        )
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "a later --discard=yes on the same line overrides --discard=no"


def repart_execstart_wrong_section_ignored():
    with fixture() as root:
        build_repart_root(
            root,
            dropin="[Unit]\nExecStart=\nExecStart=systemd-repart --discard=no\n",
        )
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "ExecStart outside [Service] must not satisfy the check"


def repart_indented_correct_dropin_passes():
    with fixture() as root:
        build_repart_root(
            root,
            dropin="  [Service]\n\tExecStart=\n\tExecStart=systemd-repart --discard=no\n",
        )
        ok, problems = policy.repart_root_ok(root)
        assert ok, problems


def repart_later_dropin_resets_away_the_flag():
    with fixture() as root:
        build_repart_root(root)
        write(
            root / "etc/systemd/system/systemd-repart.service.d/20-reset.conf",
            "[Service]\n  ExecStart=\n  ExecStart=systemd-repart\n",
        )
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "a later drop-in that resets ExecStart must win"


def repart_dropin_precedence_etc_overrides_usr_lib():
    with fixture() as root:
        write(root / REPART_UNIT, "[Service]\nExecStart=systemd-repart\n")
        # usr/lib sets --discard=no, but same-named /etc drop-in overrides it.
        write(
            root / "usr/lib/systemd/system/systemd-repart.service.d/10-repart.conf",
            GOOD_DROPIN,
        )
        write(
            root / "etc/systemd/system/systemd-repart.service.d/10-repart.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart\n",
        )
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "/etc drop-in must override same-named /usr/lib drop-in"
        # Same-named /etc drop-in masking /usr/lib drop-in via /dev/null.
        etc_dropin = root / "etc/systemd/system/systemd-repart.service.d/10-repart.conf"
        etc_dropin.unlink()
        etc_dropin.symlink_to("/dev/null")
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "/etc /dev/null symlink must mask /usr/lib drop-in"


def repart_overlay_drops_dropin():
    with fixture() as root:
        build_repart_root(root, dropin=None)
        ok, problems = policy.repart_root_ok(root)
        assert not ok, "a missing no-discard drop-in must fail the build check"
        assert any("systemd-repart.service" in p for p in problems), problems


def repart_etc_unit_override():
    with fixture() as root:
        build_repart_root(
            root, dropin=None, etc_unit="[Service]\nExecStart=systemd-repart\n"
        )
        ok, _ = policy.repart_root_ok(root)
        assert (
            not ok
        ), "a regular-file /etc unit override without --discard=no must fail"


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


def repart_absent_passes():
    with fixture() as root:
        ok, problems = policy.repart_root_ok(root)
        assert ok, problems


def _build_cpio_initramfs(tree, out_img):
    entries = sorted(p.relative_to(tree).as_posix() for p in tree.rglob("*"))
    res = subprocess.run(
        ["cpio", "-o", "-H", "newc", "--quiet"],
        input=("\n".join(entries) + ("\n" if entries else "")).encode(),
        cwd=tree,
        capture_output=True,
        check=True,
    )
    out_img.write_bytes(res.stdout)


def repart_precedence_cases():
    for scope in ("service.d", "systemd-.service.d", "systemd-repart@demo.service.d"):
        with fixture() as tree:
            build_repart_root(tree)
            if "@" in scope:
                write(
                    tree / "usr/lib/systemd/system/systemd-repart@.service", GOOD_DROPIN
                )
            write(
                tree / "etc/systemd/system" / scope / "90-reset.conf",
                "[Service]\nExecStart=\nExecStart=systemd-repart\n",
            )
            ok, _ = policy.repart_root_ok(tree)
            assert not ok, scope
            img = tree / "test.img"
            _build_cpio_initramfs(tree, img)
            ok, problems = policy.repart_initramfs_ok(img)
            assert not ok and any("--discard=no" in p for p in problems), (
                scope,
                problems,
            )


def repart_dir_before_scope_precedence():
    """Load-path directories beat name scopes; type-wide service.d comes last."""
    # 1. Unsafe /etc/.../systemd-.service.d/50-test.conf MUST beat safe
    #    /usr/lib/.../systemd-repart.service.d/50-test.conf (root + initramfs).
    with fixture() as tree:
        write(
            tree / "usr/lib/systemd/system/systemd-repart.service",
            "[Unit]\nDescription=Repart\n[Service]\nExecStart=systemd-repart --dry-run=no\n",
        )
        write(
            tree / "usr/lib/systemd/system/systemd-repart.service.d/50-test.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart --dry-run=no --discard=no\n",
        )
        write(
            tree / "etc/systemd/system/systemd-.service.d/50-test.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart --dry-run=no\n",
        )
        ok, problems = policy.repart_root_ok(tree)
        assert not ok and any("--discard=no" in p for p in problems), problems
        img = tree / "test.img"
        _build_cpio_initramfs(tree, img)
        ok, problems = policy.repart_initramfs_ok(img)
        assert not ok and any("--discard=no" in p for p in problems), problems

    # 2. Safe /usr/lib/.../systemd-repart.service.d/50-test.conf MUST beat unsafe
    #    type-wide /etc/.../service.d/50-test.conf (type-wide defaults last).
    with fixture() as tree:
        write(
            tree / "usr/lib/systemd/system/systemd-repart.service",
            "[Unit]\nDescription=Repart\n[Service]\nExecStart=systemd-repart --dry-run=no\n",
        )
        write(
            tree / "usr/lib/systemd/system/systemd-repart.service.d/50-test.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart --dry-run=no --discard=no\n",
        )
        write(
            tree / "etc/systemd/system/service.d/50-test.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart --dry-run=no\n",
        )
        ok, problems = policy.repart_root_ok(tree)
        assert ok, problems
        img = tree / "test.img"
        _build_cpio_initramfs(tree, img)
        ok, problems = policy.repart_initramfs_ok(img)
        assert ok, problems

    # 3. Mask in /etc/.../systemd-.service.d/10-board.conf -> /dev/null masks
    #    safe /usr/lib/.../systemd-repart.service.d/10-board.conf.
    with fixture() as tree:
        write(
            tree / "usr/lib/systemd/system/systemd-repart.service",
            "[Unit]\nDescription=Repart\n[Service]\nExecStart=systemd-repart --dry-run=no\n",
        )
        write(
            tree / "usr/lib/systemd/system/systemd-repart.service.d/10-board.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart --dry-run=no --discard=no\n",
        )
        mask = tree / "etc/systemd/system/systemd-.service.d/10-board.conf"
        mask.parent.mkdir(parents=True, exist_ok=True)
        mask.symlink_to("/dev/null")
        ok, problems = policy.repart_root_ok(tree)
        assert not ok and any("--discard=no" in p for p in problems), problems
        img = tree / "test.img"
        _build_cpio_initramfs(tree, img)
        ok, problems = policy.repart_initramfs_ok(img)
        assert not ok and any("--discard=no" in p for p in problems), problems


def repart_instance_dashed_scope():
    """Dashed scopes retaining the instance (systemd-@demo.service.d) apply."""
    # Case 1: template + unsafe /etc/.../systemd-@demo.service.d (no explicit instance unit).
    with fixture() as tree:
        build_repart_root(tree)
        write(
            tree / "usr/lib/systemd/system/systemd-repart@.service",
            "[Unit]\nDescription=Repart@\n[Service]\nExecStart=systemd-repart --discard=no\n",
        )
        write(
            tree / "etc/systemd/system/systemd-@demo.service.d/50-inst.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart\n",
        )
        ok, problems = policy.repart_root_ok(tree)
        assert not ok and any(
            "systemd-repart@demo.service" in p for p in problems
        ), problems
        img = tree / "test.img"
        _build_cpio_initramfs(tree, img)
        ok, problems = policy.repart_initramfs_ok(img)
        assert not ok and any(
            "systemd-repart@demo.service" in p for p in problems
        ), problems

    # Case 2: unsafe /etc/.../systemd-@demo.service.d/50-inst.conf beats safe
    #         /usr/lib/.../systemd-repart@demo.service.d/50-inst.conf.
    with fixture() as tree:
        build_repart_root(tree)
        write(
            tree / "usr/lib/systemd/system/systemd-repart@.service",
            "[Unit]\nDescription=Repart@\n[Service]\nExecStart=systemd-repart\n",
        )
        write(
            tree / "usr/lib/systemd/system/systemd-repart@demo.service.d/50-inst.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart --discard=no\n",
        )
        write(
            tree / "etc/systemd/system/systemd-@demo.service.d/50-inst.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart\n",
        )
        ok, problems = policy.repart_root_ok(tree)
        assert not ok and any("--discard=no" in p for p in problems), problems
        img = tree / "test.img"
        _build_cpio_initramfs(tree, img)
        ok, problems = policy.repart_initramfs_ok(img)
        assert not ok and any("--discard=no" in p for p in problems), problems

    # Case 3: unsafe /etc/.../systemd-@.service.d/50-tpl.conf applies to template.
    with fixture() as tree:
        build_repart_root(tree)
        write(
            tree / "usr/lib/systemd/system/systemd-repart@.service",
            "[Unit]\nDescription=Repart@\n[Service]\nExecStart=systemd-repart --discard=no\n",
        )
        write(
            tree / "etc/systemd/system/systemd-@.service.d/50-tpl.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart\n",
        )
        ok, problems = policy.repart_root_ok(tree)
        assert not ok and any("--discard=no" in p for p in problems), problems
        img = tree / "test.img"
        _build_cpio_initramfs(tree, img)
        ok, problems = policy.repart_initramfs_ok(img)
        assert not ok and any("--discard=no" in p for p in problems), problems


def repart_systemd_analyze_oracle():
    """Cross-check _unit_files order against offline `systemd-analyze --root= verify`."""
    assert shutil.which("systemd-analyze"), "need systemd-analyze"

    def oracle_files(root, unit):
        env = {**os.environ, "SYSTEMD_LOG_LEVEL": "debug"}
        r = subprocess.run(
            ["systemd-analyze", f"--root={root}", "--generators=no", "verify", unit],
            capture_output=True,
            text=True,
            env=env,
        )
        prefix = str(root.resolve()) + "/"
        fragment = None
        dropins = []
        in_unit = False
        for line in r.stdout.splitlines():
            stripped = line.strip()
            if stripped == f"\u2192 Unit {unit}:":
                in_unit = True
                continue
            if in_unit and stripped.startswith("\u2192 Unit "):
                break
            if not in_unit:
                continue
            if stripped.startswith("Fragment Path: "):
                fragment = stripped.split("Fragment Path: ", 1)[1].removeprefix(prefix)
            elif stripped.startswith("DropIn Path: "):
                p = stripped.split("DropIn Path: ", 1)[1]
                # systemd-analyze prints masked drop-ins too; filter /dev/null masks
                # the same way _unit_files excludes them from effective files.
                if not policy._masked(Path(p)):
                    dropins.append(p.removeprefix(prefix))
        assert (
            fragment is not None
        ), f"oracle failed for {unit}:\n{r.stdout}\n{r.stderr}"
        return [fragment] + dropins

    with fixture() as root:
        # Build a rich multi-dir, multi-scope fixture testing every precedence axis.
        write(
            root / "usr/lib/systemd/system/systemd-repart.service",
            "[Unit]\nDescription=Repart\n[Service]\nType=oneshot\nExecStart=/bin/u0\n",
        )
        write(
            root / "usr/lib/systemd/system/systemd-repart-extra@.service",
            "[Unit]\nDescription=RepartExtra\n[Service]\nType=oneshot\nExecStart=/bin/t0\n",
        )
        # Same-basename conflict across dir vs scope (/etc dashed beats /usr/lib unit).
        write(
            root / "usr/lib/systemd/system/systemd-repart.service.d/10-conflict.conf",
            "[Service]\nExecStart=/bin/usr-unit\n",
        )
        write(
            root / "etc/systemd/system/systemd-.service.d/10-conflict.conf",
            "[Service]\nExecStart=/bin/etc-dashed\n",
        )
        # Same-basename conflict: /usr/lib unit beats /etc type-wide service.d.
        write(
            root / "usr/lib/systemd/system/systemd-repart.service.d/20-type.conf",
            "[Service]\nExecStart=/bin/usr-unit-20\n",
        )
        write(
            root / "etc/systemd/system/service.d/20-type.conf",
            "[Service]\nExecStart=/bin/etc-service-20\n",
        )
        # Same-basename conflict across run vs usr/local/lib vs usr/lib.
        write(
            root / "usr/lib/systemd/system/systemd-repart.service.d/30-dir.conf",
            "[Service]\nExecStart=/bin/usr-lib-30\n",
        )
        write(
            root / "usr/local/lib/systemd/system/systemd-repart.service.d/30-dir.conf",
            "[Service]\nExecStart=/bin/usr-local-30\n",
        )
        write(
            root / "run/systemd/system/systemd-.service.d/30-dir.conf",
            "[Service]\nExecStart=/bin/run-dashed-30\n",
        )
        # Mask in /etc overrides /usr/lib drop-in.
        write(
            root / "usr/lib/systemd/system/systemd-repart.service.d/35-mask.conf",
            "[Service]\nExecStart=/bin/usr-masked\n",
        )
        mask = root / "etc/systemd/system/systemd-.service.d/35-mask.conf"
        mask.parent.mkdir(parents=True, exist_ok=True)
        mask.symlink_to("/dev/null")
        # Multi-dash + instance conflicts for systemd-repart-extra@demo.service:
        #   40-inst: /etc dashed-without-@ beats /etc dashed-with-@demo
        write(
            root / "etc/systemd/system/systemd-repart-@demo.service.d/40-inst.conf",
            "[Service]\nExecStart=/bin/etc-repart-at-demo\n",
        )
        write(
            root / "etc/systemd/system/systemd-.service.d/40-inst.conf",
            "[Service]\nExecStart=/bin/etc-systemd-dash\n",
        )
        #   45-inst: /etc systemd-@demo beats /usr/lib systemd-repart-extra@demo
        write(
            root
            / "usr/lib/systemd/system/systemd-repart-extra@demo.service.d/45-inst.conf",
            "[Service]\nExecStart=/bin/usr-exact-inst\n",
        )
        write(
            root / "etc/systemd/system/systemd-@demo.service.d/45-inst.conf",
            "[Service]\nExecStart=/bin/etc-systemd-at-demo\n",
        )
        #   50-bare: /etc systemd-repart-@demo beats /etc systemd-repart-@
        write(
            root / "etc/systemd/system/systemd-repart-@.service.d/50-bare.conf",
            "[Service]\nExecStart=/bin/etc-repart-at\n",
        )
        write(
            root / "etc/systemd/system/systemd-repart-@demo.service.d/50-bare.conf",
            "[Service]\nExecStart=/bin/etc-repart-at-demo-50\n",
        )
        #   60-only-type: type-wide service.d applies when no higher scope has it.
        write(
            root / "etc/systemd/system/service.d/60-only-type.conf",
            "[Service]\nExecStart=/bin/etc-service-60\n",
        )

        root_res = root.resolve()
        for unit in ("systemd-repart.service", "systemd-repart-extra@demo.service"):
            expected = oracle_files(root, unit)
            actual = [
                p.relative_to(root_res).as_posix()
                for p in policy._unit_files(root, unit)
            ]
            assert (
                actual == expected
            ), f"{unit}:\n  actual  ={actual}\n  expected={expected}"


def unreadable_directories_fail_closed():
    """Unreadable directories/files must raise PolicyError, never pass as empty."""
    if os.geteuid() == 0:
        return  # root bypasses DAC mode 000
    with fixture() as root:
        # 1. Unreadable systemd drop-in directory
        build_repart_root(root)
        locked_d = root / "etc/systemd/system/systemd-.service.d"
        write(
            locked_d / "99-bad.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart\n",
        )
        locked_d.chmod(0o000)
        try:
            try:
                policy.repart_root_ok(root)
                raise AssertionError("unreadable drop-in dir must raise PolicyError")
            except policy.PolicyError:
                pass
        finally:
            locked_d.chmod(0o755)

        # 2. Unreadable firmware subdirectory in aic-root / aic-overlay
        locked_fw = root / "usr/lib/firmware/aic"
        write(locked_fw / "fmacfw_8800d80_u02.bin", "blob")
        locked_fw.chmod(0o000)
        try:
            for fn in (policy.aic_root_files, policy.aic_overlay_inputs):
                try:
                    fn(root)
                    raise AssertionError(f"{fn.__name__} must fail on unreadable dir")
                except policy.PolicyError:
                    pass
        finally:
            locked_fw.chmod(0o755)

        # 3. Unreadable .repo file in enabled_repo_ids
        repo = root / "etc/yum.repos.d/hidden.repo"
        write(repo, "[rawhide]\nenabled=1\n")
        repo.chmod(0o000)
        try:
            try:
                policy.enabled_repo_ids([root / "etc/yum.repos.d"])
                raise AssertionError("unreadable .repo must raise PolicyError")
            except policy.PolicyError:
                pass
        finally:
            repo.chmod(0o644)


def repart_silent_truncated_listing():
    """B2: silent partial lsinitrd (exit 0, no stderr, cut after 1 valid row) fails."""
    with fixture() as work:
        tree = work / "tree"
        write(tree / "usr/lib/modules/placeholder", "ok\n")
        write(
            tree / "usr/lib/systemd/system/systemd-repart.service",
            "[Unit]\nDescription=Repart\n[Service]\nExecStart=systemd-repart\n",
        )
        img = work / "real.img"
        _build_cpio_initramfs(tree, img)
        rule = "=" * 72
        row = "-rw-r--r--   1 root     root            3 Nov 19 06:00 usr/lib/modules/placeholder"
        inject_log = work / "inject.log"

        # Case 1: exit 0, no stderr, truncated after 1 valid row (no closing rule).
        fake_open = work / "lsinitrd-trunc-open"
        fake_open.write_text(
            "#!/bin/sh\n"
            f'echo "injected-open:$*" >> "{inject_log}"\n'
            f'printf "%s\\n%s\\n" "{rule}" "{row}"\n'
            "exit 0\n"
        )
        fake_open.chmod(0o755)
        ok, problems = policy.repart_initramfs_ok(img, [str(fake_open)])
        assert "injected-open:" in inject_log.read_text(), "fault was not injected"
        assert not ok, f"silent truncated listing (no closing rule) passed: {problems}"

        # Case 2: exit 0, no stderr, truncated after 1 valid row WITH closing rule
        # (simulates internal cpio pipe truncation before sort in lsinitrd).
        fake_closed = work / "lsinitrd-trunc-closed"
        fake_closed.write_text(
            "#!/bin/sh\n"
            f'echo "injected-closed:$*" >> "{inject_log}"\n'
            f'printf "%s\\n%s\\n%s\\n" "{rule}" "{row}" "{rule}"\n'
            "exit 0\n"
        )
        fake_closed.chmod(0o755)
        ok, problems = policy.repart_initramfs_ok(img, [str(fake_closed)])
        assert "injected-closed:" in inject_log.read_text(), "fault was not injected"
        assert (
            not ok
        ), f"silent truncated listing (with forged closing rule) passed: {problems}"

        # Case 3: valid two-part initramfs (early cpio + gzip/xz/zstd main cpio) passes.
        early = work / "early"
        write(early / "early_cpio", "1\n")
        early_img = work / "early.cpio"
        _build_cpio_initramfs(early, early_img)
        main_tree = work / "main"
        build_repart_root(main_tree)
        main_cpio = work / "main.cpio"
        _build_cpio_initramfs(main_tree, main_cpio)
        raw_main = main_cpio.read_bytes()
        import gzip
        import lzma

        for name, compressed in (
            ("gzip", gzip.compress(raw_main)),
            ("xz", lzma.compress(raw_main)),
        ):
            combo = work / f"combo-{name}.img"
            combo.write_bytes(early_img.read_bytes() + compressed)
            ok, problems = policy.repart_initramfs_ok(combo)
            assert ok, (name, problems)


def initramfs_check_truncation_cases():
    """S0-9: initramfs-check absence checks reject silent lsinitrd and -f truncation."""
    with fixture() as work:
        tree = work / "tree"
        write(tree / "usr/lib/modules/extra/sun60i-a733-ccu.ko", "ko")
        write(
            tree / "etc/cmdline.d/20-force_drivers.conf",
            'force_drivers+=" sun60i_a733_ccu pinctrl_sun60i_a733 "\n',
        )
        img = work / "rd.img"
        _build_cpio_initramfs(tree, img)

        # Clean positive check passes; forbidden text present fails.
        ok, problems = policy.initramfs_check(
            img,
            require_paths=[r"/extra/sun60i-a733-ccu\.ko"],
            forbid_paths=[r"pinctrl-sun60i-a733"],
        )
        assert ok, problems
        ok, _ = policy.initramfs_check(
            img,
            file_rel="etc/cmdline.d/20-force_drivers.conf",
            forbid_text=[r"pinctrl"],
        )
        assert not ok, "forbidden pinctrl text must fail"

        # Silent truncation of `lsinitrd -f` after `sun60i_a733_ccu` before `pinctrl`
        # must fail closed (byte-size mismatch against verified listing).
        real_lsinitrd = shutil.which("lsinitrd")
        inject_log = work / "inject-f.log"
        wrapper = work / "lsinitrd-trunc-f"
        wrapper.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "-f" ]; then\n'
            f'  echo "injected-f:$*" >> "{inject_log}"\n'
            "  printf 'force_drivers+=\" sun60i_a733_ccu '\n"
            "  exit 0\n"
            "fi\n"
            f'exec "{real_lsinitrd}" "$@"\n'
        )
        wrapper.chmod(0o755)
        ok, problems = policy.initramfs_check(
            img,
            lsinitrd_cmd=[str(wrapper)],
            file_rel="etc/cmdline.d/20-force_drivers.conf",
            forbid_text=[r"pinctrl"],
        )
        assert "injected-f:" in inject_log.read_text(), "fault was not injected"
        assert not ok, f"truncated lsinitrd -f passed forbid_text: {problems}"


def repart_incomplete_listing():
    with fixture() as work:
        fake = work / "listing"
        for body in ("", "echo 'cpio: incomplete archive' >&2"):
            fake.write_text("#!/bin/sh\necho ========\n" + body + "\n")
            fake.chmod(0o755)
            ok, _ = policy.repart_initramfs_ok(work / "fixture.img", [str(fake)])
            assert not ok, "an incomplete listing cannot certify absence"
        tree = work / "tree"
        build_repart_root(tree)
        img = work / "truncated.img"
        _build_cpio_initramfs(tree, img)
        img.write_bytes(img.read_bytes()[:256])
        ok, _ = policy.repart_initramfs_ok(img)
        assert not ok, "lsinitrd can exit successfully despite cpio listing errors"


def repart_initramfs_cases():
    assert shutil.which("lsinitrd") and shutil.which("cpio"), "need lsinitrd and cpio"
    with fixture() as tmp:
        # 1. Initramfs without repart passes (both normal and --forbid-repart).
        tree1 = tmp / "t1"
        write(tree1 / "usr/lib/modules/placeholder", "ok\n")
        img1 = tmp / "no-repart.img"
        _build_cpio_initramfs(tree1, img1)
        ok, problems = policy.repart_initramfs_ok(img1)
        assert ok, problems
        ok, problems = policy.repart_initramfs_ok(img1, forbid_repart=True)
        assert ok, problems

        # 2. Initramfs with repart + valid drop-in passes (and fails --forbid-repart).
        tree2 = tmp / "t2"
        build_repart_root(tree2)
        img2 = tmp / "good-repart.img"
        _build_cpio_initramfs(tree2, img2)
        ok, problems = policy.repart_initramfs_ok(img2)
        assert ok, problems
        ok, problems = policy.repart_initramfs_ok(img2, forbid_repart=True)
        assert not ok, "forbid_repart must fail when active systemd-repart is present"

        # 3. Filename-only drop-in whose content drops --discard=no (indented) FAILS.
        tree3 = tmp / "t3"
        build_repart_root(
            tree3,
            dropin="[Service]\n  ExecStart=\n  ExecStart=systemd-repart\n",
        )
        img3 = tmp / "bad-dropin.img"
        _build_cpio_initramfs(tree3, img3)
        ok, _ = policy.repart_initramfs_ok(img3)
        assert not ok, "must not accept drop-in by filename alone"

        # 4. Masked unit in initramfs passes.
        tree4 = tmp / "t4"
        build_repart_root(tree4, dropin=None, etc_unit="/dev/null")
        img4 = tmp / "masked-repart.img"
        _build_cpio_initramfs(tree4, img4)
        ok, problems = policy.repart_initramfs_ok(img4)
        assert ok, problems

        # 5. Missing initramfs fails closed.
        ok, _ = policy.repart_initramfs_ok(tmp / "missing.img")
        assert not ok, "missing initramfs must fail closed"


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
        "repart: effective generic, dash and instance overrides",
        repart_precedence_cases,
    )
    case(
        "repart: directory precedence before scope, type-wide last",
        repart_dir_before_scope_precedence,
    )
    case(
        "repart: dashed scopes retaining instance (systemd-@demo.service.d)",
        repart_instance_dashed_scope,
    )
    case(
        "repart: order matches offline systemd-analyze --root= verify oracle",
        repart_systemd_analyze_oracle,
    )
    case(
        "policy: unreadable directories and repo files fail closed",
        unreadable_directories_fail_closed,
    )
    case(
        "repart: silent truncated lsinitrd listing fails closed (B2)",
        repart_silent_truncated_listing,
    )
    case(
        "initramfs-check: silent truncation of lsinitrd and -f fails closed (S0-9)",
        initramfs_check_truncation_cases,
    )
    case("repart: incomplete listing fails closed", repart_incomplete_listing)
    case("repart: good root", repart_good_root)
    case("repart: indented override drops flag", repart_indented_override_drops_flag)
    case(
        "repart: reset then ExecStart without flag",
        repart_reset_then_new_execstart_without_flag,
    )
    case("repart: --discard=no then --discard=yes", repart_discard_no_then_yes_fails)
    case(
        "repart: ExecStart outside [Service] ignored",
        repart_execstart_wrong_section_ignored,
    )
    case(
        "repart: indented correct drop-in passes", repart_indented_correct_dropin_passes
    )
    case(
        "repart: later drop-in resets away flag",
        repart_later_dropin_resets_away_the_flag,
    )
    case(
        "repart: /etc drop-in overrides /usr/lib",
        repart_dropin_precedence_etc_overrides_usr_lib,
    )
    case("repart: overlay drops the drop-in", repart_overlay_drops_dropin)
    case("repart: /etc unit override", repart_etc_unit_override)
    case("repart: masked unit", repart_masked_unit_ok)
    case("repart: repart.d without the unit", repart_conf_without_unit)
    case("repart: absent unit passes", repart_absent_passes)
    case("repart: initramfs effective command", repart_initramfs_cases)
    if FAILURES:
        print(f"{len(FAILURES)} test(s) FAILED")
        return 1
    print("all devcard-policy tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
