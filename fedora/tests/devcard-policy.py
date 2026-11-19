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
STOCK_UNIT = "[Service]\nExecStart=systemd-repart --dry-run=no\n"
GOOD_DROPIN = policy.repart_dropin_text("systemd-repart.service", STOCK_UNIT)


def build_repart_root(root, dropin=GOOD_DROPIN, etc_unit=None):
    write(root / REPART_UNIT, STOCK_UNIT)
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


def repart_indented_correct_dropin_refused():
    """F6: the drop-in is pinned to mkdevcard's bytes; an equivalent rewrite is refused."""
    with fixture() as root:
        build_repart_root(
            root,
            dropin="  [Service]\n\tExecStart=\n"
            "\tExecStart=systemd-repart --dry-run=no --discard=no\n",
        )
        ok, problems = policy.repart_root_ok(root)
        assert not ok and any(
            "differs from the drop-in" in p for p in problems
        ), problems


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


def _raw_cpio(tree):
    entries = sorted(p.relative_to(tree).as_posix() for p in tree.rglob("*"))
    res = subprocess.run(
        ["cpio", "-o", "-H", "newc", "--quiet"],
        input=("\n".join(entries) + ("\n" if entries else "")).encode(),
        cwd=tree,
        capture_output=True,
        check=True,
    )
    return res.stdout


def _build_cpio_initramfs(tree, out_img):
    import compression.zstd as zstd

    out_img.write_bytes(zstd.compress(_raw_cpio(tree)))


def repart_pinned_refusals():
    """B1: aliases, unexpected repart drop-in dirs and unexpected service.d are refused."""
    # 1. Alias symlink to systemd-repart.service + alias drop-in directory (root + initramfs).
    with fixture() as tree:
        build_repart_root(tree)
        alias = tree / "etc/systemd/system/repart-alias.service"
        alias.symlink_to("systemd-repart.service")
        write(
            tree / "etc/systemd/system/repart-alias.service.d/90-bad.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart\n",
        )
        ok, problems = policy.repart_root_ok(tree)
        assert not ok and any("alias symlink" in p for p in problems), problems
        assert any("alias drop-in directory" in p for p in problems), problems
        img = tree / "alias.img"
        _build_cpio_initramfs(tree, img)
        ok, problems = policy.repart_initramfs_ok(img)
        assert not ok and any("alias symlink" in p for p in problems), problems
        assert any("alias drop-in directory" in p for p in problems), problems

    # 2. Multi-hop alias symlink chain (a.service -> b.service -> systemd-repart.service).
    with fixture() as tree:
        build_repart_root(tree)
        (tree / "etc/systemd/system/b.service").symlink_to("systemd-repart.service")
        (tree / "etc/systemd/system/a.service").symlink_to("b.service")
        ok, problems = policy.repart_root_ok(tree)
        assert not ok and any("alias symlink" in p for p in problems), problems
        img = tree / "chain.img"
        _build_cpio_initramfs(tree, img)
        ok, problems = policy.repart_initramfs_ok(img)
        assert not ok and any("alias symlink" in p for p in problems), problems

    # 3. Alias symlink FROM checked unit (not /dev/null mask).
    with fixture() as tree:
        build_repart_root(tree)
        write(
            tree / "usr/lib/systemd/system/other.service",
            "[Service]\nExecStart=systemd-repart --discard=no\n",
        )
        (tree / "etc/systemd/system/systemd-repart.service").symlink_to("other.service")
        ok, problems = policy.repart_root_ok(tree)
        assert not ok and any("alias symlink from" in p for p in problems), problems
        img = tree / "from.img"
        _build_cpio_initramfs(tree, img)
        ok, problems = policy.repart_initramfs_ok(img)
        assert not ok and any("alias symlink from" in p for p in problems), problems

    # 4. [Install] Alias= in checked unit and in drop-in (root + initramfs).
    for where in ("unit", "dropin"):
        with fixture() as tree:
            build_repart_root(tree)
            if where == "unit":
                write(
                    tree / REPART_UNIT,
                    "[Service]\nExecStart=systemd-repart\n[Install]\nAlias=repart-alias.service\n",
                )
            else:
                write(
                    tree / REPART_DROPIN,
                    GOOD_DROPIN + "[Install]\nAlias=repart-alias.service\n",
                )
            ok, problems = policy.repart_root_ok(tree)
            assert not ok and any("[Install] Alias=" in p for p in problems), problems
            img = tree / f"install-{where}.img"
            _build_cpio_initramfs(tree, img)
            ok, problems = policy.repart_initramfs_ok(img)
            assert not ok and any("[Install] Alias=" in p for p in problems), problems

    # 5. Unexpected drop-in directories for systemd-repart* (dashed & instance).
    for dname in (
        "systemd-.service.d",
        "systemd-@.service.d",
        "systemd-@demo.service.d",
        "systemd-repart@demo.service.d",
        "systemd-repart-extra.service.d",
    ):
        with fixture() as tree:
            build_repart_root(tree)
            write(
                tree / "etc/systemd/system" / dname / "50-extra.conf",
                "[Service]\nTimeoutStartSec=5\n",
            )
            ok, problems = policy.repart_root_ok(tree)
            assert not ok and any("unexpected repart drop-in" in p for p in problems), (
                dname,
                problems,
            )
            img = tree / "dropin.img"
            _build_cpio_initramfs(tree, img)
            ok, problems = policy.repart_initramfs_ok(img)
            assert not ok and any("unexpected repart drop-in" in p for p in problems), (
                dname,
                problems,
            )

    # 6. Type-wide service.d drop-ins: stock Fedora 10-timeout-abort.conf without
    #    ExecStart/Alias passes; any unexpected file or ExecStart/Alias is refused.
    with fixture() as tree:
        build_repart_root(tree)
        write(
            tree / "usr/lib/systemd/system/service.d/10-timeout-abort.conf",
            "[Service]\nTimeoutStopFailureMode=abort\n",
        )
        ok, problems = policy.repart_root_ok(tree)
        assert ok, problems
        img = tree / "vendor-ok.img"
        _build_cpio_initramfs(tree, img)
        ok, problems = policy.repart_initramfs_ok(img)
        assert ok, problems

    for rel, body in (
        (
            "etc/systemd/system/service.d/90-extra.conf",
            "[Service]\nTimeoutStartSec=5\n",
        ),
        (
            "usr/lib/systemd/system/service.d/90-extra.conf",
            "[Service]\nTimeoutStartSec=5\n",
        ),
        (
            "usr/lib/systemd/system/service.d/10-timeout-abort.conf",
            "[Service]\nExecStart=\nExecStart=systemd-repart --discard=no\n",
        ),
    ):
        with fixture() as tree:
            build_repart_root(tree)
            write(tree / rel, body)
            ok, problems = policy.repart_root_ok(tree)
            assert not ok and any("type-wide drop-in" in p for p in problems), (
                rel,
                problems,
            )
            img = tree / "service-d.img"
            _build_cpio_initramfs(tree, img)
            ok, problems = policy.repart_initramfs_ok(img)
            assert not ok and any("type-wide drop-in" in p for p in problems), (
                rel,
                problems,
            )


def _bad_dropin(path):
    write(path, "[Service]\nExecStart=\nExecStart=systemd-repart --dry-run=no\n")


def repart_prefilter_initramfs_cases():
    """F6 B2: raw cpio records; symlinked or unexpected .d refused before filtering."""
    cases = {}
    # A symlinked systemd-repart.service.d whose target hides an override.
    cases["symlinked-repart-d"] = lambda t: (
        _bad_dropin(t / "opt/rd/90-bad.conf"),
        (t / "usr/lib/systemd/system/systemd-repart.service.d").symlink_to("/opt/rd"),
    )
    # A symlinked type-wide service.d whose target hides an override.
    cases["symlinked-service-d"] = lambda t: (
        _bad_dropin(t / "opt/sd/90-bad.conf"),
        (t / "usr/lib/systemd/system/service.d").symlink_to("/opt/sd"),
    )
    # An empty unexpected drop-in directory for a checked unit.
    cases["empty-unexpected-d"] = lambda t: (
        t / "usr/lib/systemd/system/systemd-repart.service.d"
    ).mkdir(parents=True)
    # An extra directive in the stock type-wide file.
    cases["stock-extra-directive"] = lambda t: write(
        t / "usr/lib/systemd/system/service.d/10-timeout-abort.conf",
        "[Service]\nTimeoutStopFailureMode=abort\nExecStartPre=/bin/true\n",
    )
    for name, plant in cases.items():
        with fixture() as work:
            t = work / "tree"
            build_repart_root(t)
            (t / "usr/lib/systemd/system").mkdir(parents=True, exist_ok=True)
            plant(t)
            img = work / f"{name}.img"
            _build_cpio_initramfs(t, img)
            ok, problems = policy.repart_initramfs_ok(img)
            assert not ok, f"{name}: initramfs accepted: {problems}"
            ok, problems = policy.repart_root_ok(t)
            assert not ok, f"{name}: root accepted: {problems}"
    # The unchanged fixture passes both ways.
    with fixture() as work:
        t = work / "tree"
        build_repart_root(t)
        write(
            t / "usr/lib/systemd/system/service.d/10-timeout-abort.conf",
            "# stock\n[Service]\nTimeoutStopFailureMode=abort\n",
        )
        img = work / "good.img"
        _build_cpio_initramfs(t, img)
        ok, problems = policy.repart_initramfs_ok(img)
        assert ok, problems
        ok, problems = policy.repart_root_ok(t)
        assert ok, problems


def repart_initramfs_bytes_from_cpio():
    """F6 B2: types and bytes come from the cpio records, not lsinitrd."""
    with fixture() as work:
        t = work / "tree"
        build_repart_root(t, dropin="[Service]\nExecStart=\nExecStart=systemd-repart\n")
        img = work / "bad.img"
        _build_cpio_initramfs(t, img)
        real = shutil.which("lsinitrd")
        good = work / "good-dropin.conf"
        good.write_text(GOOD_DROPIN)
        log = work / "inject.log"
        log.write_text("")
        # lsinitrd that lies about the drop-in's bytes (-f) must not matter.
        wrap = work / "lsinitrd-lie"
        wrap.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "-f" ]; then\n'
            f'  echo "injected-f:$*" >> "{log}"\n'
            f'  cat "{good}"\n'
            "  exit 0\n"
            "fi\n"
            f'exec "{real}" "$@"\n'
        )
        wrap.chmod(0o755)
        ok, problems = policy.repart_initramfs_ok(img, [str(wrap)])
        assert not ok, f"lsinitrd -f bytes trusted over the archive: {problems}"


def repart_grow_root_cases():
    """F6 B2: GROW_ROOT=yes needs the unit present, unmasked, enabled, our repart.d."""

    def good_yes(t):
        build_repart_root(t)
        link = t / "usr/lib/systemd/system/sysinit.target.wants/systemd-repart.service"
        link.parent.mkdir(parents=True)
        link.symlink_to("../systemd-repart.service")
        write(t / "etc/repart.d/50-root.conf", "[Partition]\nType=root\n")

    with fixture() as t:
        good_yes(t)
        ok, problems = policy.repart_root_ok(t, grow_root="yes")
        assert ok, problems
        assert policy.main(["repart-root", "--grow-root", "yes", str(t)]) == 0
    for label, mutate in (
        (
            "masked",
            lambda t: (t / "etc/systemd/system/systemd-repart.service").symlink_to(
                "/dev/null"
            ),
        ),
        (
            "not-enabled",
            lambda t: (
                t / "usr/lib/systemd/system/sysinit.target.wants/systemd-repart.service"
            ).unlink(),
        ),
        (
            "extra-repart.d",
            lambda t: write(t / "usr/lib/repart.d/60-swap.conf", "[Partition]\n"),
        ),
        (
            "changed-50-root",
            lambda t: write(
                t / "etc/repart.d/50-root.conf",
                "[Partition]\nType=root\nSizeMaxBytes=1G\n",
            ),
        ),
    ):
        with fixture() as t:
            good_yes(t)
            mutate(t)
            ok, problems = policy.repart_root_ok(t, grow_root="yes")
            assert not ok, (label, problems)
            assert policy.main(["repart-root", "--grow-root", "yes", str(t)]) == 1
    # GROW_ROOT=no: masked in /etc, no repart.d.
    with fixture() as t:
        build_repart_root(t, etc_unit="/dev/null")
        ok, problems = policy.repart_root_ok(t, grow_root="no")
        assert ok, problems
        write(t / "etc/repart.d/50-root.conf", "[Partition]\nType=root\n")
        ok, problems = policy.repart_root_ok(t, grow_root="no")
        assert not ok, problems
    with fixture() as t:
        build_repart_root(t)
        ok, problems = policy.repart_root_ok(t, grow_root="no")
        assert not ok and any("/dev/null" in p for p in problems), problems


def repart_dropin_writer_cases():
    """F6 B2: mkdevcard writes the drop-in with the rule's own writer."""
    with fixture() as t:
        unit = t / "u.service"
        unit.write_text(STOCK_UNIT)
        assert policy.repart_dropin_text("systemd-repart.service", STOCK_UNIT).endswith(
            "ExecStart=\nExecStart=systemd-repart --dry-run=no --discard=no\n"
        )
        for stock in (
            "[Service]\nExecStart=systemd-repart\n",
            "[Service]\nExecStart=systemd-repart --dry-run=no --discard=yes\n",
            "[Service]\nExecStart=systemd-repart --dry-run=no\nExecStart=x\n",
        ):
            unit.write_text(stock)
            rc = policy.main(["repart-dropin", "systemd-repart.service", str(unit)])
            assert rc == 1, stock
    mk = (here.parent / "mkdevcard.sh").read_text()
    assert 'repart-dropin "$u" "$unit"' in mk
    assert 'repart-root --grow-root "$GROW_ROOT" "$ROOT"' in mk
    vd = (here.parent / "verify-devcard.sh").read_text()
    assert 'repart-root --grow-root "$GROW_ROOT" "$ROOT"' in vd


def repart_systemd_analyze_oracle():
    """Cross-check exact-unit _unit_files order against offline systemd-analyze verify."""
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
                if not policy._masked(Path(p)):
                    dropins.append(p.removeprefix(prefix))
        assert (
            fragment is not None
        ), f"oracle failed for {unit}:\n{r.stdout}\n{r.stderr}"
        return [fragment] + dropins

    with fixture() as root:
        write(
            root / "usr/lib/systemd/system/systemd-repart.service",
            "[Unit]\nDescription=Repart\n[Service]\nType=oneshot\nExecStart=/bin/u0\n",
        )
        write(
            root / "usr/lib/systemd/system/systemd-repart.service.d/10-dropin.conf",
            "[Service]\nExecStart=/bin/usr-10\n",
        )
        write(
            root / "etc/systemd/system/systemd-repart.service.d/10-dropin.conf",
            "[Service]\nExecStart=/bin/etc-10\n",
        )
        write(
            root / "usr/lib/systemd/system/systemd-repart.service.d/20-dir.conf",
            "[Service]\nExecStart=/bin/usr-lib-20\n",
        )
        write(
            root / "usr/local/lib/systemd/system/systemd-repart.service.d/20-dir.conf",
            "[Service]\nExecStart=/bin/usr-local-20\n",
        )
        write(
            root / "run/systemd/system/systemd-repart.service.d/20-dir.conf",
            "[Service]\nExecStart=/bin/run-20\n",
        )
        write(
            root / "usr/lib/systemd/system/systemd-repart.service.d/35-mask.conf",
            "[Service]\nExecStart=/bin/usr-masked\n",
        )
        mask = root / "etc/systemd/system/systemd-repart.service.d/35-mask.conf"
        mask.parent.mkdir(parents=True, exist_ok=True)
        mask.symlink_to("/dev/null")

        root_res = root.resolve()
        unit = "systemd-repart.service"
        expected = oracle_files(root, unit)
        actual = [
            p.relative_to(root_res).as_posix() for p in policy._unit_files(root, unit)
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
        locked_d = root / "etc/systemd/system/systemd-repart.service.d"
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

        # Case 3: valid two-part initramfs (early cpio + one zstd frame) passes;
        # multi-frame zstd is refused (zstd_single_frame_cases).
        import bz2
        import compression.zstd as zstd
        import gzip
        import lzma

        early = work / "early"
        write(early / "early_cpio", "1\n")
        raw_early = _raw_cpio(early)
        main_tree = work / "main"
        build_repart_root(main_tree)
        raw_main = _raw_cpio(main_tree)
        zstd_main = zstd.compress(raw_main)

        combo = work / "combo-zstd.img"
        combo.write_bytes(raw_early + zstd_main)
        ok, problems = policy.repart_initramfs_ok(combo)
        assert ok, ("early+zstd", problems)

        # Case 4 (B2): valid zstd frame followed by truncated frame, garbage or trailing NUL is refused.
        for label, bad_bytes in (
            ("zstd+trunc", zstd_main + zstd_main[:10]),
            ("zstd+garbage", zstd_main + b"TRAILING_GARBAGE"),
            ("zstd+nul", zstd_main + b"\x00"),
            ("early+zstd+garbage", raw_early + zstd_main + b"JUNK"),
        ):
            bad_img = work / f"{label}.img"
            bad_img.write_bytes(bad_bytes)
            try:
                policy.parse_cpio_initramfs(bad_img)
                raise AssertionError(f"{label} must be refused")
            except policy.PolicyError:
                pass

        # Case 5 (B2 + 4b): non-zstd compressors and uncompressed-only cpio are refused.
        for label, other_bytes in (
            ("gzip", gzip.compress(raw_main)),
            ("xz", lzma.compress(raw_main)),
            ("xz+garbage", lzma.compress(raw_main) + b"TRAILING_GARBAGE"),
            ("bzip2", bz2.compress(raw_main)),
            ("bzip2+garbage", bz2.compress(raw_main) + b"TRAILING_GARBAGE"),
            ("lz4", b"\x04\x22\x4d\x18" + b"\x00" * 16),
            ("lzo", b"\x89LZO\x00\x0d\x0a\x1a\x0a" + b"\x00" * 16),
            ("lzma-legacy", b"\x5d\x00\x00\x80\x00" + b"\x00" * 16),
            ("uncompressed-only", raw_main),
        ):
            other_img = work / f"other-{label}.img"
            other_img.write_bytes(other_bytes)
            try:
                policy.parse_cpio_initramfs(other_img)
                raise AssertionError(f"non-zstd compressor {label} must be refused")
            except policy.PolicyError:
                pass

        # Case 6 (4b): padded newc names (extra trailing NULs inside namesize, 4-byte aligned)
        # parse cleanly and match lsinitrd; non-NUL after NUL is refused.
        def newc_rec(raw_name, payload=b"", mode=0o100644):
            hdr = (
                f"070701{1:08x}{mode:08x}{0:08x}{0:08x}{1:08x}{0:08x}"
                f"{len(payload):08x}{0:08x}{0:08x}{0:08x}{0:08x}"
                f"{len(raw_name):08x}{0:08x}"
            ).encode("ascii")
            rec = hdr + raw_name
            rec += b"\x00" * ((-len(rec)) % 4)
            rec += payload
            rec += b"\x00" * ((-len(rec)) % 4)
            return rec

        padded_cpio = newc_rec(b"etc/hello.txt\x00\x00\x00", b"hi\n") + newc_rec(
            b"TRAILER!!!\x00", b"", mode=0
        )
        padded_img = work / "padded-name.img"
        padded_img.write_bytes(zstd.compress(padded_cpio))
        parsed = policy.parse_cpio_initramfs(padded_img)
        assert parsed == [("file", "etc/hello.txt", 3)], parsed
        records = policy.inspect_initramfs(padded_img)
        assert [r[1] for r in records] == ["etc/hello.txt"], records

        corrupt_cpio = newc_rec(b"etc/a\x00junk\x00", b"hi\n") + newc_rec(
            b"TRAILER!!!\x00", b"", mode=0
        )
        corrupt_img = work / "corrupt-name.img"
        corrupt_img.write_bytes(zstd.compress(corrupt_cpio))
        try:
            policy.parse_cpio_initramfs(corrupt_img)
            raise AssertionError("embedded non-NUL after NUL in newc name must fail")
        except policy.PolicyError:
            pass


def zstd_single_frame_cases():
    """F6 B1: exactly one zstd frame after an optional early cpio; frames never joined."""
    import compression.zstd as zstd

    with fixture() as work:
        tree = work / "main"
        write(tree / "usr/lib/modules/placeholder", "ok\n")
        write(tree / "etc/hello.txt", "hi\n")
        raw = _raw_cpio(tree)
        early_tree = work / "early"
        write(early_tree / "early_cpio", "1\n")
        raw_early = _raw_cpio(early_tree)

        # One frame (with and without early cpio) passes.
        for label, blob in (
            ("one-frame", zstd.compress(raw)),
            ("early+one-frame", raw_early + zstd.compress(raw)),
        ):
            img = work / f"{label}.img"
            img.write_bytes(blob)
            rels = [r for _, r, _ in policy.parse_cpio_initramfs(img)]
            assert "etc/hello.txt" in rels, (label, rels)

        # A cpio header split across two frames (Linux rejects it) is refused.
        second = raw.index(b"070701", 1)
        split_at = second + 40  # inside the second 110-byte newc header
        split = zstd.compress(raw[:split_at]) + zstd.compress(raw[split_at:])
        # A second frame on an entry boundary is refused too: never join frames.
        boundary = zstd.compress(raw[:second]) + zstd.compress(raw[second:])
        skip_after = (
            zstd.compress(raw) + b"\x50\x2a\x4d\x18" + (4).to_bytes(4, "little")
        )
        skip_after += b"SKIP"
        skip_before = b"\x50\x2a\x4d\x18" + (4).to_bytes(4, "little") + b"SKIP"
        skip_before += zstd.compress(raw)
        for label, blob in (
            ("split-header", split),
            ("two-frames-on-boundary", boundary),
            ("early+split-header", raw_early + split),
            ("skippable-after", skip_after),
            ("skippable-before", skip_before),
        ):
            img = work / f"{label}.img"
            img.write_bytes(blob)
            try:
                policy.parse_cpio_initramfs(img)
            except policy.PolicyError as exc:
                msg = str(exc)
                assert "multi-frame" in msg or "non-zstd" in msg, (label, msg)
            else:
                raise AssertionError(f"{label}: multi-frame zstd initramfs accepted")
            ok, problems = policy.repart_initramfs_ok(img)
            assert not ok, (label, problems)


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

        # The member's bytes come from the raw cpio record, never `lsinitrd -f`:
        # a wrapper that truncates -f output is never consulted (F6 B2).
        real_lsinitrd = shutil.which("lsinitrd")
        inject_log = work / "inject-f.log"
        inject_log.write_text("")
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
        assert "injected-f:" not in inject_log.read_text(), "lsinitrd -f was used"
        assert not ok, f"forbidden text in the cpio member passed: {problems}"


def verify_rpmdb_list_cases():
    """S0-8: verify-rpmdb-list rejects silently truncated `rpm -qa` output."""
    import rpm

    with fixture() as work:
        unsigned = _build_test_aic_rpm(work)
        ts = rpm.TransactionSet(str(work))
        with unsigned.open("rb") as f:
            hdr = ts.hdrFromFdno(f.fileno())
        root = _rpmdb_fixture(work, [(hdr.unload(),)])
        # Import a real Fedora pubkey into the fixture rpmdb so there are >=2 entries.
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

        # Silent truncation after 1 valid row (exit 0, no stderr) must fail closed.
        trunc_file = work / "packages-trunc.txt"
        trunc_file.write_text(lines[0] + "\n")
        try:
            policy.verify_rpmdb_list(root, trunc_file)
            raise AssertionError("verify_rpmdb_list accepted truncated rpm -qa list")
        except policy.PolicyError as exc:
            assert "mismatch" in str(exc), exc


def absence_check_cases():
    """S0-10: absence-check detects matches and fails closed on unreadable dirs/files."""
    with fixture() as root:
        # Clean root passes all modes.
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

        # Real hits fail.
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


ESP_BASE_FILES = (
    "EFI/BOOT/BOOTAA64.EFI",
    "EFI/BOOT/fbaa64.efi",
    "EFI/fedora/BOOTAA64.CSV",
    "EFI/fedora/grub.cfg",
    "EFI/fedora/grubaa64.efi",
    "EFI/fedora/mmaa64.efi",
    "EFI/fedora/shim.efi",
    "EFI/fedora/shimaa64.efi",
)
DTB_BYTES = b"\xd0\x0d\xfe\xed packaged dtb\n"


def _esp_root(work, fw="0\n", pkg="8\n"):
    """A root with DTB stamps, the packaged DTB and its recorded payload digest."""
    root = work / "root"
    write(root / "var/lib/cubie-a7a/firmware-dtb-version", fw)
    write(root / "usr/lib/cubie-a7a/dtb/VERSION", pkg)
    dtb = root / "usr/lib/cubie-a7a/dtb/allwinner/sun60i-a733-cubie-a7a.dtb"
    dtb.parent.mkdir(parents=True)
    dtb.write_bytes(DTB_BYTES)
    own = work / "ownership.tsv"
    own.write_text(
        f"cubie-a7a-dtb\tusr/lib/cubie-a7a/dtb/allwinner/sun60i-a733-cubie-a7a.dtb\t"
        f"{hashlib.sha256(DTB_BYTES).hexdigest()}\t8\t\t0\n"
    )
    return root, own


def _esp_tree(work, dtb=True, dtb_bytes=DTB_BYTES, mark=None):
    src = work / "esp"
    for rel in ESP_BASE_FILES:
        write(src / rel, "ok\n")
    if dtb:
        d = src / "dtb/allwinner"
        d.mkdir(parents=True)
        (d / "sun60i-a733-cubie-a7a.dtb").write_bytes(dtb_bytes)
        digest = hashlib.sha256(DTB_BYTES).hexdigest() if mark is None else mark
        (d / "sun60i-a733-cubie-a7a.dtb.cubie-a7a-dtb").write_text(digest + "\n")
    return src


def _esp_img(work, src):
    esp = work / "esp.img"
    subprocess.run(
        ["mkfs.fat", "-F", "32", "-n", "EFI", "-C", str(esp), "34000"],
        check=True,
        capture_output=True,
    )
    items = [str(p) for p in sorted(src.iterdir())]
    subprocess.run(
        ["mcopy", "-s", "-p", "-m", "-i", str(esp), *items, "::"],
        check=True,
        capture_output=True,
    )
    return esp


def _admit(root, own, **src):
    ((key, value),) = src.items()
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(here.parent / "devcard-policy.py"),
            "esp-admit",
            "--root",
            str(root),
            f"--{key.replace('_', '-')}",
            str(value),
            "--ownership",
            str(own),
        ],
        capture_output=True,
        text=True,
    )


def esp_admission_cases():
    """F6 B4: one ESP admission at build (staged tree) and verify (image)."""
    assert shutil.which("mkfs.fat") and shutil.which("mcopy")
    # Our build's layouts pass in both modes.
    for fw, dtb in (("0\n", True), ("8\n", False), ("9\n", False)):
        with fixture() as work:
            root, own = _esp_root(work, fw=fw)
            src = _esp_tree(work, dtb=dtb)
            r = _admit(root, own, esp_dir=src)
            assert r.returncode == 0, (fw, r.stderr)
            r = _admit(root, own, esp_img=_esp_img(work, src))
            assert r.returncode == 0, (fw, r.stderr)
    # esp_override: the DTB is expected even with a current firmware stamp.
    with fixture() as work:
        root, own = _esp_root(work, fw="8\n")
        write(root / "usr/lib/cubie-a7a/dtb/esp-override", "")
        r = _admit(root, own, esp_dir=_esp_tree(work, dtb=False))
        assert r.returncode == 1 and "missing=" in r.stderr, r.stderr
    # Malformed stamps are refused, never read as "no DTB".
    for fw, pkg in (("8x\n", "8\n"), ("", "8\n"), ("0\n", "eight\n"), (None, "8\n")):
        with fixture() as work:
            root, own = _esp_root(work, fw="0\n" if fw is None else fw, pkg=pkg)
            if fw is None:
                (root / "var/lib/cubie-a7a/firmware-dtb-version").unlink()
            src = _esp_tree(work, dtb=False)
            for mode in ("esp_dir", "esp_img"):
                arg = src if mode == "esp_dir" else _esp_img(work, src)
                r = _admit(root, own, **{mode: arg})
                assert r.returncode == 1 and "malformed DTB stamp" in r.stderr, (
                    fw,
                    pkg,
                    mode,
                    r.stderr,
                )
                if mode == "esp_img":
                    arg.unlink()
    # Wrong entry types: a directory where a file belongs (and the reverse).
    with fixture() as work:
        root, own = _esp_root(work)
        src = _esp_tree(work)
        (src / "EFI/fedora/grub.cfg").unlink()
        (src / "EFI/fedora/grub.cfg").mkdir()
        write(src / "EFI/fedora/grub.cfg/x", "")
        for mode in ("esp_dir", "esp_img"):
            arg = src if mode == "esp_dir" else _esp_img(work, src)
            r = _admit(root, own, **{mode: arg})
            assert r.returncode == 1 and (
                "wrong type" in r.stderr or "extra" in r.stderr
            ), (
                mode,
                r.stderr,
            )
    with fixture() as work:
        root, own = _esp_root(work)
        src = _esp_tree(work)
        dtb = src / "dtb/allwinner/sun60i-a733-cubie-a7a.dtb"
        dtb.unlink()
        dtb.mkdir()
        esp = _esp_img(work, src)
        r = _admit(root, own, esp_img=esp)
        assert r.returncode == 1 and "wrong type" in r.stderr, r.stderr
    # The right path with the wrong DTB bytes, and a marker that disagrees.
    for kw, needle in (
        ({"dtb_bytes": b"\xd0\x0d\xfe\xed other dtb\n"}, "is not the packaged DTB"),
        ({"mark": "0" * 64}, "does not hold the DTB's digest"),
    ):
        with fixture() as work:
            root, own = _esp_root(work)
            src = _esp_tree(work, **kw)
            for mode in ("esp_dir", "esp_img"):
                arg = src if mode == "esp_dir" else _esp_img(work, src)
                r = _admit(root, own, **{mode: arg})
                assert r.returncode == 1 and needle in r.stderr, (kw, mode, r.stderr)
    # Build time: an extra ESP file, and an OVERLAY that writes boot/efi.
    with fixture() as work:
        root, own = _esp_root(work)
        src = _esp_tree(work)
        write(src / "EFI/fedora/extra.efi", "x")
        r = _admit(root, own, esp_dir=src)
        assert r.returncode == 1 and "extra=" in r.stderr, r.stderr
        overlay = work / "overlay"
        write(overlay / "boot/efi/EFI/fedora/grub.cfg", "x")
        r = _admit(root, own, overlay=overlay)
        assert r.returncode == 1 and "OVERLAY writes the ESP" in r.stderr, r.stderr
        clean = work / "overlay-clean"
        write(clean / "opt/vendor/x", "x")
        r = _admit(root, own, overlay=clean)
        assert r.returncode == 0, r.stderr
    # mkdevcard.sh calls the admission before the overlay copy, on the staged
    # tree, and on esp.img before the tree is emptied; verify on the image.
    mk = (here.parent / "mkdevcard.sh").read_text()
    i_overlay = mk.index('esp-admit --root "$ROOT" --overlay "$OVERLAY"')
    i_cp = mk.index('cp -a --no-preserve=ownership "$OVERLAY"/. "$ROOT"/')
    i_dir = mk.index('esp-admit --root "$ROOT" --esp-dir "$ROOT/boot/efi"')
    i_mcopy = mk.index('mcopy -s -p -m -i "$esp" "$ROOT"/boot/efi/* ::')
    i_img = mk.index('esp-admit --root "$ROOT" --esp-img "$esp"')
    i_del = mk.index('find "$ROOT/boot/efi" -mindepth 1 -delete')
    assert i_overlay < i_cp < i_dir < i_mcopy < i_img < i_del
    vd = (here.parent / "verify-devcard.sh").read_text()
    assert 'esp-admit --root "$ROOT" --esp-img "$ESP"' in vd
    assert "esp-check" not in vd


def esp_check_cases():
    """Step 0 mdir: full ESP layout cross-checked with fsck.fat rejects prefixes and extras."""
    assert shutil.which("mkfs.fat") and shutil.which("mcopy")
    assert shutil.which("mdir") and shutil.which("fsck.fat")
    with fixture() as work:
        esp = work / "esp.img"
        subprocess.run(
            ["mkfs.fat", "-F", "32", "-n", "EFI", "-C", str(esp), "34000"],
            check=True,
            capture_output=True,
        )
        src = work / "src"
        for rel in (
            "EFI/BOOT/BOOTAA64.EFI",
            "EFI/BOOT/fbaa64.efi",
            "EFI/fedora/BOOTAA64.CSV",
            "EFI/fedora/grub.cfg",
            "EFI/fedora/grubaa64.efi",
            "EFI/fedora/mmaa64.efi",
            "EFI/fedora/shim.efi",
            "EFI/fedora/shimaa64.efi",
        ):
            write(src / rel, "ok\n")
        subprocess.run(
            ["mcopy", "-s", "-p", "-m", "-i", str(esp), str(src / "EFI"), "::"],
            check=True,
            capture_output=True,
        )
        assert policy.esp_check(esp, expect_dtb=False) == 11
        try:
            policy.esp_check(esp, expect_dtb=True)
            raise AssertionError("missing DTB must fail --expect-dtb")
        except policy.PolicyError:
            pass

        # Add our exact DTB override files.
        for rel in (
            "dtb/allwinner/sun60i-a733-cubie-a7a.dtb",
            "dtb/allwinner/sun60i-a733-cubie-a7a.dtb.cubie-a7a-dtb",
        ):
            write(src / rel, "dtb\n")
        subprocess.run(
            ["mcopy", "-s", "-p", "-m", "-i", str(esp), str(src / "dtb"), "::"],
            check=True,
            capture_output=True,
        )
        assert policy.esp_check(esp, expect_dtb=True) == 15
        try:
            policy.esp_check(esp, expect_dtb=False)
            raise AssertionError("present DTB must fail --no-dtb")
        except policy.PolicyError:
            pass

        # Silent mdir prefix truncation (returns only ::/EFI/ with exit 0) fails closed.
        inj = work / "mdir-inj.log"
        mdir_wrap = work / "bin-mdir/mdir"
        mdir_wrap.parent.mkdir()
        mdir_wrap.write_text(
            "#!/bin/sh\n"
            f'echo "injected:mdir-prefix:$*" >> "{inj}"\n'
            'printf "::/EFI/\\n"\n'
            "exit 0\n"
        )
        mdir_wrap.chmod(0o755)
        r = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(here.parent / "devcard-policy.py"),
                "esp-check",
                str(esp),
                "--no-dtb",
            ],
            env={**os.environ, "PATH": f"{mdir_wrap.parent}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )
        assert "injected:mdir-prefix:" in inj.read_text()
        assert r.returncode != 0, (r.returncode, r.stdout, r.stderr)

        # Silent fsck.fat truncation (drops footer) fails closed.
        fsck_inj = work / "fsck-inj.log"
        fsck_wrap = work / "bin-fsck/fsck.fat"
        fsck_wrap.parent.mkdir()
        fsck_wrap.write_text(
            "#!/bin/sh\n"
            f'echo "injected:fsck-trunc:$*" >> "{fsck_inj}"\n'
            'printf "fsck.fat 4.2\\nChecking file /\\nChecking file /EFI\\n"\n'
            "exit 0\n"
        )
        fsck_wrap.chmod(0o755)
        r2 = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(here.parent / "devcard-policy.py"),
                "esp-check",
                str(esp),
                "--expect-dtb",
            ],
            env={**os.environ, "PATH": f"{fsck_wrap.parent}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )
        assert "injected:fsck-trunc:" in fsck_inj.read_text()
        assert r2.returncode != 0, (r2.returncode, r2.stdout, r2.stderr)

        # Extra unexpected file on ESP is refused.
        write(src / "EFI/stray.efi", "extra\n")
        subprocess.run(
            [
                "mcopy",
                "-i",
                str(esp),
                str(src / "EFI/stray.efi"),
                "::/EFI/stray.efi",
            ],
            check=True,
            capture_output=True,
        )
        try:
            policy.esp_check(esp, expect_dtb=True)
            raise AssertionError("extra ESP file must be refused")
        except policy.PolicyError:
            pass


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
        "repart: aliases, unexpected drop-ins and unexpected service.d refused (B1)",
        repart_pinned_refusals,
    )
    case(
        "repart: symlinked/unexpected .d and stock-file directives refused (F6 B2)",
        repart_prefilter_initramfs_cases,
    )
    case(
        "repart: initramfs bytes from cpio records, not lsinitrd -f (F6 B2)",
        repart_initramfs_bytes_from_cpio,
    )
    case(
        "repart: GROW_ROOT=yes needs present, unmasked, enabled unit (F6 B2)",
        repart_grow_root_cases,
    )
    case(
        "repart: mkdevcard writes the drop-in with the rule's writer (F6 B2)",
        repart_dropin_writer_cases,
    )
    case(
        "repart: exact-unit order matches offline systemd-analyze --root= verify oracle",
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
        "initramfs: exactly one zstd frame, split header and skippable refused (F6 B1)",
        zstd_single_frame_cases,
    )
    case(
        "initramfs-check: silent truncation of lsinitrd and -f fails closed (S0-9)",
        initramfs_check_truncation_cases,
    )
    case(
        "verify-rpmdb-list: silent rpm -qa truncation fails closed (S0-8)",
        verify_rpmdb_list_cases,
    )
    case(
        "esp-admit: stamps, entry types, DTB bytes and marker at build and verify (F6 B4)",
        esp_admission_cases,
    )
    case(
        "esp-check: mdir + fsck.fat + exact ESP layout rejects prefixes and extras (Step 0)",
        esp_check_cases,
    )
    case(
        "absence-check: matches and unreadable dirs fail closed (S0-10)",
        absence_check_cases,
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
        "repart: rewritten (indented) drop-in refused: pinned bytes (F6)",
        repart_indented_correct_dropin_refused,
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
