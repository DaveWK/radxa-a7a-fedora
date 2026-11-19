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
    except Exception as exc:  # noqa: BLE001 - a test error is a failure
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


def repart_overlay_drops_dropin():
    # The fixture overlay scenario: the unit is there, the drop-in is gone.
    with fixture() as root:
        build_repart_root(root, dropin=None)
        ok, problems = policy.repart_root_ok(root)
        assert not ok, "a missing no-discard drop-in must fail the build check"
        assert any("systemd-repart.service" in p for p in problems), problems


def repart_overlay_replaces_dropin():
    with fixture() as root:
        build_repart_root(
            root,
            dropin="[Service]\nExecStart=\nExecStart=systemd-repart --discard=yes\n",
        )
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "a --discard=yes drop-in must fail"


def repart_other_dropin_sets_execstart():
    with fixture() as root:
        build_repart_root(root)
        write(
            root / "etc/systemd/system/systemd-repart.service.d/20-evil.conf",
            "[Service]\nExecStart=systemd-repart --discard=yes\n",
        )
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "another drop-in setting ExecStart must fail"


def repart_etc_unit_override():
    with fixture() as root:
        build_repart_root(root, etc_unit="[Service]\nExecStart=systemd-repart\n")
        ok, _ = policy.repart_root_ok(root)
        assert not ok, "a regular-file /etc unit override must fail"


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


def repart_initramfs_cases():
    ok, _ = policy.repart_initramfs_ok("usr/lib/modules/x\n")
    assert ok, "an initramfs without systemd-repart is fine"
    ok, _ = policy.repart_initramfs_ok(
        "usr/lib/systemd/system/systemd-repart.service\n"
        "usr/lib/systemd/system/systemd-repart.service.d/10-cubie-a7a-no-discard.conf\n"
    )
    assert ok, "an initramfs with the drop-in is fine"
    ok, problem = policy.repart_initramfs_ok(
        "usr/lib/systemd/system/systemd-repart.service\n"
    )
    assert not ok, "an initramfs with systemd-repart and no drop-in must fail"
    assert "drop-in" in problem


def main():
    case("aic-overlay: refuses firmware paths", aic_overlay_refuses_firmware_paths)
    case("aic-overlay: refuses symlink", aic_overlay_refuses_symlink)
    case("aic-overlay: missing directory", aic_overlay_missing_dir)
    case("aic-overlay: other firmware allowed", aic_overlay_other_firmware_allowed)
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
    case("aic-provenance: report written", aic_provenance_report_written)
    case("aic-manifest names", aic_manifest_names_cases)
    case("enabled repos: populated and missing dirs", enabled_repos_cases)
    case("enabled repos: empty and missing", enabled_repos_empty)
    case("dumpe2fs: sizes and empty", dumpe2fs_cases)
    case("loader entry: fields, missing file", loader_entry_cases)
    case("loader entry: empty and whitespace", loader_entry_empty_and_ws)
    case("shadow: root, others, empty", shadow_cases)
    case("passwd: sole root policy", passwd_sole_root_cases)
    case("repart: good root", repart_good_root)
    case("repart: overlay drops the drop-in", repart_overlay_drops_dropin)
    case("repart: overlay replaces the drop-in", repart_overlay_replaces_dropin)
    case("repart: another drop-in sets ExecStart", repart_other_dropin_sets_execstart)
    case("repart: /etc unit override", repart_etc_unit_override)
    case("repart: masked unit", repart_masked_unit_ok)
    case("repart: repart.d without the unit", repart_conf_without_unit)
    case("repart: initramfs listings", repart_initramfs_cases)
    if FAILURES:
        print(f"{len(FAILURES)} test(s) FAILED")
        return 1
    print("all devcard-policy tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
