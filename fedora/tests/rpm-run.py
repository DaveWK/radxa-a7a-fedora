#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Interleave two builds with same-name, different-byte fixture RPMs.

Runs real RPM tools, createrepo_c and offline DNF in a network namespace; no
image, hardware or external repository. Set CREATEREPO_C to an absolute
path to a runnable createrepo_c wrapper when not in PATH. --base-fedora
selects extracted F7 source for the original red; --pre-rpmdb-fedora selects
extracted F8a round-one source for the wrong installed RPM red.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
PACKAGES = ("cubie-a7a-dtb", "cubie-a7a-board-support", "cubie-a7a-hat")
FEDORA = Path(__file__).resolve().parent.parent


def command(*args, env=None):
    proc = subprocess.run(args, capture_output=True, text=True, env=env)
    if proc.returncode:
        raise AssertionError(
            f"{args!r}: exit {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
        )
    return proc.stdout.strip()


def build_fixtures(work, tag, version=1, packages=PACKAGES):
    top = work / ("top-" + tag)
    (top / "tmp").mkdir(parents=True)
    paths = {}
    for package in packages:
        spec = top / f"{package}.spec"
        dest = f"/usr/share/a7a-test/{package}"
        requires = (
            "Requires: cubie-a7a-hat\n" if package == "cubie-a7a-board-support" else ""
        )
        spec.write_text(
            f"Name: {package}\nVersion: {version}\nRelease: 1\nBuildArch: noarch\n"
            "Summary: Run isolation fixture\nLicense: GPL-2.0-only\n"
            f"{requires}"
            "%description\nRun isolation fixture\n%install\n"
            "mkdir -p %{buildroot}/usr/share/a7a-test\n"
            f"echo {tag} > %{{buildroot}}{dest}\n%files\n{dest}\n"
        )
        command(
            "rpmbuild",
            "--define",
            f"_topdir {top}",
            "--define",
            f"_tmppath {top / 'tmp'}",
            "-bb",
            str(spec),
        )
        paths[package] = next((top / "RPMS/noarch").glob(f"{package}-*.rpm"))
    return paths


def load_module(path):
    spec = importlib.util.spec_from_file_location("manifest", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reject_incomplete_inventory(policy, run):
    snapshot = run / "rpm-snapshot.json"
    saved = snapshot.read_bytes()
    data = json.loads(saved)
    hat = next(rec for rec in data["rpms"] if rec["package"] == "cubie-a7a-hat")

    def refuse(path, diagnostic):
        proc = subprocess.run(
            [*policy, "load-rpm-run", str(run)], capture_output=True, text=True
        )
        assert (
            proc.returncode == 1
            and str(path) in proc.stderr
            and diagnostic in proc.stderr
        ), f"{path}: expected {diagnostic!r}, got exit {proc.returncode}: {proc.stderr}"

    # Keep valid JSON and leave metadata and both lists of actual RPM files intact.
    snapshot.chmod(0o644)
    try:
        data["rpms"].remove(hat)
        snapshot.write_text(json.dumps(data))
        snapshot.chmod(0o444)
        refuse(run / "out" / hat["relpath"], "not in RPM snapshot")
        snapshot.chmod(0o644)
        data["rpms"].append(hat)
        orig_nevra = hat["nevra"]
        hat["nevra"] = orig_nevra.replace("-1-1.", "-9-1.")
        snapshot.write_text(json.dumps(data))
        snapshot.chmod(0o444)
        refuse(run / "repo" / hat["relpath"], "RPM identity differs from snapshot")
    finally:
        snapshot.chmod(0o644)
        snapshot.write_bytes(saved)
        snapshot.chmod(0o444)

    for directory in ("out", "repo"):
        path = run / directory / hat["relpath"]
        path.parent.chmod(0o755)
        extra = path.with_name("unexpected.rpm")
        # Move the removed test file outside the inventory, leaving repodata intact.
        removed = run / path.with_suffix(".saved").name
        try:
            shutil.copyfile(path, extra)
            refuse(extra, "not in RPM snapshot")
            extra.unlink()
            path.rename(removed)
            refuse(path, "missing from RPM inventory")
        finally:
            extra.unlink(missing_ok=True)
            if removed.exists():
                removed.rename(path)
            path.parent.chmod(0o555)
    print("snapshot omission, false identity, and extra or missing RPMs refused")


def dnf(work, tag, root, env, action, *args):
    return command(
        "unshare",
        "--map-root-user",
        "--net",
        "dnf5",
        "--no-plugins",
        "-y",
        action,
        "--use-host-config",
        f"--installroot={root}",
        "--releasever=45",
        f"--setopt=reposdir={work / 'repos'}",
        f"--setopt=cachedir={work / ('cache-' + tag)}",
        f"--setopt=system_cachedir={work / ('cache-' + tag)}",
        f"--setopt=logdir={work}",
        "--setopt=countme=False",
        "--setopt=tsflags=nocontexts",
        "--setopt=localpkg_gpgcheck=False",
        *args,
        env=env,
    )


def reject_substituted_install(work, root, env, policy, manifest, records, pre_rpmdb):
    package = "cubie-a7a-hat"
    source = work / "synthetic-fedora"
    source.mkdir()
    higher = build_fixtures(work, "other", version=9, packages=(package,))[package]
    shutil.copyfile(higher, source / higher.name)
    command(os.environ.get("CREATEREPO_C", "createrepo_c"), str(source))
    # Replace just this package in the staged root. The checked paths and their
    # snapshots are unchanged, so sealing source-file hashes alone cannot tell.
    dnf(
        work,
        "synthetic-fedora",
        root,
        env,
        "upgrade",
        f"--repofrompath=synthetic-fedora,{source.as_uri()}",
        "--repo=synthetic-fedora",
        "--setopt=synthetic-fedora.gpgcheck=False",
        "--setopt=synthetic-fedora.repo_gpgcheck=False",
        package,
    )
    actual = command("rpm", "--root", str(root), "-q", "--qf", "%{NEVRA}", package)
    assert actual == "cubie-a7a-hat-9-1.noarch", actual
    print(f"synthetic Fedora repo installed {actual}")
    if pre_rpmdb:
        assert manifest._rpm_model(records)
        raise AssertionError(f"round-one RPM sealing accepted the staged {actual}")
    result = subprocess.run(
        [*policy, "check-installed-rpms", str(root), json.dumps(records)],
        capture_output=True,
        text=True,
    )
    assert (
        result.returncode == 1
        and f"installed {package} differs from snapshot" in result.stderr
        and actual in result.stderr
    ), f"expected the staged rpmdb gate to reject {actual}: {result.stderr}"
    print("higher same-name repository RPM refused by staged rpmdb check")


def exercise(work, code, legacy, pre_rpmdb=False):
    manifest = load_module(code / "devcard-manifest.py")
    policy = [sys.executable, "-I", str(code / "devcard-policy.py")]
    buildroot = work / "buildroot"
    shared = buildroot / "RPMS"
    env = {
        **os.environ,
        "HOME": str(work),
        "XDG_CACHE_HOME": str(work / "xdg-cache"),
        "XDG_STATE_HOME": str(work / "xdg-state"),
    }
    expected = {}
    captured = {}
    for tag in ("one", "two"):
        if legacy:
            run, outputs = shared, shared
        else:
            run = Path(command(*policy, "new-rpm-run", str(buildroot)))
            assert re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{8}", run.name)
            outputs = run / "out"
        (outputs / "noarch").mkdir(parents=True, exist_ok=True)
        expected[tag] = {}
        for package, src in build_fixtures(work, tag).items():
            target = outputs / "noarch" / src.name
            shutil.copyfile(src, target)
            expected[tag][package] = (src.name, _hash(src))
        if legacy:
            command(
                *policy,
                "write-rpm-manifest",
                str(outputs),
                str(outputs / "checked-rpms.json"),
                *map(str, sorted((outputs / "noarch").glob("*.rpm"))),
            )
            selected = command(*policy, "select-rpms", str(outputs))
            paths = [line.split("\t")[1] for line in selected.splitlines()]
            records = outputs
        else:
            command(*policy, "seal-rpm-run", str(run))
            selected = command(*policy, "load-rpm-run", str(run)).splitlines()
            records = json.loads(selected[0])
            paths = [line.split("\t", maxsplit=2)[2] for line in selected[1:]]
            for path in map(Path, paths):
                output = outputs / path.relative_to(run / "repo")
                assert path.stat().st_ino != output.stat().st_ino
                assert not (output.stat().st_mode | path.stat().st_mode) & 0o222
        captured[tag] = run, paths, records
    for package in PACKAGES:
        same, first = expected["one"][package]
        other, second = expected["two"][package]
        assert same == other and first != second, (same, other, first, second)

    # Run A already selected its files when B published identically named
    # inputs. Now install and seal A, then B. The base points A at B's files.
    errors = []
    (work / "repos").mkdir()
    if not legacy and not pre_rpmdb:
        reject_incomplete_inventory(policy, captured["one"][0])
    for tag, (run, paths, records) in captured.items():
        root = work / f"installed-{tag}"
        root.mkdir()
        dnf(work, tag, root, env, "install", *paths)
        installed = {
            (root / "usr/share/a7a-test" / name).read_text().strip()
            for name in PACKAGES
        }
        if installed != {tag}:
            errors.append(f"run {tag} installed run {', '.join(sorted(installed))}")
        sealed = {r["sha256"] for r in manifest._rpm_model(records)}
        if sealed != {digest for _, digest in expected[tag].values()}:
            errors.append(f"run {tag} sealed the wrong RPM digests")
        if not legacy:
            if not pre_rpmdb:
                command(*policy, "check-installed-rpms", str(root), json.dumps(records))
            if tag == "one":
                reject_substituted_install(
                    work, root, env, policy, manifest, records, pre_rpmdb
                )
            path = Path(paths[0])
            path.chmod(0o644)
            with path.open("ab") as stream:
                stream.write(b"\0")
            try:
                manifest._rpm_model(records)
            except manifest.ManifestError as exc:
                assert "sha256 mismatch for consumed RPM" in str(exc), exc
            else:
                errors.append(f"run {tag} sealed changed repository bytes")
    assert not errors, "; ".join(errors)
    print("both runs installed and sealed only their own same-name RPM bytes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    bases = parser.add_mutually_exclusive_group()
    bases.add_argument("--base-fedora", type=Path)
    bases.add_argument("--pre-rpmdb-fedora", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="a7a-rpm-run-") as tmp:
        exercise(
            Path(tmp),
            args.base_fedora or args.pre_rpmdb_fedora or FEDORA,
            args.base_fedora is not None,
            args.pre_rpmdb_fedora is not None,
        )


if __name__ == "__main__":
    main()
