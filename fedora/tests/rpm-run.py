#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Interleave two builds with same-name, different-byte fixture RPMs.

Runs real RPM tools, createrepo_c and offline DNF in a network namespace; no
image, hardware or external repository. Set CREATEREPO_C to an absolute
path to a runnable createrepo_c wrapper when not in PATH. --base-fedora
selects an extracted F7 source directory for the red reproduction.
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
PACKAGES = ("cubie-a7a-dtb", "cubie-a7a-board-support")
FEDORA = Path(__file__).resolve().parent.parent


def command(*args, env=None):
    proc = subprocess.run(args, capture_output=True, text=True, env=env)
    if proc.returncode:
        raise AssertionError(
            f"{args!r}: exit {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
        )
    return proc.stdout.strip()


def build_fixtures(work, tag):
    top = work / ("top-" + tag)
    (top / "tmp").mkdir(parents=True)
    paths = {}
    for package in PACKAGES:
        spec = top / f"{package}.spec"
        dest = f"/usr/share/a7a-test/{package}"
        spec.write_text(
            f"Name: {package}\nVersion: 1\nRelease: 1\nBuildArch: noarch\n"
            "Summary: Run isolation fixture\nLicense: GPL-2.0-only\n"
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


def exercise(work, code, legacy):
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
    empty_repos = work / "repos"
    empty_repos.mkdir()
    for tag, (run, paths, records) in captured.items():
        root = work / f"installed-{tag}"
        root.mkdir()
        local_repo = []
        if not legacy:
            repo_id = "a7a-board-" + run.name
            url = (run / "repo").as_uri()
            local_repo = [
                f"--repofrompath={repo_id},{url}",
                f"--repo={repo_id}",
                f"--setopt={repo_id}.gpgcheck=False",
                f"--setopt={repo_id}.repo_gpgcheck=False",
            ]
        command(
            "unshare",
            "--map-root-user",
            "--net",
            "dnf5",
            "--no-plugins",
            "-y",
            "install",
            "--use-host-config",
            f"--installroot={root}",
            "--releasever=45",
            f"--setopt=reposdir={empty_repos}",
            f"--setopt=cachedir={work / ('cache-' + tag)}",
            f"--setopt=system_cachedir={work / ('cache-' + tag)}",
            f"--setopt=logdir={work}",
            "--setopt=countme=False",
            "--setopt=tsflags=nocontexts",
            "--setopt=localpkg_gpgcheck=False",
            *local_repo,
            *paths,
            env=env,
        )
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
    parser.add_argument("--base-fedora", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="a7a-rpm-run-") as tmp:
        exercise(Path(tmp), args.base_fedora or FEDORA, args.base_fedora is not None)


if __name__ == "__main__":
    main()
