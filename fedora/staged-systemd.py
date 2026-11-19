#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check the staged repart units with the real, unprivileged systemd loader."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from staged_paths import RUNTIME_LINKS, resolve, walk

SYSTEMD = "/usr/lib/systemd/systemd"
UNIT_DIRS = (
    "etc/systemd/system",
    "run/systemd/system",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
)
REPART = "systemd-repart.service"
TEMPLATE = "systemd-repart@.service"
SYSINIT = "sysinit.target"
UNIT_BLOCK = re.compile(r"^\s*→ Unit ([^\s:]+):")
FIELDS = ("Unit Load State:", "Fragment Path:", "DropIn Path:", "Command Line:")
REPART_DIRS = ("etc", "run", "usr/local/lib", "usr/lib")


class PolicyError(RuntimeError):
    pass


def inside(root, path):
    return path.is_relative_to(root)


def readable_tree(root, whole=False):
    """Executed as the same nonroot identity as the loader, before it runs."""
    if os.getuid() != 1000 or os.getgid() != 1000:
        raise PolicyError("systemd preflight must run as mapped UID/GID 1000")
    if not os.access(root, os.R_OK | os.X_OK):
        raise PolicyError(f"unreadable staged root: {root}")
    if not whole and os.path.lexists(root / "lib"):
        alternate = resolve(root, "lib")
        if alternate != root / "usr/lib" and (alternate / "systemd/system").is_dir():
            raise PolicyError("unadmitted non-usr-merged /lib/systemd/system")
    for directory in (root,) if whole else unit_paths(root):
        for path in walk(directory):
            st = path.lstat()
            if stat.S_ISDIR(st.st_mode):
                if not os.access(path, os.R_OK | os.X_OK):
                    raise PolicyError(f"unreadable staged directory: {path}")
            elif stat.S_ISREG(st.st_mode):
                if not os.access(path, os.R_OK):
                    raise PolicyError(f"unreadable staged file: {path}")
            elif stat.S_ISLNK(st.st_mode):
                raw = os.readlink(path)
                rel = path.relative_to(root).as_posix()
                if whole and RUNTIME_LINKS.get(rel) == raw:
                    continue
                target = resolve(root, rel, masks=not whole)
                if target is None:
                    continue
                if not os.access(target, os.R_OK):
                    raise PolicyError(
                        f"unreadable or out-of-root symlink target: {path} -> {raw}"
                    )
                if target.is_dir() and not os.access(target, os.X_OK):
                    raise PolicyError(f"untraversable symlink target: {path} -> {raw}")


def unit_paths(root):
    for subdir in UNIT_DIRS:
        current = root
        for part in Path(subdir).parts:
            current /= part
            if not os.path.lexists(current):
                break
            if current.is_symlink() or not current.is_dir():
                raise PolicyError(
                    f"unit search path is not a physical directory: {current}"
                )
        else:
            yield current


def loader(root, unit, whole=False):
    path = ":".join(str(root / part) for part in UNIT_DIRS)
    result = subprocess.run(
        [
            "unshare",
            "--user",
            "--map-user=1000",
            "--map-group=1000",
            "--",
            "env",
            f"SYSTEMD_UNIT_PATH={path}",
            "SYSTEMD_GENERATOR_PATH=",
            "SYSTEMD_ENVIRONMENT_GENERATOR_PATH=",
            "LC_ALL=C.UTF-8",
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "_load",
            str(root),
            unit,
            *(["--whole"] if whole else []),
        ],
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise PolicyError(
            f"nested systemd loader for {unit}: exit {result.returncode}: {result.stderr.strip()}"
        )
    return parse_dump(root, result.stdout)


def parse_dump(root, dump):
    blocks = {}
    current = None
    for line in dump.splitlines():
        match = UNIT_BLOCK.match(line)
        if match:
            current = blocks.setdefault(match[1], [])
            continue
        if line.startswith(("→", "\t→")):
            current = None
        line = line.strip()
        if line.startswith(("Fragment Path:", "DropIn Path:")):
            prefix, _, path = line.partition(": ")
            p = Path(path)
            if path != "/dev/null":
                if not p.is_absolute() or not inside(root, p):
                    raise PolicyError(
                        f"loader {prefix} outside the staged root: {path}"
                    )
                resolve(root, p.relative_to(root), masks=True)
                line = f"{prefix}: /{p.relative_to(root).as_posix()}"
        if current is not None:
            current.append(line)
    if not blocks:
        raise PolicyError("systemd loader emitted no unit blocks")
    return blocks


def inventory(root):
    records = {}
    for path in unit_paths(root):
        for entry in walk(path):
            rel = entry.relative_to(root)
            if entry.is_symlink():
                records[rel.as_posix()] = {"link": os.readlink(entry)}
            elif any(p.endswith(".d") for p in rel.parts[:-1]) or entry.name in (
                REPART,
                TEMPLATE,
            ):
                if entry.is_dir():
                    continue
                if not entry.is_file():
                    raise PolicyError(f"unexpected unit inventory entry: {rel}")
                records[rel.as_posix()] = {
                    "sha256": hashlib.sha256(entry.read_bytes()).hexdigest()
                }
    return records


def configuration(root, mode):
    blocks = loader(root, SYSINIT, whole=mode == "initramfs")
    if mode == "initramfs":
        for name in (REPART, TEMPLATE):
            if any(os.path.lexists(root / sub / name) for sub in UNIT_DIRS):
                raise PolicyError(f"initramfs must not contain {name}")
        for name in blocks:
            if name.startswith("systemd-repart"):
                raise PolicyError(f"initramfs loader found {name}")
        return ""
    if mode == "yes":
        if not any(
            line.startswith(f"Wants: {REPART} ") for line in blocks.get(SYSINIT, ())
        ):
            raise PolicyError(f"{SYSINIT} does not Want {REPART}")
        wanted = root / UNIT_DIRS[-1] / REPART
        links = []
        for sub in (UNIT_DIRS[0], UNIT_DIRS[-1]):
            path = root / sub / f"{SYSINIT}.wants" / REPART
            if path.is_symlink():
                if resolve(root, path.relative_to(root), masks=True) == wanted:
                    links.append(path.relative_to(root).as_posix())
        if not links:
            raise PolicyError(
                f"no persistent {SYSINIT}.wants/{REPART} link to its staged fragment"
            )
        print("persistent repart activation:", ", ".join(links), file=sys.stderr)
        blocks = loader(root, REPART)
        state = "loaded"
    else:
        for name in (REPART, TEMPLATE):
            path = root / UNIT_DIRS[0] / name
            if not path.is_symlink() or os.readlink(path) != "/dev/null":
                raise PolicyError(f"missing persistent mask: {path} -> /dev/null")
        state = "masked"
    lines = [line for line in blocks.get(REPART, ()) if line.startswith(FIELDS)]
    if f"Unit Load State: {state}" not in lines:
        raise PolicyError(f"{REPART}: expected loader state {state}, got {lines}")
    if mode == "yes" and not any(
        line.startswith("Command Line:") and "--discard=no" in line.split()
        for line in lines
    ):
        raise PolicyError(f"{REPART}: loaded command lacks --discard=no")
    return "\n".join(lines) + "\n"


def repart_files(root, mode, root_uuid=None, esp_uuid=None):
    actual = []
    for prefix in REPART_DIRS:
        directory = root / prefix / "repart.d"
        if not os.path.lexists(directory):
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise PolicyError(f"invalid repart.d directory: {directory}")
        actual.extend(
            p.relative_to(root).as_posix() for p in sorted(directory.iterdir())
        )
    expected = ["etc/repart.d/50-root.conf"] if mode == "yes" else []
    if actual != expected:
        raise PolicyError(f"repart.d inventory: expected {expected}, found {actual}")
    if expected:
        path = root / expected[0]
        if (
            path.is_symlink()
            or not path.is_file()
            or path.read_bytes() != b"[Partition]\nType=root\n"
        ):
            raise PolicyError(f"{path}: invalid root growth partition configuration")
    if mode == "initramfs":
        return
    path = root / "etc/fstab"
    if path.is_symlink() or not path.is_file():
        raise PolicyError(f"{path}: expected a regular file")
    rows = [
        line.split()
        for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    grow = ",x-systemd.growfs" if mode == "yes" else ""
    expected_rows = [
        [f"UUID={root_uuid}", "/", "ext4", f"defaults{grow}", "1", "1"],
        [
            f"UUID={esp_uuid}",
            "/boot/efi",
            "vfat",
            "umask=0077,shortname=winnt",
            "0",
            "2",
        ],
    ]
    if rows != expected_rows:
        raise PolicyError(
            f"{path}: entries do not match GROW_ROOT={mode} and the staged UUIDs"
        )


def check(root, fixtures, mode, root_uuid=None, esp_uuid=None):
    expected_units = (fixtures / f"repart-{mode}.unit.txt").read_text()
    expected = json.loads((fixtures / f"repart-{mode}.inventory.json").read_text())
    actual_units = configuration(root, mode)
    actual = inventory(root)
    for name in sorted(expected.keys() | actual.keys()):
        if actual.get(name) != expected.get(name):
            raise PolicyError(
                f"unit inventory mismatch at {name}: expected {expected.get(name)}, got {actual.get(name)}"
            )
    if actual_units != expected_units:
        raise PolicyError(
            f"effective {REPART}, mode {mode}: expected {expected_units!r}, got {actual_units!r}"
        )
    repart_files(root, mode, root_uuid, esp_uuid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    child = commands.add_parser("_load")
    child.add_argument("root", type=Path)
    child.add_argument("unit", choices=(SYSINIT, REPART))
    child.add_argument("--whole", action="store_true")
    for name in ("check", "capture"):
        cli = commands.add_parser(name)
        cli.add_argument("root", type=Path)
        cli.add_argument("fixtures", type=Path)
        cli.add_argument("mode", choices=("yes", "no", "initramfs"))
        if name == "check":
            cli.add_argument("--root-uuid")
            cli.add_argument("--esp-uuid")
    args = parser.parse_args()
    try:
        root = args.root.resolve(strict=True)
        if root == Path("/") or ":" in str(root):
            raise PolicyError(f"invalid staged root: {root}")
        if args.command == "_load":
            readable_tree(root, args.whole)
            version = subprocess.check_output([SYSTEMD, "--version"], text=True)
            match = re.match(r"systemd (\d+)", version)
            if not match or int(match[1]) < 250:
                raise PolicyError("systemd >= 250 is required")
            print(version.splitlines()[0], file=sys.stderr, flush=True)
            os.execv(
                SYSTEMD,
                [SYSTEMD, "--test", "--system", f"--unit={args.unit}", "--no-pager"],
            )
        print(
            subprocess.check_output([SYSTEMD, "--version"], text=True).splitlines()[0],
            file=sys.stderr,
        )
        if args.command == "capture":
            text = configuration(root, args.mode)
            (args.fixtures / f"repart-{args.mode}.unit.txt").write_text(text)
            (args.fixtures / f"repart-{args.mode}.inventory.json").write_text(
                json.dumps(inventory(root), sort_keys=True, indent=2) + "\n"
            )
        else:
            check(root, args.fixtures, args.mode, args.root_uuid, args.esp_uuid)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"staged-systemd: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
