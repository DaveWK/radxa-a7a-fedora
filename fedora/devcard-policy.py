#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Image-policy checks shared by fedora/mkdevcard.sh and
fedora/verify-devcard.sh.

Python 3, run with -I by the shell scripts; the host tests import it.  Every
command prints a stable, shell-friendly result and exits nonzero on a policy
violation, so a caller can use it directly as a check.

Commands:
  aic-find ROOT       AIC8800 firmware our own paths put in ROOT: anything
                      under the user-override directory aic8800_fw (the
                      OVERLAY / AIC_OVERRIDE path) and any manifest-named
                      file outside Fedora's standard linux-firmware path
                      aic/aic8800d80 (DECISIONS 2026-11-11; Dave 2026-11-19:
                      the standard linux-firmware package is fine).
                      Prints one path per line; exit 1 when any is found.
  repart-root ROOT    every effective systemd-repart unit carries the
                      --discard=no drop-in; exit 1 with a diagnostic otherwise.
  repart-initramfs-listing
                      stdin is an lsinitrd listing: no systemd-repart, or one
                      with the --discard=no drop-in; exit 1 otherwise.
  enabled-repos DIR [DIR...]
                      enabled dnf repository ids, sorted, each followed by a
                      space (the awk's sort -u | tr '\n' ' ').
  dumpe2fs IMG        "X GiB, Y GiB free" from dumpe2fs -h.
  loader-entry FILE FIELD
                      linux, initrd or options of a BLS entry file.
  shadow              stdin is /etc/shadow: "salt<TAB>root-hash<TAB>others".
  passwd-sole-root FILE
                      exactly one uid 0 named root and no other human user.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

AIC_PATTERN = re.compile(r"aic8800", re.IGNORECASE)
MANIFEST = "usr/share/cubie-a7a/aic8800-d80-usb.manifest"
FIRMWARE = "usr/lib/firmware"
# Fedora's standard linux-firmware package installs the D80 files here; Dave
# 2026-11-19: that package is fine and must not be rejected.  Our own
# OVERLAY / AIC_OVERRIDE path is aic8800_fw, which the image must not carry.
LINUX_FIRMWARE_AIC = "aic/aic8800d80"
OVERRIDE_DIR = "aic8800_fw"
REPART_UNITS = ("systemd-repart.service", "systemd-repart@.service")
REPART_DROPIN = "10-cubie-a7a-no-discard.conf"
REPART_REPARTD = ("etc/repart.d", "usr/lib/repart.d", "usr/local/lib/repart.d")


def aic_manifest_names(root):
    """File names recorded in the driver package's manifest, in order."""
    man = Path(root) / MANIFEST
    if not man.is_file():
        return []
    names = []
    for line in man.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts:
            names.append(parts[0])
    return names


def _under_firmware(root):
    fw = Path(root) / FIRMWARE
    if not fw.is_dir():
        return []
    return [p for p in fw.rglob("*") if p.is_file() or p.is_symlink()]


def _from_linux_firmware(rel):
    return rel == LINUX_FIRMWARE_AIC or rel.startswith(LINUX_FIRMWARE_AIC + "/")


def aic_find(root):
    """Every AIC8800 file our own paths put in the image's firmware tree.

    Fedora's standard linux-firmware files (aic/aic8800d80) are allowed.
    Two tests catch ours: anything under the user-override directory
    aic8800_fw (what OVERLAY / AIC_OVERRIDE would populate) and any other
    path naming aic8800, plus each manifest name with its optional
    .xz/.zst suffix outside linux-firmware's directory (a copy under an
    unrelated directory).
    """
    fw = Path(root) / FIRMWARE
    hits = []
    for path in _under_firmware(root):
        rel = str(path.relative_to(fw))
        if _from_linux_firmware(rel):
            continue
        if rel == OVERRIDE_DIR or rel.startswith(OVERRIDE_DIR + "/"):
            hits.append(str(path))
        elif AIC_PATTERN.search(rel):
            hits.append(str(path))
    names = aic_manifest_names(root)
    if names:
        wanted = set()
        for name in names:
            wanted.update((name, name + ".xz", name + ".zst"))
        for path in _under_firmware(root):
            rel = str(path.relative_to(fw))
            if _from_linux_firmware(rel):
                continue
            if path.name in wanted and str(path) not in hits:
                hits.append(str(path))
    return sorted(hits)


def enabled_repo_ids(dirs):
    """Ids of the enabled repositories in dnf's .repo files, sorted.

    Mirrors the awk repo-file parse (a section header names the id, an
    ``enabled = 1`` line prints it) over every *.repo in every directory,
    then ``sort -u``.  A missing directory is skipped (find's error is
    suppressed upstream).
    """
    ids = set()
    for directory in dirs:
        path = Path(directory)
        if not path.is_dir():
            continue
        for repo in sorted(path.glob("*.repo")):
            try:
                text = repo.read_text()
            except OSError:
                continue
            ident = None
            for line in text.splitlines():
                if line.startswith("["):
                    ident = line[1:-1]
                elif ident is not None and re.match(r"enabled *= *1", line):
                    ids.add(ident)
    return sorted(ids)


def parse_dumpe2fs(text):
    """The ``key: value`` pairs of ``dumpe2fs -h``."""
    values = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    return values


def format_dumpe2fs(text):
    """The root-filesystem size line, as the awk replacement prints it."""

    def number(key):
        try:
            return int(parse_dumpe2fs(text).get(key, "") or 0)
        except ValueError:
            return 0

    blocks, free, size = (
        number("Block count"),
        number("Free blocks"),
        number("Block size"),
    )
    return f"{blocks * size / 2**30:.2f} GiB, {free * size / 2**30:.2f} GiB free"


def loader_field(path, field):
    """One field of a BLS entry: linux, initrd or options.

    Matches ``awk '$1=="FIELD"{...}'``: the first whitespace-separated field
    must be exactly FIELD.  options is the remaining fields joined by single
    spaces (awk rebuilds the record after $1=""), with one line per match;
    a missing or unreadable file yields the empty string, as the awk did.
    """
    entry = Path(path)
    if not entry.is_file():
        return ""
    values = []
    for line in entry.read_text().splitlines():
        parts = line.split()
        if not parts or parts[0] != field:
            continue
        if field == "options":
            values.append(" ".join(parts[1:]))
        else:
            values.append(parts[1] if len(parts) > 1 else "")
    return "\n".join(values)


def shadow_fields(text):
    """(root salt, root hash, non-root users with a password) of /etc/shadow.

    Mirrors ``awk -F:``: the root hash's third $-separated field is the
    salt, and any other user whose password starts with $ has a password.
    """
    salt, root_hash, others = "", "", []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user, password = parts[0], parts[1]
        if user == "root":
            root_hash = password
            fields = password.split("$")
            if len(fields) >= 3:
                salt = fields[2]
        elif password.startswith("$"):
            others.append(user)
    return salt, root_hash, others


def passwd_sole_root(text):
    """Exactly one uid 0, named root, and no other human (1000-59999) user.

    Mirrors the check-sshd awk over /etc/passwd.
    """
    roots = 0
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 3:
            continue
        user, uid = parts[0], parts[2]
        try:
            uid = int(uid)
        except ValueError:
            uid = 0
        if uid == 0:
            if user != "root":
                return False
            roots += 1
        elif 1000 <= uid < 60000 and user != "root":
            return False
    return roots == 1


def _exec_start_lines(path):
    if not path.is_file():
        return []
    return [
        line[len("ExecStart=") :]
        for line in path.read_text().splitlines()
        if line.startswith("ExecStart=")
    ]


def repart_unit_ok(root, unit):
    """True when UNIT carries the no-discard protection.

    The drop-in repeats the unit's own ExecStart with --discard=no, no other
    drop-in sets ExecStart, and /etc does not replace the unit with a regular
    file.  A masked unit (a /dev/null symlink) is left alone: it cannot run.
    """
    root = Path(root)
    lib = root / "usr/lib/systemd/system" / unit
    etc = root / "etc/systemd/system" / unit
    if etc.is_symlink():
        try:
            if etc.resolve() == Path("/dev/null"):
                return True
        except OSError:
            pass
    if etc.exists() and not etc.is_symlink():
        return False
    if not lib.is_file():
        return False
    stock = _exec_start_lines(lib)
    if len(stock) != 1 or not stock[0]:
        return False
    dropin = root / "etc/systemd/system" / (unit + ".d") / REPART_DROPIN
    if not dropin.is_file():
        return False
    lines = [
        line
        for line in dropin.read_text().splitlines()
        if line and not line.startswith("#")
    ]
    if lines != ["[Service]", "ExecStart=", f"ExecStart={stock[0]} --discard=no"]:
        return False
    for directory in (dropin.parent, lib.parent / (unit + ".d")):
        if not directory.is_dir():
            continue
        for conf in sorted(directory.glob("*.conf")):
            if conf == dropin:
                continue
            if any(
                line.startswith("ExecStart") for line in conf.read_text().splitlines()
            ):
                return False
    return True


def repart_root_ok(root):
    """Every effective systemd-repart unit carries the protection."""
    root = Path(root)
    problems = []
    for unit in REPART_UNITS:
        lib = root / "usr/lib/systemd/system" / unit
        etc = root / "etc/systemd/system" / unit
        if not lib.exists() and not etc.exists() and not etc.is_symlink():
            continue
        if not repart_unit_ok(root, unit):
            problems.append(f"{unit} lacks the --discard=no drop-in")
    configs = []
    for rel in REPART_REPARTD:
        directory = root / rel
        if directory.is_dir():
            configs += [c for c in directory.glob("*.conf") if c.is_file()]
    if (
        configs
        and not (root / "usr/lib/systemd/system/systemd-repart.service").is_file()
    ):
        problems.append("repart.d configuration without systemd-repart.service")
    return (not problems, problems)


def repart_initramfs_ok(listing):
    """An initramfs listing: no systemd-repart, or one with the drop-in."""
    if "systemd-repart" not in listing:
        return True, ""
    if f"systemd-repart.service.d/{REPART_DROPIN}" not in listing:
        return (
            False,
            "initramfs carries systemd-repart without the --discard=no drop-in",
        )
    return True, ""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("aic-find")
    p.add_argument("root", type=Path)
    p = sub.add_parser("repart-root")
    p.add_argument("root", type=Path)
    p = sub.add_parser("repart-initramfs-listing")
    p = sub.add_parser("enabled-repos")
    p.add_argument("dirs", nargs="+", type=Path)
    p = sub.add_parser("dumpe2fs")
    p.add_argument("img", type=Path)
    p = sub.add_parser("loader-entry")
    p.add_argument("path", type=Path)
    p.add_argument("field", choices=("linux", "initrd", "options"))
    p = sub.add_parser("shadow")
    p = sub.add_parser("passwd-sole-root")
    p.add_argument("path", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "aic-find":
        hits = aic_find(a.root)
        for hit in hits:
            print(hit)
        return 1 if hits else 0
    if a.cmd == "repart-root":
        ok, problems = repart_root_ok(a.root)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 0 if ok else 1
    if a.cmd == "repart-initramfs-listing":
        ok, problem = repart_initramfs_ok(sys.stdin.read())
        if problem:
            print(problem, file=sys.stderr)
        return 0 if ok else 1
    if a.cmd == "enabled-repos":
        sys.stdout.write("".join(i + " " for i in enabled_repo_ids(a.dirs)))
        return 0
    if a.cmd == "dumpe2fs":
        r = subprocess.run(
            ["dumpe2fs", "-h", str(a.img)], capture_output=True, text=True
        )
        print(format_dumpe2fs(r.stdout))
        return 0
    if a.cmd == "loader-entry":
        sys.stdout.write(loader_field(a.path, a.field))
        return 0
    if a.cmd == "shadow":
        salt, root_hash, others = shadow_fields(sys.stdin.read())
        print(f"{salt}\t{root_hash}\t{' '.join(others)}")
        return 0
    if a.cmd == "passwd-sole-root":
        if not passwd_sole_root(Path(a.path).read_text()):
            print(
                f"{a.path}: not exactly one root login and no other human user",
                file=sys.stderr,
            )
            return 1
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
