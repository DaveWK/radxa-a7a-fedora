#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Image-policy checks shared by fedora/mkdevcard.sh and
fedora/verify-devcard.sh.

Python 3, run with -I by the shell scripts; the host tests import it.  Every
command prints a stable, shell-friendly result and exits nonzero on a policy
violation, so a caller can use it directly as a check.

Commands:
  aic-overlay DIR     AIC8800 firmware paths in an OVERLAY directory that
                      must be refused before the copy: anything under
                      usr/lib/firmware/ or lib/firmware/ matching aic/,
                      aic8800*, or *aic8800* (DECISIONS 2026-11-11; Dave
                      2026-11-19: Fedora's standard linux-firmware files are
                      fine, our own are not).  Prints one path per line;
                      exit 1 when any is found.
  aic-provenance ROOT [--ownership FILE] [--report FILE]
                      every file under usr/lib/firmware/aic* (and any stray
                      aic8800* or manifest-named file under firmware/) in ROOT
                      must be owned by a signed Fedora package and match that
                      package's recorded digest.  Ownership comes from ROOT's
                      rpm database, or from a recorded TSV / rpm -qlv --dump
                      FILE.  Prints one problem per line; exit 1 on failure.
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
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

AIC_PATTERN = re.compile(r"aic8800", re.IGNORECASE)
MANIFEST = "usr/share/cubie-a7a/aic8800-d80-usb.manifest"
FIRMWARE_PREFIXES = (("usr", "lib", "firmware"), ("lib", "firmware"))
FIRMWARE = "usr/lib/firmware"
# Provenance, not path: Fedora's standard linux-firmware package owns
# aic/aic8800d80 and is fine (Dave 2026-11-19); any unowned, modified or
# non-Fedora file under an AIC firmware path is ours and forbidden
# (DECISIONS 2026-11-11).
REPART_UNITS = ("systemd-repart.service", "systemd-repart@.service")
REPART_DROPIN = "10-cubie-a7a-no-discard.conf"
REPART_REPARTD = ("etc/repart.d", "usr/lib/repart.d", "usr/local/lib/repart.d")
# rpm's PGPHASHALGO values (rpm/rpmpgp.h).
RPM_ALGO = {1: "md5", 2: "sha1", 3: "sha224", 8: "sha256", 9: "sha384", 10: "sha512"}
DIGEST_ALGO_DEFAULT = 8
RPMDB_CANDIDATES = (
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "var/lib/rpm/rpmdb.sqlite",
    "var/lib/rpm/Packages",
)


class PolicyError(RuntimeError):
    """A policy check could not be performed; callers must fail closed."""


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


def _firmware_rel(rel):
    """Strip usr/lib/firmware/ or lib/firmware/ prefix, or return None."""
    parts = rel.split("/")
    for prefix in FIRMWARE_PREFIXES:
        if len(parts) > len(prefix) and tuple(parts[: len(prefix)]) == prefix:
            return "/".join(parts[len(prefix) :])
    return None


def _aic_overlay_rel(fw_rel):
    """True when a firmware-relative overlay path targets AIC8800 firmware."""
    head = fw_rel.split("/", 1)[0].lower()
    return (
        head == "aic" or head.startswith("aic8800") or bool(AIC_PATTERN.search(fw_rel))
    )


def _aic_root_rel(fw_rel):
    """True when a firmware-relative root path is under aic* or names aic8800."""
    head = fw_rel.split("/", 1)[0].lower()
    return head.startswith("aic") or bool(AIC_PATTERN.search(fw_rel))


def aic_overlay_inputs(overlay):
    """Overlay inputs that would land in an AIC8800 firmware path.

    mkdevcard.sh refuses these before the overlay copy: only a Fedora package
    may put AIC8800 firmware in an image, and the overlay is ours.
    """
    base = Path(overlay)
    hits = []
    if not base.is_dir():
        return hits
    for path in base.rglob("*"):
        if not (path.is_file() or path.is_symlink()):
            continue
        rel = path.relative_to(base).as_posix()
        fw_rel = _firmware_rel(rel)
        if fw_rel is not None and _aic_overlay_rel(fw_rel):
            hits.append(str(path))
    return sorted(hits)


def _firmware_dirs(root):
    """Firmware directories under ROOT without traversing usr-merge twice."""
    root = Path(root)
    dirs = []
    usr_fw = root / "usr/lib/firmware"
    if usr_fw.is_dir():
        dirs.append(usr_fw)
    lib = root / "lib"
    lib_fw = root / "lib/firmware"
    if (
        lib.is_dir()
        and not lib.is_symlink()
        and lib_fw.is_dir()
        and not lib_fw.is_symlink()
    ):
        dirs.append(lib_fw)
    return dirs


def aic_root_files(root):
    """Every regular file and symlink under usr/lib/firmware/aic*, plus any
    stray aic8800* or manifest-named file under firmware/.
    """
    root = Path(root)
    wanted = set()
    for name in aic_manifest_names(root):
        wanted.update((name, name + ".xz", name + ".zst"))
    out = []
    for fw in _firmware_dirs(root):
        for path in fw.rglob("*"):
            if not (path.is_file() or path.is_symlink()):
                continue
            fw_rel = path.relative_to(fw).as_posix()
            if _aic_root_rel(fw_rel) or path.name in wanted:
                out.append(path)
    return sorted(out)


def _file_digest(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _resolve_within(root, path):
    """The regular file a symlink points at inside ROOT, or None on escape/loop."""
    root_res = Path(root).resolve()
    cur = path
    seen = set()
    while cur.is_symlink():
        if cur in seen:
            return None
        seen.add(cur)
        dest = os.readlink(cur)
        if os.path.isabs(dest):
            cur = root_res / dest.lstrip("/")
        else:
            cur = cur.parent / dest
        cur = Path(os.path.normpath(cur))
        try:
            cur.relative_to(root_res)
        except ValueError:
            return None
    if not cur.is_file():
        return None
    try:
        resolved = cur.resolve()
        resolved.relative_to(root_res)
    except (OSError, ValueError):
        return None
    return resolved


def _recorded_ownership(path):
    """Index path -> (pkg, digest, algo, linkto, is_fedora) from a recorded file.

    Accepts either:
      - tab-separated ``pkg<TAB>path<TAB>digest[<TAB>algo[<TAB>linkto[<TAB>fedora]]]``
      - ``rpm -qlv --dump`` / ``rpm -q --dump`` lines (11 whitespace fields,
        with optional ``# package: <name>`` comment header; default linux-firmware)
    """
    index = {}
    text = Path(path).read_text()
    dump_pkg = "linux-firmware"
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            m = re.match(r"#\s*package:\s*(\S+)", stripped)
            if m:
                dump_pkg = m.group(1)
            continue
        if "\t" in line:
            parts = line.split("\t")
            if len(parts) < 3:
                raise PolicyError(f"{path}:{number}: bad ownership record {line!r}")
            pkg, name, digest = parts[0], parts[1], parts[2].lower()
            algo = int(parts[3]) if len(parts) > 3 and parts[3] else DIGEST_ALGO_DEFAULT
            linkto = parts[4] if len(parts) > 4 else ""
            if len(parts) > 5 and parts[5] != "":
                is_fedora = parts[5].lower() not in ("0", "false", "no", "non-fedora")
            else:
                is_fedora = True
            index[name.lstrip("/")] = (pkg, digest, algo, linkto, is_fedora)
            continue
        # rpm -qlv --dump: path size mtime digest mode owner group iscfg isdoc rdev symlink
        parts = stripped.split()
        if len(parts) < 11:
            raise PolicyError(f"{path}:{number}: bad ownership record {line!r}")
        name = parts[0].lstrip("/")
        digest = parts[3].lower()
        mode = parts[4]
        linkto = "" if parts[10] == "X" else parts[10]
        if mode.startswith("04"):
            continue  # directory entry in rpm --dump
        if linkto:
            digest = ""
        index[name] = (dump_pkg, digest, DIGEST_ALGO_DEFAULT, linkto, True)
    return index


def _live_ownership(root):
    """Index path -> (pkg, digest, algo, linkto, is_fedora) from ROOT's rpmdb."""
    root = Path(root)
    if not any((root / cand).is_file() for cand in RPMDB_CANDIDATES):
        raise PolicyError(f"no rpm database found under {root}")
    try:
        import rpm
    except ImportError as exc:
        raise PolicyError(f"python3-rpm is unavailable: {exc}") from exc
    try:
        ts = rpm.TransactionSet(str(root))
        index = {}
        for hdr in ts.dbMatch():
            filenames = hdr["filenames"]
            if not filenames:
                continue
            raw_algo = hdr["filedigestalgo"]
            algo = int(raw_algo) if raw_algo is not None else DIGEST_ALGO_DEFAULT
            pkg = str(hdr["name"])
            vendor = str(hdr["vendor"] or "")
            signed = bool(hdr["rsaheader"] or hdr["sigpgp"] or hdr["dsaheader"])
            is_fedora = vendor == "Fedora Project" and signed
            digests = hdr["filedigests"] or []
            linktos = hdr["filelinktos"] or []
            for idx, name in enumerate(filenames):
                digest = str(digests[idx]).lower() if idx < len(digests) else ""
                linkto = str(linktos[idx]) if idx < len(linktos) else ""
                index[str(name).lstrip("/")] = (pkg, digest, algo, linkto, is_fedora)
    except Exception as exc:
        raise PolicyError(f"cannot read the rpm database under {root}: {exc}") from exc
    if not index:
        raise PolicyError(f"no installed packages found under {root}")
    return index


def _digest_problems(path, label, entry):
    pkg, recorded, algo, _linkto, _is_fedora = entry
    if not recorded or set(recorded) == {"0"}:
        return [f"{label}: {pkg} records no file digest"]
    name = RPM_ALGO.get(algo)
    if name is None:
        return [f"{label}: {pkg} records digest algorithm {algo}, unsupported here"]
    try:
        actual = _file_digest(path, name)
    except OSError as exc:
        return [f"{label}: unreadable ({exc})"]
    if actual != recorded:
        return [
            f"{label}: owned by {pkg} but modified "
            f"(actual {actual}, package records {recorded})"
        ]
    return []


def aic_problems(root, ownership=None):
    """Every provenance problem in ROOT's AIC8800 firmware tree.

    Every file under usr/lib/firmware/aic* (and any stray aic8800* or
    manifest-named firmware file) must be owned by a signed Fedora package
    with a digest matching that package's recorded digest.  A symlink must
    itself be owned by a Fedora package with a matching target, and resolve
    inside ROOT to a Fedora-owned file with a matching digest.
    """
    root = Path(root)
    if ownership:
        index = _recorded_ownership(ownership)
    else:
        index = _live_ownership(root)
    problems = []
    records = []
    root_res = root.resolve()
    for path in aic_root_files(root):
        rel = path.relative_to(root).as_posix()
        entry = index.get(rel)
        if entry is None:
            problems.append(f"{rel}: owned by no installed package")
            continue
        pkg, digest, algo, linkto, is_fedora = entry
        if not is_fedora:
            problems.append(f"{rel}: owned by non-Fedora package {pkg}")
            continue
        if path.is_symlink():
            actual_link = os.readlink(path)
            if not linkto:
                problems.append(f"{rel}: symlink replaces a non-symlink owned by {pkg}")
                continue
            if actual_link != linkto:
                problems.append(
                    f"{rel}: symlink owned by {pkg} was modified "
                    f"(actual -> {actual_link}, package records -> {linkto})"
                )
                continue
            target = _resolve_within(root, path)
            if target is None:
                problems.append(f"{rel}: symlink does not resolve inside the image")
                continue
            target_rel = target.relative_to(root_res).as_posix()
            target_entry = index.get(target_rel)
            if target_entry is None:
                problems.append(
                    f"{rel}: symlink target {target_rel} is owned by no package"
                )
                continue
            if not target_entry[4]:
                problems.append(
                    f"{rel}: symlink target {target_rel} is owned by "
                    f"non-Fedora package {target_entry[0]}"
                )
                continue
            problems.extend(_digest_problems(target, rel, target_entry))
            records.append((pkg, rel, target_entry[1], target_entry[2], linkto))
            continue
        if linkto:
            problems.append(f"{rel}: regular file replaces a symlink owned by {pkg}")
            continue
        problems.extend(_digest_problems(path, rel, entry))
        records.append((pkg, rel, digest, algo, ""))
    return problems, records


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
    p = sub.add_parser("aic-overlay")
    p.add_argument("overlay", type=Path)
    p = sub.add_parser("aic-provenance")
    p.add_argument("root", type=Path)
    p.add_argument("--ownership", type=Path)
    p.add_argument("--report", type=Path)
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
    if a.cmd == "aic-overlay":
        hits = aic_overlay_inputs(a.overlay)
        for hit in hits:
            print(hit)
        return 1 if hits else 0
    if a.cmd == "aic-provenance":
        try:
            problems, records = aic_problems(a.root, a.ownership)
        except PolicyError as exc:
            print(f"aic-provenance: {exc}", file=sys.stderr)
            return 1
        for problem in problems:
            print(problem)
        if a.report:
            with open(a.report, "w") as fh:
                for pkg, rel, digest, algo, linkto in records:
                    fh.write(f"{pkg}\t{rel}\t{digest}\t{algo}\t{linkto}\n")
        return 1 if problems else 0
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
