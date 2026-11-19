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
  repart-root ROOT    every effective systemd-repart invocation carries
                      --discard=no; exit 1 with a diagnostic otherwise.  The
                      effective command comes from the unit plus every drop-in
                      in systemd precedence order, including indented
                      ExecStart= lines and ExecStart= resets.
  repart-initramfs IMG [--chroot ROOT | --run-build-ns SCRIPT] [--forbid-repart]
                      extract systemd-repart units, drop-ins and repart.d
                      configs from IMG via lsinitrd and verify the effective
                      command carries --discard=no (or is absent/masked);
                      never accepts a drop-in by filename alone.
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
import base64
import bz2
import errno
import gzip
import hashlib
import importlib
import lzma
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

AIC_PATTERN = re.compile(r"aic8800", re.IGNORECASE)
MANIFEST = "usr/share/cubie-a7a/aic8800-d80-usb.manifest"
REPO_MANIFEST = (
    Path(__file__).resolve().parent
    / "rpm/cubie-a7a-aic8800-usb/aic8800-d80-usb.manifest"
)
FIRMWARE_PREFIXES = (("usr", "lib", "firmware"), ("lib", "firmware"))
FIRMWARE = "usr/lib/firmware"
# SHA-256 of the OpenPGP certificates (binary packets, not ASCII armor)
# shipped as RPM-GPG-KEY-fedora-{44,45,46}-primary in Fedora's distribution
# keys. A new release key needs independent review before admission. Neither
# a key's self-declared user ID nor a short issuer ID is a trust anchor.
FEDORA_CERTIFICATES = {
    "ee42b9c07cf45061e59446506442fed9a68270e2a65b775d41b2549501fc4dbc",
    "ecf2e6d384554b1ddd2b221d90dc1d5c96b351c2e16204c798f63d1213bdb414",
    "b176af5099fa5f13452ad84d33821edcee235cd1d484018fe96daa39e54e6a50",
}
# Provenance, not path: Fedora's standard linux-firmware package owns
# aic/aic8800d80 and is fine (Dave 2026-11-19); any unowned, modified or
# non-Fedora file under an AIC firmware path is ours and forbidden
# (DECISIONS 2026-11-11).
REPART_UNITS = ("systemd-repart.service", "systemd-repart@.service")
REPART_REPARTD = (
    "etc/repart.d",
    "run/repart.d",
    "usr/lib/repart.d",
    "usr/local/lib/repart.d",
)
# systemd unit search path, highest precedence first (systemd-262.1-1.fc45,
# derived from `systemd-analyze unit-paths` and verified offline with
# `systemd-analyze --root= --generators=no verify`).
SYSTEMD_UNIT_DIRS = (
    "etc/systemd/system.control",
    "run/systemd/system.control",
    "etc/systemd/system",
    "etc/systemd/system.attached",
    "run/systemd/system",
    "run/systemd/system.attached",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
)
DISCARD_FLAG = "--discard=no"
UNIT_CHAR = r"[A-Za-z0-9_:.\\-]"
REPART_NAME = rf"systemd-repart(?:-{UNIT_CHAR}+)?(?:@{UNIT_CHAR}*)?\.service"
REPART_DASHED_DROPIN = (
    rf"systemd-(?:repart-(?:{UNIT_CHAR}+-)?)?(?:@{UNIT_CHAR}*)?\.service"
)
UNIT_DIR_RE = (
    r"(?:(?:etc|run)/systemd/system(?:\.(?:control|attached))?"
    r"|(?:usr/local/lib|usr/lib|lib)/systemd/system)"
)
INITRAMFS_REPART_RE = re.compile(
    rf"^{UNIT_DIR_RE}/"
    rf"(?:(?:[^/]+\.(?:wants|requires)/)?{REPART_NAME}"
    rf"|(?:{REPART_NAME}|{REPART_DASHED_DROPIN}|service)\.d/[^/]+\.conf)$"
    r"|^(?:etc|run|usr/lib|usr/local/lib)/repart\.d/[^/]+\.conf$"
)
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


def _scandir_if_exists(path):
    """Return sorted Path entries of directory PATH, failing closed on I/O errors.

    Returns [] only when PATH does not exist or is not a directory (ENOENT/ENOTDIR).
    Raises PolicyError on EACCES or any other OSError so an unreadable directory
    cannot silently appear empty.
    """
    try:
        with os.scandir(path) as it:
            return sorted((Path(entry.path) for entry in it), key=lambda p: p.name)
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            return []
        raise PolicyError(f"cannot read directory {path}: {exc}") from exc


def _walk_entries(base):
    """Yield every regular file and symlink under BASE, failing closed on errors."""

    def on_error(exc):
        raise PolicyError(f"cannot traverse {exc.filename or base}: {exc}") from exc

    for dirpath, dirnames, filenames in os.walk(base, onerror=on_error):
        dirnames.sort()
        cur = Path(dirpath)
        for dname in dirnames:
            dpath = cur / dname
            if dpath.is_symlink():
                yield dpath
        for fname in sorted(filenames):
            fpath = cur / fname
            if fpath.is_symlink() or fpath.is_file():
                yield fpath


def _read_manifest_file(path):
    """File names recorded in a manifest FILE, in order."""
    man = Path(path)
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


def aic_manifest_names(root):
    """File names recorded in the driver package's manifest, in order."""
    return _read_manifest_file(Path(root) / MANIFEST)


def _wanted_manifest_names(root=None, extra_manifest=None):
    """Manifest-named AIC8800 files (raw, .xz, .zst) from root/repo/explicit."""
    sources = []
    if extra_manifest is not None:
        extra = Path(extra_manifest)
        if not extra.is_file():
            raise PolicyError(f"manifest not found: {extra}")
        sources.append(extra)
    if root is not None:
        sources.append(Path(root) / MANIFEST)
    if REPO_MANIFEST.is_file():
        sources.append(REPO_MANIFEST)
    wanted = set()
    for src in sources:
        for name in _read_manifest_file(src):
            wanted.update((name, name + ".xz", name + ".zst"))
    return wanted


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


def aic_overlay_inputs(overlay, manifest=None):
    """Overlay inputs that would land in an AIC8800 firmware path or carry a
    manifest-named AIC8800 file anywhere in the overlay.

    mkdevcard.sh refuses these before the overlay copy: only a Fedora package
    may put AIC8800 firmware in an image, and the overlay is ours.
    """
    base = Path(overlay)
    hits = []
    if not base.is_dir():
        return hits
    wanted = _wanted_manifest_names(root=base, extra_manifest=manifest)
    for path in _walk_entries(base):
        rel = path.relative_to(base).as_posix()
        fw_rel = _firmware_rel(rel)
        if (fw_rel is not None and _aic_overlay_rel(fw_rel)) or path.name in wanted:
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
    wanted = _wanted_manifest_names(root=root)
    out = []
    for fw in _firmware_dirs(root):
        for path in _walk_entries(fw):
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


def _load_fedora_keyring(ts):
    """Build an rpm.keyring holding only trusted Fedora release signing keys
    imported in the target root's rpmdb (``gpg-pubkey`` headers).
    """
    import rpm

    keyring = rpm.keyring()
    for hdr in ts.dbMatch("name", "gpg-pubkey"):
        cert = rpm.pubkey(hdr["description"].encode("ascii"))
        digest = hashlib.sha256(base64.b64decode(cert.base64())).hexdigest()
        if digest in FEDORA_CERTIFICATES:
            keyring.addKey(cert)
    return keyring


def _verify_fedora_header(hdr, verify_ts):
    """Verify the installed header signature with the restricted target keyring."""
    if not any(hdr[tag] for tag in ("openpgp", "rsaheader", "dsaheader")):
        return False
    try:
        verify_ts.hdrCheck(hdr.unload())
    except Exception:
        return False
    return True


def _live_ownership(root, wanted_paths=None):
    """Index path -> list[(pkg, digest, algo, linkto, is_fedora)] from ROOT's rpmdb.

    When WANTED_PATHS is provided, only packages owning at least one path in
    WANTED_PATHS undergo cryptographic header signature verification, while
    still validating that ROOT has a readable non-empty rpmdb.
    """
    root = Path(root)
    if not any((root / cand).is_file() for cand in RPMDB_CANDIDATES):
        raise PolicyError(f"no rpm database found under {root}")
    try:
        import rpm
    except ImportError as exc:
        raise PolicyError(f"python3-rpm is unavailable: {exc}") from exc
    try:
        ts = rpm.TransactionSet(str(root))
        fedora_keyring = _load_fedora_keyring(ts)
        verify_ts = rpm.TransactionSet(str(root))
        verify_ts.setKeyring(fedora_keyring)
        verify_ts.setVSFlags(0)
        verify_ts.setVfyFlags(0)
        verify_ts.setVfyLevel(rpm.RPMSIG_SIGNATURE_TYPE | rpm.RPMSIG_DIGEST_TYPE)
        index = {}
        pkg_count = 0
        for hdr in ts.dbMatch():
            pkg = str(hdr["name"] or "")
            if pkg == "gpg-pubkey":
                continue
            filenames = hdr["filenames"]
            if not filenames:
                continue
            pkg_count += 1
            norm_names = [str(name).lstrip("/") for name in filenames]
            if wanted_paths is not None and not any(
                n in wanted_paths for n in norm_names
            ):
                continue
            raw_algo = hdr["filedigestalgo"]
            algo = int(raw_algo) if raw_algo is not None else DIGEST_ALGO_DEFAULT
            is_fedora = _verify_fedora_header(hdr, verify_ts)
            digests = hdr["filedigests"] or []
            linktos = hdr["filelinktos"] or []
            for idx, rel in enumerate(norm_names):
                if wanted_paths is not None and rel not in wanted_paths:
                    continue
                digest = str(digests[idx]).lower() if idx < len(digests) else ""
                linkto = str(linktos[idx]) if idx < len(linktos) else ""
                index.setdefault(rel, []).append((pkg, digest, algo, linkto, is_fedora))
    except PolicyError:
        raise
    except Exception as exc:
        raise PolicyError(f"cannot read the rpm database under {root}: {exc}") from exc
    if pkg_count == 0:
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
    manifest-named firmware file) must be owned by a package whose header
    signature verifies offline against a trusted Fedora release signing key
    imported in ROOT's rpmdb, with a digest matching that package's recorded
    digest.  A symlink must itself be owned by a verified Fedora package with
    a matching target, and resolve inside ROOT to a verified Fedora-owned file
    with a matching digest.
    """
    root = Path(root)
    root_res = root.resolve()
    candidates = aic_root_files(root)
    if ownership:
        raw_index = _recorded_ownership(ownership)
        index = {rel: [entry] for rel, entry in raw_index.items()}
    else:
        wanted_paths = set()
        for path in candidates:
            wanted_paths.add(path.relative_to(root).as_posix())
            if path.is_symlink():
                target = _resolve_within(root, path)
                if target is not None:
                    wanted_paths.add(target.relative_to(root_res).as_posix())
        index = _live_ownership(root, wanted_paths=wanted_paths)
    problems = []
    records = []
    for path in candidates:
        rel = path.relative_to(root).as_posix()
        entries = index.get(rel)
        if not entries:
            problems.append(f"{rel}: owned by no installed package")
            continue
        unverified = [e[0] for e in entries if not e[4]]
        if unverified:
            for pkg in unverified:
                problems.append(
                    f"{rel}: owned by unverified or non-Fedora package {pkg}"
                )
            continue
        entry = entries[0]
        pkg, digest, algo, linkto, _is_fedora = entry
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
            target_entries = index.get(target_rel)
            if not target_entries:
                problems.append(
                    f"{rel}: symlink target {target_rel} is owned by no package"
                )
                continue
            bad_targets = [e[0] for e in target_entries if not e[4]]
            if bad_targets:
                for tpkg in bad_targets:
                    problems.append(
                        f"{rel}: symlink target {target_rel} is owned by "
                        f"unverified or non-Fedora package {tpkg}"
                    )
                continue
            target_entry = target_entries[0]
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

    Mirrors the repo-file parse (a section header names the id, an
    ``enabled = 1`` line prints it) over every *.repo in every directory,
    then ``sort -u``.  A missing directory is skipped; unreadable directories
    or .repo files fail closed with PolicyError.
    """
    ids = set()
    for directory in dirs:
        path = Path(directory)
        for repo in _scandir_if_exists(path):
            if not repo.name.endswith(".repo"):
                continue
            try:
                text = repo.read_text()
            except OSError as exc:
                raise PolicyError(f"cannot read repo file {repo}: {exc}") from exc
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

    A malformed UID or GID field is an error, never 0: ``root:x:oops:0:...``
    must fail.
    """
    roots = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(":")
        if len(parts) < 4:
            return False
        user, uid_field, gid_field = parts[0], parts[2], parts[3]
        if not re.fullmatch(r"[0-9]+", uid_field) or not re.fullmatch(
            r"[0-9]+", gid_field
        ):
            return False
        # uid_t/gid_t exclude the all-ones sentinel. Bound before int() so a
        # very long decimal field produces a policy rejection, not an exception.
        uid_field, gid_field = (
            value.lstrip("0") or "0" for value in (uid_field, gid_field)
        )
        if any(
            len(value) > 10 or int(value) > 4294967294
            for value in (uid_field, gid_field)
        ):
            return False
        uid = int(uid_field)
        if uid == 0:
            if user != "root":
                return False
            roots += 1
        elif 1000 <= uid < 60000 and user != "root":
            return False
    return roots == 1


def _logical_lines(text):
    """Unit-file logical lines: backslash continuations joined per systemd."""
    lines = []
    buf = ""
    for line in text.splitlines():
        if buf:
            stripped = line.lstrip()
            if stripped.startswith(("#", ";")):
                continue
            line = stripped
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        lines.append(buf)
        buf = ""
    if buf:
        lines.append(buf)
    return lines


def _service_assignments(text):
    """Ordered (key, value) pairs inside [Service], whitespace tolerated."""
    out = []
    section = None
    for line in _logical_lines(text):
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            continue
        if section != "Service" or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        out.append((key.strip(), value.strip()))
    return out


def _masked(path):
    try:
        if not path.is_symlink():
            return False
        return os.readlink(path) == "/dev/null" or os.path.realpath(path) == "/dev/null"
    except OSError:
        return False


def _active_unit_dirs(root):
    """Unit directories in precedence order, skipping lib/ when usr-merged."""
    dirs = []
    lib = root / "lib"
    for rel in SYSTEMD_UNIT_DIRS:
        if rel == "lib/systemd/system" and lib.is_symlink():
            continue
        dirs.append(rel)
    return dirs


def _repart_units(root):
    names = set(REPART_UNITS)
    dashed_instances = []
    for directory in _active_unit_dirs(root):
        path = root / directory
        for entry in _scandir_if_exists(path):
            raw = entry.name
            stem = raw.removesuffix(".d")
            if re.fullmatch(REPART_NAME, stem):
                names.add(stem)
            if raw.endswith(".d") and re.fullmatch(REPART_DASHED_DROPIN, stem):
                base_stem = stem.removesuffix(".service")
                if "@" in base_stem:
                    dash_prefix, inst = base_stem.split("@", 1)
                    if inst:
                        dashed_instances.append((dash_prefix, inst))
            if raw.endswith((".wants", ".requires")) and entry.is_dir():
                for child in _scandir_if_exists(entry):
                    if re.fullmatch(REPART_NAME, child.name):
                        names.add(child.name)
    # Any dashed-prefix instance drop-in (e.g. systemd-@demo.service.d) applies
    # to every repart template unit sharing that dashed prefix (e.g.
    # systemd-repart@.service instantiated as systemd-repart@demo.service).
    for unit in list(names):
        if not unit.endswith("@.service"):
            continue
        tpl_prefix = unit.removesuffix("@.service")
        for dash_prefix, inst in dashed_instances:
            if tpl_prefix.startswith(dash_prefix):
                names.add(f"{tpl_prefix}@{inst}.service")
    return sorted(names)


def _unit_dropin_scopes(unit):
    """Return systemd's name-based drop-in scopes for UNIT, highest precedence first.

    Matches systemd-262.1-1.fc45 (`systemd-analyze --root= --generators=no verify`):
      1. exact unit (e.g. systemd-a-b@demo.service)
      2. template (e.g. systemd-a-b@.service), when instantiated
      3. dashed prefixes without '@' (e.g. systemd-a-.service, systemd-.service)
      4. for template/instantiated units, dashed prefixes retaining '@<inst>' and '@'
         (e.g. systemd-a-@demo.service, systemd-a-@.service,
          systemd-@demo.service, systemd-@.service)
    Type-wide 'service.d' is searched separately after all load-path directories.
    """
    stem = unit.removesuffix(".service")
    if "@" in stem:
        prefix, instance = stem.split("@", 1)
    else:
        prefix, instance = stem, None
    scopes = [unit]
    if instance:
        scopes.append(f"{prefix}@.service")
    dashed = []
    cur = prefix
    while "-" in cur:
        cur = cur.rsplit("-", 1)[0]
        dashed.append(cur + "-")
    for dash_prefix in dashed:
        scopes.append(f"{dash_prefix}.service")
    if instance is not None:
        for dash_prefix in dashed:
            if instance:
                scopes.append(f"{dash_prefix}@{instance}.service")
            scopes.append(f"{dash_prefix}@.service")
    return scopes


def _scan_dropin_dir(dropin_dir, root, by_name):
    for conf in _scandir_if_exists(dropin_dir):
        if not conf.name.endswith(".conf"):
            continue
        if conf.name not in by_name:
            if _masked(conf):
                by_name[conf.name] = None
            else:
                resolved = _resolve_within(root, conf)
                if resolved is None:
                    raise PolicyError(f"cannot resolve drop-in {conf}")
                by_name[conf.name] = resolved


def _unit_files(root, unit):
    """Resolve UNIT and its effective drop-ins in systemd's exact search order.

    Load-path directories come first (/etc before /run before /usr/lib); within
    each directory, unit -> template -> dashed scopes (including dashed scopes
    retaining the instance); type-wide service.d defaults come last across all
    load-path directories. For each basename, the first match wins; winners are
    applied in global sorted basename order.
    """
    root = Path(root)
    unit_dirs = _active_unit_dirs(root)
    bases = [unit]
    if "@" in unit and not unit.endswith("@.service"):
        bases.append(unit.split("@", 1)[0] + "@.service")
    base = None
    for name in bases:
        for directory in unit_dirs:
            candidate = root / directory / name
            if _masked(candidate):
                return None
            if candidate.is_file() or candidate.is_symlink():
                base = _resolve_within(root, candidate)
                if base is None:
                    raise PolicyError(f"cannot resolve unit {candidate}")
                break
        if base is not None:
            break
    if base is None:
        return []
    name_scopes = _unit_dropin_scopes(unit)
    by_name = {}
    for directory in unit_dirs:
        for scope in name_scopes:
            _scan_dropin_dir(root / directory / (scope + ".d"), root, by_name)
    for directory in unit_dirs:
        _scan_dropin_dir(root / directory / "service.d", root, by_name)
    return [base] + [by_name[n] for n in sorted(by_name) if by_name[n] is not None]


def _effective_exec_start(files):
    """Effective [Service] ExecStart commands after applying FILES in order.

    An empty ``ExecStart=`` resets the list, as systemd does; a later
    assignment appends.  Indented lines and whitespace around ``=`` are
    handled by ``_service_assignments``.  Returns None if any file cannot
    be read (fail closed).
    """
    commands = []
    for path in files:
        if not path.is_file():
            return None
        try:
            text = path.read_text()
        except OSError:
            return None
        for key, value in _service_assignments(text):
            if key != "ExecStart":
                continue
            if value == "":
                commands = []
            else:
                commands.append(value)
    return commands


def _command_carries_no_discard(command):
    """True when COMMAND's effective --discard option is --discard=no."""
    cmd = command.lstrip("@-:+!")
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    discard = None
    for tok in tokens[1:]:
        if tok == "--":
            break
        if tok == DISCARD_FLAG:
            discard = "no"
        elif tok == "--discard" or tok.startswith("--discard="):
            discard = "other"
    return discard == "no"


def _carries_no_discard(commands):
    return bool(commands) and all(_command_carries_no_discard(c) for c in commands)


def repart_root_ok(root):
    """Every effective systemd-repart invocation carries --discard=no."""
    root = Path(root)
    problems = []
    repart_service_seen = False
    for unit in _repart_units(root):
        files = _unit_files(root, unit)
        if files == []:
            continue
        if unit == "systemd-repart.service":
            repart_service_seen = True
        if files is None:
            continue  # masked: cannot run
        commands = _effective_exec_start(files)
        if commands is None:
            problems.append(f"{unit}: unreadable unit or drop-in")
        elif not _carries_no_discard(commands):
            problems.append(f"{unit} runs {commands!r} without {DISCARD_FLAG}")
    configs = []
    for rel in REPART_REPARTD:
        for entry in _scandir_if_exists(root / rel):
            if entry.name.endswith(".conf") and entry.is_file():
                configs.append(entry)
    if configs and not repart_service_seen:
        problems.append("repart.d configuration without systemd-repart.service")
    return (not problems, problems)


LSINITRD_RULE = "=" * 72
LS_ROW_RE = re.compile(r"^([dlcbps-])[rwxsStT-]{9}[.+@]?\s")
CPIO_NEWC_MAGICS = (b"070701", b"070702")


def _norm_archive_path(name):
    rel = name.lstrip("/")
    while rel.startswith("./"):
        rel = rel[2:]
    return rel if rel else "."


def _decompress_initramfs_segment(buf):
    """Decompress a compressed initramfs segment, failing closed on truncation/error."""
    if buf.startswith(b"\x1f\x8b"):
        try:
            return gzip.decompress(buf)
        except OSError as exc:
            raise PolicyError(f"truncated or corrupt gzip initramfs: {exc}") from exc
    if buf.startswith(b"\xfd7zXZ\x00"):
        try:
            return lzma.decompress(buf)
        except lzma.LZMAError as exc:
            raise PolicyError(f"truncated or corrupt xz initramfs: {exc}") from exc
    if buf.startswith(b"BZh"):
        try:
            return bz2.decompress(buf)
        except OSError as exc:
            raise PolicyError(f"truncated or corrupt bzip2 initramfs: {exc}") from exc
    if buf.startswith(b"\x28\xb5\x2f\xfd"):
        try:
            zstd = importlib.import_module("compression.zstd")
            return zstd.decompress(buf)
        except ImportError:
            pass
        except Exception as exc:
            raise PolicyError(f"truncated or corrupt zstd initramfs: {exc}") from exc
        if not shutil.which("zstd"):
            raise PolicyError("zstd is unavailable to verify zstd initramfs")
        res = subprocess.run(["zstd", "-qdc"], input=buf, capture_output=True)
        if res.returncode != 0 or res.stderr.strip():
            raise PolicyError(
                f"truncated or corrupt zstd initramfs: {res.stderr.decode(errors='replace').strip()}"
            )
        return res.stdout
    if buf.startswith((b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18")):
        if not shutil.which("lz4"):
            raise PolicyError("lz4 is unavailable to verify lz4 initramfs")
        res = subprocess.run(["lz4", "-qdc"], input=buf, capture_output=True)
        if res.returncode != 0 or res.stderr.strip():
            raise PolicyError(
                f"truncated or corrupt lz4 initramfs: {res.stderr.decode(errors='replace').strip()}"
            )
        return res.stdout
    raise PolicyError(f"unrecognized initramfs segment magic {buf[:8]!r}")


def _parse_cpio_one(data, offset):
    """Parse one cpio newc/crc archive starting at OFFSET, requiring TRAILER!!!."""
    entries = []
    pos = offset
    length = len(data)
    while True:
        if pos + 110 > length:
            raise PolicyError("truncated cpio header before TRAILER!!!")
        magic = data[pos : pos + 6]
        if magic not in CPIO_NEWC_MAGICS:
            raise PolicyError(f"bad cpio magic {magic!r} at offset {pos}")
        try:
            fields = [
                int(data[pos + 6 + i * 8 : pos + 14 + i * 8], 16) for i in range(13)
            ]
        except ValueError as exc:
            raise PolicyError(f"corrupt cpio header at offset {pos}") from exc
        mode, filesize, namesize = fields[1], fields[6], fields[11]
        pos += 110
        if namesize < 1 or pos + namesize > length:
            raise PolicyError("truncated cpio entry name before TRAILER!!!")
        raw_name = data[pos : pos + namesize]
        if not raw_name.endswith(b"\x00"):
            raise PolicyError("unterminated cpio entry name")
        name = os.fsdecode(raw_name[:-1])
        pos += namesize
        if pos % 4:
            pos += 4 - (pos % 4)
        if pos + filesize > length:
            raise PolicyError(f"truncated cpio payload for {name!r}")
        payload = data[pos : pos + filesize]
        pos += filesize
        if pos % 4:
            pos += 4 - (pos % 4)
        if name == "TRAILER!!!":
            return entries, pos
        rel = _norm_archive_path(name)
        if stat.S_ISLNK(mode):
            entries.append(("symlink", rel, os.fsdecode(payload)))
        elif stat.S_ISREG(mode):
            entries.append(("file", rel, filesize))
        else:
            entries.append(("other", rel, 0))


def parse_cpio_stream(data):
    """Parse one or more concatenated cpio newc/crc archives, each ending in TRAILER!!!."""
    entries = []
    pos = 0
    length = len(data)
    archives = 0
    while pos < length:
        while pos < length and data[pos] == 0:
            pos += 1
        if pos >= length:
            break
        if data[pos : pos + 6] not in CPIO_NEWC_MAGICS:
            raise PolicyError(f"trailing non-cpio bytes at offset {pos}")
        part, pos = _parse_cpio_one(data, pos)
        entries.extend(part)
        archives += 1
    if archives == 0 or not entries:
        raise PolicyError("cpio archive contains no entries")
    return entries


def parse_cpio_initramfs(archive_path):
    """Independently parse an initramfs image (early uncompressed + compressed cpio).

    Every cpio segment must terminate cleanly at TRAILER!!! and every compressed
    segment must decompress cleanly with zero unparsed trailing bytes.
    """
    path = Path(archive_path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read initramfs {path}: {exc}") from exc
    if not data:
        raise PolicyError(f"empty initramfs archive {path}")
    entries = []
    pos = 0
    length = len(data)
    while pos < length:
        while pos < length and data[pos] == 0:
            pos += 1
        if pos >= length:
            break
        if data[pos : pos + 6] in CPIO_NEWC_MAGICS:
            part, pos = _parse_cpio_one(data, pos)
            entries.extend(part)
        else:
            decompressed = _decompress_initramfs_segment(data[pos:])
            entries.extend(parse_cpio_stream(decompressed))
            pos = length
    if not entries:
        raise PolicyError(f"initramfs {path} contains no entries")
    return entries


def _parse_ls_row(line):
    """Parse one lsinitrd `ls -l` row -> (kind, rel, meta), or raise PolicyError."""
    match = LS_ROW_RE.match(line)
    if not match:
        raise PolicyError(f"malformed lsinitrd listing row: {line!r}")
    ftype = match.group(1)
    if ftype in ("c", "b"):
        parts = line.split(None, 9)
        if len(parts) < 10 or not parts[4].endswith(",") or not parts[5].isdigit():
            raise PolicyError(f"malformed lsinitrd device row: {line!r}")
        return ("other", _norm_archive_path(parts[9]), 0)
    parts = line.split(None, 8)
    if len(parts) < 9 or not parts[4].isdigit():
        raise PolicyError(f"malformed lsinitrd listing row: {line!r}")
    size_str, rest = parts[4], parts[8]
    if ftype == "l":
        if " -> " not in rest:
            raise PolicyError(f"malformed lsinitrd symlink row: {line!r}")
        rel, target = rest.split(" -> ", 1)
        return ("symlink", _norm_archive_path(rel), target)
    if ftype == "-":
        return ("file", _norm_archive_path(rest), int(size_str))
    return ("other", _norm_archive_path(rest), 0)


def _parse_lsinitrd_listing(listing):
    """Parse lsinitrd stdout requiring opening and closing 72-'=' section framing.

    Returns (all_rows, repart_entries) where all_rows is a list of
    (kind, relpath, size_or_target) across every file-listing section.
    Raises PolicyError on missing closing separator, malformed listing row, or
    empty listing.
    """
    lines = listing.splitlines()
    rule_indices = [i for i, line in enumerate(lines) if line == LSINITRD_RULE]
    if len(rule_indices) < 2:
        raise PolicyError("incomplete lsinitrd listing: missing closing separator")
    # If file-listing rows appear after the last closing separator, output was truncated.
    trailing = lines[rule_indices[-1] + 1 :]
    if any(LS_ROW_RE.match(line) for line in trailing):
        raise PolicyError(
            "incomplete lsinitrd listing: truncated after file rows without closing separator"
        )
    all_rows = []
    repart_entries = []
    for idx in range(len(rule_indices) - 1):
        section = [
            line
            for line in lines[rule_indices[idx] + 1 : rule_indices[idx + 1]]
            if line
        ]
        if not section:
            continue
        if not any(LS_ROW_RE.match(line) for line in section):
            continue
        for line in section:
            kind, rel, meta = _parse_ls_row(line)
            all_rows.append((kind, rel, meta))
            if kind in ("file", "symlink") and INITRAMFS_REPART_RE.match(rel):
                repart_entries.append((kind, rel, meta))
    if not all_rows:
        raise PolicyError("incomplete lsinitrd listing: no recognized file rows")
    return all_rows, repart_entries


def inspect_initramfs(img, lsinitrd_cmd=None, archive_path=None):
    """Run lsinitrd and cross-check its framed listing against the raw cpio archive.

    Returns (all_rows, repart_entries). Raises PolicyError if lsinitrd fails,
    emits stderr, lacks closing section framing, or disagrees with the
    independently parsed cpio archive (which requires TRAILER!!! on every segment).
    """
    cmd = list(lsinitrd_cmd) if lsinitrd_cmd else ["lsinitrd"]
    listing = subprocess.run(cmd + [str(img)], capture_output=True, text=True)
    if listing.returncode != 0 or listing.stderr.strip():
        msg = listing.stderr.strip() or listing.stdout.strip() or "lsinitrd failed"
        raise PolicyError(f"cannot inspect initramfs {img}: {msg}")
    all_rows, repart_entries = _parse_lsinitrd_listing(listing.stdout)
    archive = Path(archive_path) if archive_path is not None else Path(img)
    cpio_entries = parse_cpio_initramfs(archive)
    listed_paths = sorted(rel for _, rel, _ in all_rows)
    cpio_paths = sorted(rel for _, rel, _ in cpio_entries)
    if listed_paths != cpio_paths:
        raise PolicyError(
            f"initramfs {img} listing mismatch: lsinitrd reported {len(listed_paths)} "
            f"entries, cpio archive holds {len(cpio_paths)}"
        )
    return all_rows, repart_entries


def repart_initramfs_ok(img, lsinitrd_cmd=None, forbid_repart=False, archive_path=None):
    """Extract systemd-repart units/drop-ins from IMG and verify effective command.

    Never accepts a drop-in by filename alone; fails closed when lsinitrd fails
    or disagrees with the independently parsed cpio archive.
    """
    cmd = list(lsinitrd_cmd) if lsinitrd_cmd else ["lsinitrd"]
    try:
        _, entries = inspect_initramfs(img, lsinitrd_cmd=cmd, archive_path=archive_path)
    except PolicyError as exc:
        return False, [str(exc)]
    if not entries:
        return True, []
    with tempfile.TemporaryDirectory(prefix="a7a-initramfs-repart-") as td:
        tree = Path(td)
        for kind, rel, meta in entries:
            if ".." in Path(rel).parts:
                return False, [f"invalid initramfs path: {rel}"]
            dest = tree / rel
            if dest.is_symlink() or dest.exists():
                return False, [f"duplicate initramfs path: {rel}"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            if kind == "symlink":
                if dest.exists() or dest.is_symlink():
                    dest.unlink()
                dest.symlink_to(meta)
            else:
                extracted = subprocess.run(
                    cmd + ["-f", rel, str(img)], capture_output=True
                )
                if (
                    extracted.returncode != 0
                    or extracted.stderr.strip()
                    or len(extracted.stdout) != meta
                ):
                    return False, [f"cannot extract {rel} from {img}"]
                dest.write_bytes(extracted.stdout)
        if forbid_repart:
            problems = []
            for unit in _repart_units(tree):
                files = _unit_files(tree, unit)
                if files:
                    problems.append(f"initramfs contains active {unit}")
            for rel_dir in REPART_REPARTD:
                if any(
                    entry.name.endswith(".conf")
                    for entry in _scandir_if_exists(tree / rel_dir)
                ):
                    problems.append(f"initramfs contains repart.d config in {rel_dir}")
            return (not problems, problems)
        return repart_root_ok(tree)


def initramfs_check(
    img,
    lsinitrd_cmd=None,
    archive_path=None,
    require_paths=(),
    forbid_paths=(),
    file_rel=None,
    require_text=(),
    forbid_text=(),
):
    """Verify path and member-text requirements against a completeness-checked initramfs."""
    cmd = list(lsinitrd_cmd) if lsinitrd_cmd else ["lsinitrd"]
    try:
        all_rows, _ = inspect_initramfs(
            img, lsinitrd_cmd=cmd, archive_path=archive_path
        )
    except PolicyError as exc:
        return False, [str(exc)]
    problems = []
    paths = [rel for _, rel, _ in all_rows]
    for pattern in require_paths:
        if not any(re.search(pattern, p) for p in paths):
            problems.append(f"initramfs {img} missing path matching {pattern!r}")
    for pattern in forbid_paths:
        if any(re.search(pattern, p) for p in paths):
            problems.append(
                f"initramfs {img} contains forbidden path matching {pattern!r}"
            )
    if file_rel is not None:
        norm = _norm_archive_path(file_rel)
        matches = [
            (kind, meta)
            for kind, rel, meta in all_rows
            if rel == norm and kind == "file"
        ]
        if not matches:
            if require_text:
                problems.append(f"initramfs {img} missing file {norm}")
        else:
            expected_size = matches[-1][1]
            extracted = subprocess.run(
                cmd + ["-f", norm, str(img)], capture_output=True
            )
            if (
                extracted.returncode != 0
                or extracted.stderr.strip()
                or len(extracted.stdout) != expected_size
            ):
                problems.append(
                    f"cannot extract complete {norm} from {img} "
                    f"(got {len(extracted.stdout)} bytes, expected {expected_size})"
                )
            else:
                text = extracted.stdout.decode("utf-8", errors="replace")
                for pattern in require_text:
                    if not re.search(pattern, text):
                        problems.append(
                            f"{norm} in {img} missing text matching {pattern!r}"
                        )
                for pattern in forbid_text:
                    if re.search(pattern, text):
                        problems.append(
                            f"{norm} in {img} contains forbidden text matching {pattern!r}"
                        )
    return (not problems, problems)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("aic-overlay")
    p.add_argument("overlay", type=Path)
    p.add_argument("--manifest", type=Path)
    p = sub.add_parser("aic-provenance")
    p.add_argument("root", type=Path)
    p.add_argument("--ownership", type=Path)
    p.add_argument("--report", type=Path)
    p = sub.add_parser("repart-root")
    p.add_argument("root", type=Path)
    p = sub.add_parser("repart-initramfs")
    p.add_argument("img")
    runner = p.add_mutually_exclusive_group()
    runner.add_argument("--chroot", type=Path)
    runner.add_argument("--run-build-ns", type=Path)
    p.add_argument("--forbid-repart", action="store_true")
    p = sub.add_parser("initramfs-check")
    p.add_argument("img")
    ic_runner = p.add_mutually_exclusive_group()
    ic_runner.add_argument("--chroot", type=Path)
    ic_runner.add_argument("--run-build-ns", type=Path)
    p.add_argument("--require-path", action="append", default=[])
    p.add_argument("--forbid-path", action="append", default=[])
    p.add_argument("--file")
    p.add_argument("--require-text", action="append", default=[])
    p.add_argument("--forbid-text", action="append", default=[])
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
        try:
            hits = aic_overlay_inputs(a.overlay, manifest=a.manifest)
        except PolicyError as exc:
            print(f"aic-overlay: {exc}", file=sys.stderr)
            return 1
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
        try:
            ok, problems = repart_root_ok(a.root)
        except PolicyError as exc:
            print(f"repart-root: {exc}", file=sys.stderr)
            return 1
        for problem in problems:
            print(problem, file=sys.stderr)
        return 0 if ok else 1
    if a.cmd == "repart-initramfs":
        lsinitrd_cmd = None
        archive_path = None
        if a.chroot:
            lsinitrd_cmd = ["chroot", str(a.chroot), "lsinitrd"]
            archive_path = a.chroot / a.img.lstrip("/")
        elif a.run_build_ns:
            lsinitrd_cmd = [str(a.run_build_ns), "user", "lsinitrd"]
        try:
            ok, problems = repart_initramfs_ok(
                a.img,
                lsinitrd_cmd=lsinitrd_cmd,
                forbid_repart=a.forbid_repart,
                archive_path=archive_path,
            )
        except PolicyError as exc:
            print(f"repart-initramfs: {exc}", file=sys.stderr)
            return 1
        for problem in problems:
            print(problem, file=sys.stderr)
        return 0 if ok else 1
    if a.cmd == "initramfs-check":
        lsinitrd_cmd = None
        archive_path = None
        if a.chroot:
            lsinitrd_cmd = ["chroot", str(a.chroot), "lsinitrd"]
            archive_path = a.chroot / a.img.lstrip("/")
        elif a.run_build_ns:
            lsinitrd_cmd = [str(a.run_build_ns), "user", "lsinitrd"]
        ok, problems = initramfs_check(
            a.img,
            lsinitrd_cmd=lsinitrd_cmd,
            archive_path=archive_path,
            require_paths=a.require_path,
            forbid_paths=a.forbid_path,
            file_rel=a.file,
            require_text=a.require_text,
            forbid_text=a.forbid_text,
        )
        for problem in problems:
            print(problem, file=sys.stderr)
        return 0 if ok else 1
    if a.cmd == "enabled-repos":
        try:
            ids = enabled_repo_ids(a.dirs)
        except PolicyError as exc:
            print(f"enabled-repos: {exc}", file=sys.stderr)
            return 1
        sys.stdout.write("".join(i + " " for i in ids))
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
        try:
            text = Path(a.path).read_text()
        except OSError as exc:
            print(f"{a.path}: unreadable ({exc})", file=sys.stderr)
            return 1
        if not passwd_sole_root(text):
            print(
                f"{a.path}: not exactly one root login and no other human user",
                file=sys.stderr,
            )
            return 1
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
