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
import errno
import fnmatch
import hashlib
import importlib
import json
import os
import re
import shlex
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
# Exact drop-in directories created by fedora/mkdevcard.sh:427-436 for the two
# checked units. Any other drop-in directory targeting systemd-repart (dashed
# prefix, instance, or unit alias) is refused explicitly.
ALLOWED_REPART_DROPIN_DIRS = frozenset(f"{unit}.d" for unit in REPART_UNITS)
# Stock Fedora systemd ships one type-wide drop-in setting only
# TimeoutStopFailureMode=abort; any other unmasked service.d/*.conf, or any
# service.d/*.conf setting ExecStart/Alias, is refused explicitly.
ALLOWED_VENDOR_SERVICE_D = frozenset(
    (
        "usr/lib/systemd/system/service.d/10-timeout-abort.conf",
        "lib/systemd/system/service.d/10-timeout-abort.conf",
    )
)
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


def _section_assignments(text, target_section):
    """Ordered (key, value) pairs inside [TARGET_SECTION], whitespace tolerated."""
    out = []
    section = None
    for line in _logical_lines(text):
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            continue
        if section != target_section or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        out.append((key.strip(), value.strip()))
    return out


def _service_assignments(text):
    """Ordered (key, value) pairs inside [Service], whitespace tolerated."""
    return _section_assignments(text, "Service")


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
    """Resolve exact UNIT and its exact UNIT.d drop-ins in load-path precedence order.

    Only the exact units and drop-in directory names created by our build
    (`systemd-repart.service`, `systemd-repart@.service`, and their `.d`
    directories) are modeled. Dashed-prefix, instance, alias and unexpected
    type-wide drop-ins are refused by `_check_repart_refusals`.
    """
    root = Path(root)
    unit_dirs = _active_unit_dirs(root)
    base = None
    for directory in unit_dirs:
        candidate = root / directory / unit
        if _masked(candidate):
            return None
        if candidate.is_file() or candidate.is_symlink():
            base = _resolve_within(root, candidate)
            if base is None:
                raise PolicyError(f"cannot resolve unit {candidate}")
            break
    if base is None:
        return []
    by_name = {}
    for directory in unit_dirs:
        _scan_dropin_dir(root / directory / (unit + ".d"), root, by_name)
    return [base] + [by_name[n] for n in sorted(by_name) if by_name[n] is not None]


def _check_repart_refusals(root):
    """Refuse aliases, unexpected drop-in dirs and unexpected service.d drop-ins."""
    root = Path(root)
    unit_dirs = _active_unit_dirs(root)
    problems = []
    alias_names = set()
    for directory in unit_dirs:
        dir_path = root / directory
        for entry in _scandir_if_exists(dir_path):
            name = entry.name
            if name.endswith(".d"):
                stem = name[:-2]
                if stem == "service":
                    continue
                if (
                    re.fullmatch(REPART_NAME, stem)
                    or re.fullmatch(REPART_DASHED_DROPIN, stem)
                ) and name not in ALLOWED_REPART_DROPIN_DIRS:
                    problems.append(
                        f"refused unexpected repart drop-in directory {directory}/{name}"
                    )
                continue
            if name.endswith((".wants", ".requires")) and entry.is_dir():
                for child in _scandir_if_exists(entry):
                    if (
                        re.fullmatch(REPART_NAME, child.name)
                        and child.name not in REPART_UNITS
                    ):
                        problems.append(
                            f"refused unexpected repart unit {directory}/{name}/{child.name}"
                        )
                continue
            if re.fullmatch(REPART_NAME, name) and name not in REPART_UNITS:
                problems.append(f"refused unexpected repart unit {directory}/{name}")
            if entry.is_symlink() and not _masked(entry):
                try:
                    raw_target = os.readlink(entry)
                except OSError as exc:
                    raise PolicyError(f"cannot read symlink {entry}: {exc}") from exc
                resolved = _resolve_within(root, entry)
                raw_base = Path(raw_target).name
                res_base = resolved.name if resolved is not None else ""
                if name in REPART_UNITS:
                    problems.append(
                        f"refused alias symlink from checked unit {directory}/{name} -> {raw_target}"
                    )
                    alias_names.add(name)
                elif re.fullmatch(REPART_NAME, raw_base) or re.fullmatch(
                    REPART_NAME, res_base
                ):
                    problems.append(
                        f"refused alias symlink to checked unit {directory}/{name} -> {raw_target}"
                    )
                    alias_names.add(name)
        for conf in _scandir_if_exists(dir_path / "service.d"):
            if not conf.name.endswith(".conf") or _masked(conf):
                continue
            rel = f"{directory}/service.d/{conf.name}"
            resolved = _resolve_within(root, conf)
            if resolved is None or not resolved.is_file():
                problems.append(f"refused unreadable type-wide drop-in {rel}")
                continue
            try:
                text = resolved.read_text()
            except OSError:
                problems.append(f"refused unreadable type-wide drop-in {rel}")
                continue
            touches = any(
                k == "ExecStart" for k, _ in _section_assignments(text, "Service")
            ) or any(k == "Alias" for k, _ in _section_assignments(text, "Install"))
            if touches:
                problems.append(
                    f"refused type-wide drop-in {rel}: sets ExecStart or Alias"
                )
            elif rel not in ALLOWED_VENDOR_SERVICE_D:
                problems.append(f"refused unexpected type-wide drop-in {rel}")
    for alias in sorted(alias_names):
        for directory in unit_dirs:
            alias_d = root / directory / f"{alias}.d"
            if alias_d.is_dir():
                problems.append(
                    f"refused alias drop-in directory {directory}/{alias}.d"
                )
    return problems


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
    """Every effective systemd-repart invocation carries --discard=no.

    Pinned to our build's exact units (`systemd-repart.service`,
    `systemd-repart@.service`) and drop-in directory names; refuses aliases,
    unexpected repart/dashed drop-in directories and unexpected `service.d`
    drop-ins.
    """
    root = Path(root)
    problems = _check_repart_refusals(root)
    unit_dirs = _active_unit_dirs(root)
    repart_service_seen = False
    for unit in REPART_UNITS:
        if any(
            "alias symlink from checked unit" in p and f"/{unit} -> " in p
            for p in problems
        ):
            continue
        files = _unit_files(root, unit)
        if files == []:
            continue
        if unit == "systemd-repart.service":
            repart_service_seen = True
        if files is None:
            continue  # masked: cannot run
        for path in files:
            if not path.is_file():
                continue
            try:
                text = path.read_text()
            except OSError:
                continue
            for key, value in _section_assignments(text, "Install"):
                if key != "Alias":
                    continue
                rel = path.relative_to(root.resolve()).as_posix()
                problems.append(f"refused [Install] Alias={value!r} in {rel}")
                for alias in value.split():
                    for directory in unit_dirs:
                        if (root / directory / f"{alias}.d").is_dir():
                            problems.append(
                                f"refused alias drop-in directory {directory}/{alias}.d"
                            )
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
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _norm_archive_path(name):
    rel = name.lstrip("/")
    while rel.startswith("./"):
        rel = rel[2:]
    return rel if rel else "."


def _decompress_zstd_members(data, start_pos):
    """Decompress one or more zstd frames starting at START_POS, member by member.

    Our build's dracut configuration uses Fedora's default compressor (zstd:
    dracut-cubie-a7a.conf and /usr/lib/dracut/dracut.conf.d/01-dist.conf leave
    compress unset, /usr/bin/dracut selects $DRACUT_COMPRESS_ZSTD first, and
    the dracut RPM requires zstd). Any other compressor, truncated frame,
    skippable frame or trailing bytes after the last frame is refused.
    """
    try:
        zstd = importlib.import_module("compression.zstd")
    except ImportError as exc:
        raise PolicyError(
            f"compression.zstd is unavailable to verify zstd initramfs: {exc}"
        ) from exc
    view = memoryview(data)
    pos = start_pos
    length = len(data)
    if pos >= length:
        raise PolicyError("missing zstd initramfs payload")
    chunks = []
    members = 0
    while pos < length:
        if bytes(view[pos : pos + 4]) != ZSTD_MAGIC:
            raise PolicyError(
                f"refused non-zstd or trailing initramfs bytes at offset {pos}: "
                f"{bytes(view[pos : pos + 8])!r}"
            )
        dec = zstd.ZstdDecompressor()
        try:
            out = dec.decompress(view[pos:])
        except Exception as exc:
            raise PolicyError(
                f"truncated or corrupt zstd initramfs frame {members + 1} at offset {pos}: {exc}"
            ) from exc
        if not dec.eof:
            raise PolicyError(
                f"truncated zstd initramfs frame {members + 1} at offset {pos}: missing end-of-frame"
            )
        consumed = (length - pos) - len(dec.unused_data)
        if consumed <= 0:
            raise PolicyError(
                f"zstd initramfs frame {members + 1} at offset {pos} consumed zero bytes"
            )
        chunks.append(out)
        pos += consumed
        members += 1
    if members == 0 or pos != length:
        raise PolicyError("incomplete zstd initramfs consumption")
    return b"".join(chunks)


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
        nul_idx = raw_name.find(b"\x00")
        if nul_idx < 0 or not raw_name.endswith(b"\x00"):
            raise PolicyError("unterminated cpio entry name")
        if any(byte != 0 for byte in raw_name[nul_idx:]):
            raise PolicyError("non-NUL byte after NUL terminator in cpio entry name")
        if nul_idx == 0:
            raise PolicyError("empty cpio entry name")
        name = os.fsdecode(raw_name[:nul_idx])
        pos += namesize + (-(110 + namesize)) % 4
        if pos + filesize > length:
            raise PolicyError(f"truncated cpio payload for {name!r}")
        payload = data[pos : pos + filesize]
        pos += filesize + (-filesize) % 4
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
    """Independently parse our build's initramfs (optional early cpio + zstd cpio).

    Leading uncompressed early-CPIO segments (if present) must each end cleanly
    at TRAILER!!! with only NUL alignment bytes before the zstd payload. The
    main payload must consist solely of one or more complete zstd frames
    consuming the input to exact EOF, and its decompressed cpio stream(s) must
    each terminate cleanly at TRAILER!!!.
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
            raise PolicyError(
                f"refused uncompressed-only initramfs {path} (expected zstd main payload)"
            )
        if data[pos : pos + 6] in CPIO_NEWC_MAGICS:
            part, pos = _parse_cpio_one(data, pos)
            entries.extend(part)
            continue
        break
    decompressed = _decompress_zstd_members(data, pos)
    entries.extend(parse_cpio_stream(decompressed))
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


def _select_initramfs_repart_entries(all_rows):
    """Select repart units, drop-ins, service.d, repart.d and alias symlinks/drop-ins."""
    unit_dir_set = set(SYSTEMD_UNIT_DIRS)
    symlink_targets = {}
    for kind, rel, meta in all_rows:
        if kind != "symlink" or meta == "/dev/null":
            continue
        parent, _, name = rel.rpartition("/")
        if parent in unit_dir_set and name:
            symlink_targets.setdefault(name, set()).add(Path(meta).name)
    alias_names = set()
    changed = True
    while changed:
        changed = False
        for name, targets in symlink_targets.items():
            if name in alias_names:
                continue
            if re.fullmatch(REPART_NAME, name) or any(
                re.fullmatch(REPART_NAME, t) or t in alias_names for t in targets
            ):
                alias_names.add(name)
                changed = True
    alias_dropin_dirs = {f"{a}.d" for a in alias_names}
    selected = []
    for kind, rel, meta in all_rows:
        if kind in ("file", "symlink") and INITRAMFS_REPART_RE.match(rel):
            selected.append((kind, rel, meta))
            continue
        parent, _, name = rel.rpartition("/")
        if kind == "symlink" and parent in unit_dir_set and name in alias_names:
            selected.append((kind, rel, meta))
            continue
        grand, _, dname = parent.rpartition("/")
        if (
            kind in ("file", "symlink")
            and grand in unit_dir_set
            and dname in alias_dropin_dirs
            and name.endswith(".conf")
        ):
            selected.append((kind, rel, meta))
    return selected


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
    if not all_rows:
        raise PolicyError("incomplete lsinitrd listing: no recognized file rows")
    return all_rows, _select_initramfs_repart_entries(all_rows)


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
            problems = _check_repart_refusals(tree)
            for unit in REPART_UNITS:
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


REQUIRED_BOARD_PACKAGES = ("cubie-a7a-dtb", "cubie-a7a-board-support")
OPTIONAL_NOARCH_PACKAGES = (
    "cubie-a7a-npu",
    "cubie-a7a-rk1828",
    "cubie-a7a-display",
    "cubie-a7a-vdec",
    "cubie-a7a-hat",
    "cubie-a7a-aic8800-usb",
)
OPTIONAL_AARCH64_PACKAGES = ("cubie-a7a-fwlog",)
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def write_rpm_manifest(rpms_dir, out_manifest, rpm_paths, kind="noarch"):
    """Write an atomic checked-RPM manifest with exact relpaths and sha256s."""
    if kind not in ("noarch", "aarch64"):
        raise PolicyError(f"invalid rpm manifest kind: {kind!r}")
    allowed = (
        set(REQUIRED_BOARD_PACKAGES) | set(OPTIONAL_NOARCH_PACKAGES)
        if kind == "noarch"
        else set(OPTIONAL_AARCH64_PACKAGES)
    )
    base = Path(rpms_dir).resolve()
    records = []
    seen = set()
    for raw in sorted(rpm_paths):
        path = Path(raw).resolve()
        if not path.is_file():
            raise PolicyError(f"missing built RPM: {path}")
        try:
            rel = path.relative_to(base).as_posix()
        except ValueError as exc:
            raise PolicyError(f"RPM {path} is outside {base}") from exc
        res = subprocess.run(
            ["rpm", "-qp", "--qf", "%{NAME}", str(path)],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0 or not res.stdout.strip():
            raise PolicyError(f"cannot read RPM name from {path}: {res.stderr.strip()}")
        pkg = res.stdout.strip()
        if pkg not in allowed:
            raise PolicyError(f"unexpected {kind} board RPM package: {pkg}")
        if pkg in seen:
            raise PolicyError(f"duplicate {kind} board RPM package in run: {pkg}")
        seen.add(pkg)
        records.append(
            {"package": pkg, "relpath": rel, "sha256": _file_digest(path, "sha256")}
        )
    if not records:
        raise PolicyError(f"no {kind} RPMs provided for manifest")
    payload = {
        "version": 1,
        "kind": kind,
        "count": len(records),
        "rpms": records,
    }
    out_path = Path(out_manifest)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=".checked-rpms.", suffix=".tmp", dir=out_path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp_name, out_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return payload


def _load_rpm_manifest(rpms_dir, manifest_path, expected_kind, allowed_packages):
    base = Path(rpms_dir).resolve()
    mpath = Path(manifest_path)
    try:
        raw = mpath.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read checked RPM manifest {mpath}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"corrupt or truncated RPM manifest {mpath}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"invalid RPM manifest {mpath}: expected object")
    if data.get("version") != 1 or data.get("kind") != expected_kind:
        raise PolicyError(
            f"invalid RPM manifest {mpath}: version={data.get('version')!r}, "
            f"kind={data.get('kind')!r}"
        )
    rpms = data.get("rpms")
    count = data.get("count")
    if (
        not isinstance(rpms, list)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count != len(rpms)
        or count == 0
    ):
        raise PolicyError(
            f"incomplete RPM manifest {mpath}: count={count!r}, entries={len(rpms) if isinstance(rpms, list) else 'invalid'}"
        )
    selected = {}
    for idx, entry in enumerate(rpms):
        if not isinstance(entry, dict):
            raise PolicyError(f"{mpath}: entry {idx} is not an object")
        pkg = entry.get("package")
        rel = entry.get("relpath")
        expected_sha = entry.get("sha256")
        if (
            not isinstance(pkg, str)
            or pkg not in allowed_packages
            or not isinstance(rel, str)
            or not rel
            or not isinstance(expected_sha, str)
            or not SHA256_HEX_RE.fullmatch(expected_sha)
        ):
            raise PolicyError(f"{mpath}: invalid entry {idx}: {entry!r}")
        if pkg in selected:
            raise PolicyError(f"{mpath}: duplicate package {pkg}")
        rel_path = Path(rel)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            raise PolicyError(f"{mpath}: unsafe relpath {rel!r}")
        target = (base / rel_path).resolve()
        try:
            target.relative_to(base)
        except ValueError as exc:
            raise PolicyError(f"{mpath}: path escapes {base}: {rel!r}") from exc
        if not target.is_file() or target.is_symlink():
            raise PolicyError(f"{mpath}: missing or non-regular RPM {rel}")
        actual_sha = _file_digest(target, "sha256")
        if actual_sha != expected_sha:
            raise PolicyError(
                f"{mpath}: sha256 mismatch for {rel} "
                f"(actual {actual_sha}, manifest {expected_sha})"
            )
        selected[pkg] = target
    return selected


def select_checked_rpms(rpms_dir):
    """Select board RPMs strictly from the checked manifest(s) under RPMS_DIR.

    Never globs the directory; verifies JSON framing, entry count, safe paths,
    and every RPM's SHA-256 digest.
    """
    base = Path(rpms_dir)
    noarch_manifest = base / "checked-rpms.json"
    selected = _load_rpm_manifest(
        base,
        noarch_manifest,
        "noarch",
        set(REQUIRED_BOARD_PACKAGES) | set(OPTIONAL_NOARCH_PACKAGES),
    )
    for req in REQUIRED_BOARD_PACKAGES:
        if req not in selected:
            raise PolicyError(f"{noarch_manifest}: missing required package {req}")
    aarch64_manifest = base / "checked-aarch64-rpms.json"
    if aarch64_manifest.exists() or aarch64_manifest.is_symlink():
        arch_selected = _load_rpm_manifest(
            base, aarch64_manifest, "aarch64", set(OPTIONAL_AARCH64_PACKAGES)
        )
        selected.update(arch_selected)
    order = (
        REQUIRED_BOARD_PACKAGES + OPTIONAL_AARCH64_PACKAGES + OPTIONAL_NOARCH_PACKAGES
    )
    return [(pkg, selected[pkg]) for pkg in order if pkg in selected]


def verify_rpmdb_list(root, packages_file):
    """Cross-check a captured `rpm --root ROOT -qa` listing against librpm.

    Fails closed if `rpm -qa` silently truncated, dropped, or altered any row.
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
        expected = sorted(
            hdr.format(
                "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH} %{RSAHEADER:pgpsig}"
            )
            for hdr in ts.dbMatch()
        )
    except Exception as exc:
        raise PolicyError(f"cannot read the rpm database under {root}: {exc}") from exc
    if not expected:
        raise PolicyError(f"no installed packages found under {root}")
    try:
        actual = sorted(Path(packages_file).read_text().splitlines())
    except OSError as exc:
        raise PolicyError(f"cannot read package list {packages_file}: {exc}") from exc
    if actual != expected:
        raise PolicyError(
            f"rpm package listing mismatch: file has {len(actual)} rows, "
            f"rpmdb has {len(expected)}"
        )
    return len(expected)


def check_absence(
    root,
    mode,
    rel_paths,
    pattern=None,
    ignore_case=False,
    allow_basenames=(),
    recursive=False,
):
    """Fail-closed filesystem absence check using os.scandir / os.walk(onerror=...).

    Raises PolicyError on unreadable directories or files rather than treating
    I/O errors as absence. Returns (ok, problems).
    """
    root = Path(root)
    problems = []
    allowed = set(allow_basenames)
    flags = re.MULTILINE | (re.IGNORECASE if ignore_case else 0)
    for rel in rel_paths:
        target = root / rel.lstrip("/")
        if mode == "no-entries":
            for entry in _scandir_if_exists(target):
                problems.append(
                    f"unexpected entry: {entry.relative_to(root).as_posix()}"
                )
        elif mode == "no-regular-files":
            if target.exists() and not target.is_symlink() and target.is_dir():
                for entry in _walk_entries(target):
                    if not entry.is_symlink() and entry.is_file():
                        problems.append(
                            f"unexpected regular file: {entry.relative_to(root).as_posix()}"
                        )
        elif mode == "no-glob":
            if not pattern:
                raise PolicyError("no-glob requires --pattern")
            if recursive:
                if target.exists() and not target.is_symlink() and target.is_dir():
                    entries = list(_walk_entries(target))
                else:
                    entries = []
            else:
                entries = _scandir_if_exists(target)
            for entry in entries:
                if fnmatch.fnmatchcase(entry.name, pattern):
                    problems.append(
                        f"unexpected match for {pattern}: "
                        f"{entry.relative_to(root).as_posix()}"
                    )
        elif mode == "no-text":
            if not pattern:
                raise PolicyError("no-text requires --pattern")
            if target.exists() and not target.is_symlink() and target.is_dir():
                for entry in _walk_entries(target):
                    if (
                        entry.name in allowed
                        or entry.is_symlink()
                        or not entry.is_file()
                    ):
                        continue
                    try:
                        text = entry.read_text(encoding="utf-8", errors="replace")
                    except OSError as exc:
                        raise PolicyError(f"cannot read {entry}: {exc}") from exc
                    if re.search(pattern, text, flags):
                        problems.append(
                            f"forbidden match {pattern!r} in "
                            f"{entry.relative_to(root).as_posix()}"
                        )
            elif target.is_file():
                try:
                    text = target.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    raise PolicyError(f"cannot read {target}: {exc}") from exc
                if re.search(pattern, text, flags):
                    problems.append(
                        f"forbidden match {pattern!r} in "
                        f"{target.relative_to(root).as_posix()}"
                    )
        else:
            raise PolicyError(f"unknown absence mode: {mode!r}")
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
    p = sub.add_parser("write-rpm-manifest")
    p.add_argument("rpms_dir", type=Path)
    p.add_argument("manifest", type=Path)
    p.add_argument("--kind", choices=("noarch", "aarch64"), default="noarch")
    p.add_argument("rpms", nargs="+", type=Path)
    p = sub.add_parser("select-rpms")
    p.add_argument("rpms_dir", type=Path)
    p = sub.add_parser("verify-rpmdb-list")
    p.add_argument("root", type=Path)
    p.add_argument("packages_file", type=Path)
    p = sub.add_parser("absence-check")
    p.add_argument("root", type=Path)
    p.add_argument(
        "--mode",
        choices=("no-entries", "no-regular-files", "no-glob", "no-text"),
        required=True,
    )
    p.add_argument("--pattern")
    p.add_argument("--ignore-case", action="store_true")
    p.add_argument("--allow-basename", action="append", default=[])
    p.add_argument("--recursive", action="store_true")
    p.add_argument("paths", nargs="+")
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
    if a.cmd == "write-rpm-manifest":
        try:
            write_rpm_manifest(a.rpms_dir, a.manifest, a.rpms, kind=a.kind)
        except PolicyError as exc:
            print(f"write-rpm-manifest: {exc}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "select-rpms":
        try:
            for pkg, rpm_path in select_checked_rpms(a.rpms_dir):
                print(f"{pkg}\t{rpm_path}")
        except PolicyError as exc:
            print(f"select-rpms: {exc}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "verify-rpmdb-list":
        try:
            verify_rpmdb_list(a.root, a.packages_file)
        except PolicyError as exc:
            print(f"verify-rpmdb-list: {exc}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "absence-check":
        try:
            ok, problems = check_absence(
                a.root,
                a.mode,
                a.paths,
                pattern=a.pattern,
                ignore_case=a.ignore_case,
                allow_basenames=a.allow_basename,
                recursive=a.recursive,
            )
        except PolicyError as exc:
            print(f"absence-check: {exc}", file=sys.stderr)
            return 1
        for problem in problems:
            print(problem, file=sys.stderr)
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
