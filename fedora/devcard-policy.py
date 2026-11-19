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
import hashlib
import os
import re
import shlex
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
REPART_REPARTD = ("etc/repart.d", "usr/lib/repart.d", "usr/local/lib/repart.d")
# systemd unit search path, highest precedence first.
SYSTEMD_UNIT_DIRS = (
    "etc/systemd/system",
    "run/systemd/system",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
)
DISCARD_FLAG = "--discard=no"
INITRAMFS_REPART_RE = re.compile(
    r"^(?:etc|run|usr/local/lib|usr/lib|lib)/systemd/system/"
    r"(?:systemd-repart(?:@)?\.service|(?:systemd-repart(?:@)?\.service|service)\.d/[^/]+\.conf)$"
    r"|^(?:etc|usr/lib|usr/local/lib)/repart\.d/[^/]+\.conf$"
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
    for path in base.rglob("*"):
        if not (path.is_file() or path.is_symlink()):
            continue
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


def _unit_files(root, unit):
    """Base unit file and drop-ins in systemd precedence order.

    Returns None when UNIT is masked (/dev/null), [] when absent, or
    [base, drop-in, ...] where:
      - base is the highest-precedence unit file (etc > run > usr/local > usr/lib)
      - drop-ins from service.d/*.conf then <unit>.d/*.conf are deduplicated
        by filename (higher-precedence directory wins, /dev/null masks that
        drop-in filename) and sorted lexicographically by filename.
    """
    root = Path(root)
    unit_dirs = _active_unit_dirs(root)
    base = None
    for directory in unit_dirs:
        candidate = root / directory / unit
        if candidate.is_symlink():
            if _masked(candidate):
                return None
            resolved = _resolve_within(root, candidate)
            if resolved is None:
                return [candidate]  # unreadable/escaping -> fail closed
            base = resolved
            break
        if candidate.is_file():
            base = candidate
            break
    if base is None:
        return []
    ordered_dropins = []
    for dropin_name in ("service.d", f"{unit}.d"):
        by_name = {}
        for directory in unit_dirs:
            dpath = root / directory / dropin_name
            if not dpath.is_dir():
                continue
            for conf in sorted(dpath.glob("*.conf")):
                if conf.name in by_name:
                    continue  # higher-precedence directory already won
                if conf.is_symlink():
                    if _masked(conf):
                        by_name[conf.name] = None  # masked drop-in
                    else:
                        by_name[conf.name] = _resolve_within(root, conf) or conf
                elif conf.is_file():
                    by_name[conf.name] = conf
        for name in sorted(by_name):
            if by_name[name] is not None:
                ordered_dropins.append(by_name[name])
    return [base] + ordered_dropins


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
    unit_dirs = _active_unit_dirs(root)
    repart_service_seen = False
    for unit in REPART_UNITS:
        present = any(
            (root / directory / unit).exists() or (root / directory / unit).is_symlink()
            for directory in unit_dirs
        )
        if not present:
            continue
        if unit == "systemd-repart.service":
            repart_service_seen = True
        files = _unit_files(root, unit)
        if files is None:
            continue  # masked: cannot run
        commands = _effective_exec_start(files)
        if commands is None:
            problems.append(f"{unit}: unreadable unit or drop-in")
        elif not _carries_no_discard(commands):
            problems.append(f"{unit} runs {commands!r} without {DISCARD_FLAG}")
    configs = []
    for rel in REPART_REPARTD:
        directory = root / rel
        if directory.is_dir():
            configs += [c for c in directory.glob("*.conf") if c.is_file()]
    if configs and not repart_service_seen:
        problems.append("repart.d configuration without systemd-repart.service")
    return (not problems, problems)


def _parse_lsinitrd_listing(listing):
    """Return list of (kind, relpath, size_or_target) for repart-related entries."""
    entries = []
    for line in listing.splitlines():
        if not line or line[0] not in ("-", "l"):
            continue
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        mode, size_str, rest = parts[0], parts[4], parts[8]
        if mode.startswith("l"):
            if " -> " not in rest:
                continue
            rel, target = rest.split(" -> ", 1)
            rel = rel.lstrip("/")
            if rel.startswith("./"):
                rel = rel[2:]
            if INITRAMFS_REPART_RE.match(rel):
                entries.append(("symlink", rel, target))
        else:
            rel = rest.lstrip("/")
            if rel.startswith("./"):
                rel = rel[2:]
            if INITRAMFS_REPART_RE.match(rel):
                size = int(size_str) if size_str.isdigit() else 0
                entries.append(("file", rel, size))
    return entries


def repart_initramfs_ok(img, lsinitrd_cmd=None, forbid_repart=False):
    """Extract systemd-repart units/drop-ins from IMG and verify effective command.

    Never accepts a drop-in by filename alone; fails closed when lsinitrd fails.
    """
    cmd = list(lsinitrd_cmd) if lsinitrd_cmd else ["lsinitrd"]
    listing = subprocess.run(cmd + [str(img)], capture_output=True, text=True)
    if listing.returncode != 0 or "========" not in listing.stdout:
        msg = listing.stderr.strip() or listing.stdout.strip() or "lsinitrd failed"
        return False, [f"cannot inspect initramfs {img}: {msg}"]
    entries = _parse_lsinitrd_listing(listing.stdout)
    if not entries:
        return True, []
    with tempfile.TemporaryDirectory(prefix="a7a-initramfs-repart-") as td:
        tree = Path(td)
        for kind, rel, meta in entries:
            dest = tree / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if kind == "symlink":
                if dest.exists() or dest.is_symlink():
                    dest.unlink()
                dest.symlink_to(meta)
            else:
                extracted = subprocess.run(
                    cmd + ["-f", rel, str(img)], capture_output=True
                )
                if extracted.returncode != 0 or (meta > 0 and not extracted.stdout):
                    return False, [f"cannot extract {rel} from {img}"]
                dest.write_bytes(extracted.stdout)
        if forbid_repart:
            problems = []
            for unit in REPART_UNITS:
                files = _unit_files(tree, unit)
                if files:
                    problems.append(f"initramfs contains active {unit}")
            for rel_dir in REPART_REPARTD:
                dpath = tree / rel_dir
                if dpath.is_dir() and any(dpath.glob("*.conf")):
                    problems.append(f"initramfs contains repart.d config in {rel_dir}")
            return (not problems, problems)
        return repart_root_ok(tree)


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
        ok, problems = repart_root_ok(a.root)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 0 if ok else 1
    if a.cmd == "repart-initramfs":
        lsinitrd_cmd = None
        if a.chroot:
            lsinitrd_cmd = ["chroot", str(a.chroot), "lsinitrd"]
        elif a.run_build_ns:
            lsinitrd_cmd = [str(a.run_build_ns), "user", "lsinitrd"]
        ok, problems = repart_initramfs_ok(
            a.img, lsinitrd_cmd=lsinitrd_cmd, forbid_repart=a.forbid_repart
        )
        for problem in problems:
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
