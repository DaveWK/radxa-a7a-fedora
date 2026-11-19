#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Image-policy checks shared by fedora/mkdevcard.sh and fedora/verify-devcard.sh.

Python 3, run with -I by the shell scripts; the host tests import it.  Every
command prints a stable, shell-friendly result and exits nonzero on a policy
violation, so a caller can use it directly as a check.

The checks that run at *build* time (mkdevcard.sh) work on staged directory
trees and real tool output, so a format is never re-derived from packed bytes:

  aic-overlay DIR     AIC8800 firmware paths in an OVERLAY directory that
                      must be refused before the copy.
  aic-provenance ROOT [--ownership FILE] [--report FILE]
                      every file under usr/lib/firmware/aic* must be owned by
                      a signed Fedora package matching its recorded digest.
  unit-config ROOT UNIT --fixture FILE
                      ``systemd-analyze --root=ROOT cat-config systemd/system/UNIT``
                      compared byte for byte (host-root headers normalized)
                      with the pinned expected text in FILE (a repo fixture).
                      That is systemd's own resolution: symlinks, usr-merge,
                      drop-ins, conditions and aliases are all systemd's
                      decisions.  Fails closed when systemd-analyze is absent.
  unit-enabled ROOT UNIT --state enabled|masked
                      ``systemctl --root=ROOT is-enabled UNIT``.  ``enabled``
                      accepts enabled or static (our build's sysinit link);
                      refutes masked, disabled and not-found.  ``masked``
                      requires exactly "masked".
  initramfs-unpack IMG DEST
                      unpack IMG with dracut's own ``lsinitrd --unpack`` into a
                      fresh DEST (the system's initramfs reader).
  esp-staged ROOT --esp-dir DIR --dtb-rpm RPM [--dtb-rpm-sha256 DIGEST]
                      the one ESP admission rule at build, on the staged tree
                      before mtools: the stamps are validated first; the DTB
                      and marker bytes, the VERSION file and the esp-override
                      presence are bound to the built cubie-a7a-dtb RPM's own
                      file list (``rpm -qp --dump``); the entry set with types
                      is exactly our build's.  An OVERLAY may not write
                      boot/efi (see overlay-esp).

  enabled-repos DIR [DIR...]
                      enabled dnf repository ids, sorted.
  dumpe2fs IMG        "X GiB, Y GiB free" from dumpe2fs -h.
  loader-entry FILE FIELD
                      linux, initrd or options of a BLS entry file.
  shadow              stdin is /etc/shadow: "salt<TAB>root-hash<TAB>others".
  passwd-sole-root FILE
                      exactly one uid 0 named root and no other human user.
  new-rpm-run BUILDROOT
                      allocate a fresh RPM build directory and print its path.
  seal-rpm-run RUN    snapshot and freeze built RPMs, then make the local repo.
  load-rpm-run RUN    check local RPM copies, output the retained records and
                      tab-separated package, digest and path rows.
  check-installed-rpms ROOT RECORDS
                      compare the staged root rpmdb with the retained snapshot.
  write-rpm-manifest, stage-srpm, select-rpms
                      private provenance checks for the optional aarch64 stage.
  verify-rpmdb-list, absence-check
                      installed package and filesystem absence checks.

The exact build manifest and its verify live in fedora/devcard-manifest.py.
"""

import argparse
import base64
import errno
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
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
# The pinned systemd units mkdevcard's no-discard drop-ins and the unit-config
# build-time check both cover (the repart service and its Varlink instance).
REPART_UNITS = ("systemd-repart.service", "systemd-repart@.service")
REPART_MAIN = "systemd-repart.service"
# rpm's PGPHASHALGO values (rpm/rpmpgp.h).
RPM_ALGO = {1: "md5", 2: "sha1", 3: "sha224", 8: "sha256", 9: "sha384", 10: "sha512"}
DIGEST_ALGO_DEFAULT = 8
RPMDB_CANDIDATES = (
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "var/lib/rpm/rpmdb.sqlite",
    "var/lib/rpm/Packages",
)
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


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
      - ``rpm -qlv --dump`` / ``rpm -q --dump`` lines (11 whitespace fields).
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
    """Build an rpm.keyring holding only trusted Fedora release signing keys."""
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
    """Index path -> list[(pkg, digest, algo, linkto, is_fedora)] from ROOT's rpmdb."""
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
    """Every provenance problem in ROOT's AIC8800 firmware tree."""
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
    """Ids of the enabled repositories in dnf's .repo files, sorted."""
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
    """One field of a BLS entry: linux, initrd or options."""
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
    """(root salt, root hash, non-root users with a password) of /etc/shadow."""
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
    """Exactly one uid 0, named root, and no other human (1000-59999) user."""
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


# --- build-time systemd checks (systemd's own resolution) ------------------


def _require_tool(name):
    if shutil.which(name) is None:
        raise PolicyError(f"{name} is required for this check (no fallback)")


def _normalize_cat_config(text, root):
    """Rewrite systemd-analyze cat-config's ``# <root>/...`` headers to ``# /...``.

    Only the ``# `` header lines carry the host root prefix; every other line
    (including the unit's own ``#`` comments) is left byte for byte.
    """
    prefix = f"# {root}/"
    lines = []
    for line in text.split("\n"):
        if line.startswith(prefix):
            line = "# /" + line[len(prefix) :]
        lines.append(line)
    return "\n".join(lines)


def _first_diff(expected, actual):
    exp_lines = expected.split("\n")
    got_lines = actual.split("\n")
    for i in range(max(len(exp_lines), len(got_lines))):
        e = exp_lines[i] if i < len(exp_lines) else "<absent>"
        g = got_lines[i] if i < len(got_lines) else "<absent>"
        if e != g:
            return f"line {i + 1}: expected {e!r}, got {g!r}"
    return "unknown difference"


def unit_config(root, unit, fixture):
    """systemd-analyze's own resolution of UNIT in ROOT vs the pinned fixture text."""
    _require_tool("systemd-analyze")
    root = Path(root).resolve()
    fixture = Path(fixture)
    try:
        expected = fixture.read_text()
    except OSError as exc:
        raise PolicyError(f"cannot read pinned-unit fixture {fixture}: {exc}") from exc
    rel = f"systemd/system/{unit}"
    r = subprocess.run(
        ["systemd-analyze", f"--root={root}", "cat-config", rel],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise PolicyError(
            f"systemd-analyze cat-config {unit}: {r.stderr.strip() or r.stdout.strip()}"
        )
    got = _normalize_cat_config(r.stdout, root)
    if got != expected:
        return (
            False,
            f"{unit} differs from the pinned text: {_first_diff(expected, got)}",
        )
    return True, ""


def unit_enabled(root, unit, state):
    """systemctl --root is-enabled UNIT, pinned to an expected STATE."""
    _require_tool("systemctl")
    r = subprocess.run(
        ["systemctl", f"--root={root}", "is-enabled", unit],
        capture_output=True,
        text=True,
    )
    got = (r.stdout.strip() or r.stderr.strip()).strip()
    enabled_states = (
        "enabled",
        "enabled-runtime",
        "static",
        "alias",
        "linked",
        "linked-runtime",
        "indirect",
    )
    if state == "enabled":
        ok = got in enabled_states
    elif state == "masked":
        ok = got == "masked"
    else:
        raise PolicyError(f"invalid unit-enabled state {state!r}")
    if ok:
        return True, f"{unit} is {got}"
    return (
        False,
        f"{unit} is {got!r}, expected {'/'.join(enabled_states) if state == 'enabled' else 'masked'}",
    )


def initramfs_unpack(img, dest, lsinitrd_cmd=None):
    """Unpack IMG with dracut's own lsinitrd --unpack into a fresh DEST."""
    cmd = list(lsinitrd_cmd) if lsinitrd_cmd else ["lsinitrd"]
    _require_tool(cmd[0])
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    r = subprocess.run(
        cmd + ["--unpack", str(img)], cwd=str(dest), capture_output=True, text=True
    )
    if r.returncode != 0:
        raise PolicyError(
            f"{cmd[0]} --unpack {img}: {r.stderr.strip() or f'exit {r.returncode}'}"
        )
    return dest


# --- ESP: the one build-time admission, bound to the built RPM's file list ---

ESP_BASE_ENTRIES = frozenset(
    (
        "efi",
        "efi/boot",
        "efi/fedora",
        "efi/boot/bootaa64.efi",
        "efi/boot/fbaa64.efi",
        "efi/fedora/bootaa64.csv",
        "efi/fedora/grub.cfg",
        "efi/fedora/grubaa64.efi",
        "efi/fedora/mmmaa64.efi",
        "efi/fedora/shim.efi",
        "efi/fedora/shimaa64.efi",
    )
)
ESP_DTB_ENTRIES = frozenset(
    (
        "dtb",
        "dtb/allwinner",
        "dtb/allwinner/sun60i-a733-cubie-a7a.dtb",
        "dtb/allwinner/sun60i-a733-cubie-a7a.dtb.cubie-a7a-dtb",
    )
)
ESP_DIRS = frozenset(("efi", "efi/boot", "efi/fedora", "dtb", "dtb/allwinner"))
ESP_DTB = "dtb/allwinner/sun60i-a733-cubie-a7a.dtb"
ESP_DTB_MARK = ESP_DTB + ".cubie-a7a-dtb"
PKG_DTB = "usr/lib/cubie-a7a/dtb/allwinner/sun60i-a733-cubie-a7a.dtb"
PKG_DTB_PACKAGE = "cubie-a7a-dtb"
PKG_DTB_VERSION = "usr/lib/cubie-a7a/dtb/VERSION"
PKG_ESP_OVERRIDE = "usr/lib/cubie-a7a/dtb/esp-override"
FW_DTB_STAMP = "var/lib/cubie-a7a/firmware-dtb-version"
DTB_STAMP_RE = re.compile(rb"[0-9]{1,9}\n")


def _dtb_stamp(root, rel):
    path = Path(root) / rel
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise PolicyError(f"malformed DTB stamp {rel}: {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise PolicyError(f"malformed DTB stamp {rel}: not a regular file")
    data = path.read_bytes()
    if not DTB_STAMP_RE.fullmatch(data):
        raise PolicyError(f"malformed DTB stamp {rel}: {data[:32]!r}")
    return int(data)


def _rpm_dump(rpm_path):
    """{rel (no leading /): (digest_hex, regular)} from ``rpm -qp --dump``.

    The RPM's own file list: path size mtime digest mode owner group iscfg isdoc
    rdev symlink. Keep non-regular entries so callers can distinguish ownership
    of the wrong entry type from absence.
    """
    r = subprocess.run(
        ["rpm", "-qp", "--dump", str(rpm_path)], capture_output=True, text=True
    )
    if r.returncode != 0:
        raise PolicyError(
            f"rpm -qp --dump {rpm_path}: {r.stderr.strip() or f'exit {r.returncode}'}"
        )
    index = {}
    for number, line in enumerate(r.stdout.splitlines(), 1):
        parts = line.split()
        if len(parts) < 11:
            raise PolicyError(f"{rpm_path}:{number}: malformed rpm --dump row {line!r}")
        rel = parts[0].lstrip("/")
        mode = parts[4]
        regular = stat.S_ISREG(int(mode, 8)) and parts[10] == "X"
        index[rel] = (parts[3].lower(), regular)
    return index


def _rpm_payload_sha256(records, rel, rpm_path):
    """The sha256 the RPM records for REL, or a PolicyError."""
    entry = records.get(rel)
    if entry is None:
        raise PolicyError(f"{rpm_path} does not own {rel}")
    digest, regular = entry
    if not regular or not SHA256_HEX_RE.fullmatch(digest):
        raise PolicyError(f"{rpm_path} records no sha256 for {rel}")
    return digest


def esp_staged(root, esp_dir, dtb_rpm, *, dtb_rpm_sha256=None):
    """The one ESP admission rule, at build, on the staged tree before mtools.

    The stamps are validated before staged admission, which runs after the
    RPM installer. A malformed stamp is never read as "no DTB". The DTB bytes,
    VERSION file and esp-override are bound to the built RPM's own file list; the
    entry set with types is exactly our build's.  Returns (ok, problems).
    """
    root = Path(root)
    problems = []
    fw = _dtb_stamp(root, FW_DTB_STAMP)
    pkg = _dtb_stamp(root, PKG_DTB_VERSION)
    if dtb_rpm_sha256 is not None:
        _check_rpm_digest(dtb_rpm, dtb_rpm_sha256)
    # The passed RPM must be the DTB package.
    q = subprocess.run(
        ["rpm", "-qp", "--qf", "%{NAME}", str(dtb_rpm)], capture_output=True, text=True
    )
    if q.returncode != 0 or q.stdout.strip() != PKG_DTB_PACKAGE:
        return False, [f"{dtb_rpm} is not a {PKG_DTB_PACKAGE} RPM"]
    records = _rpm_dump(dtb_rpm)
    pkg_dtb_digest = _rpm_payload_sha256(records, PKG_DTB, dtb_rpm)

    def check_root_payload(rel, expected):
        path = root / rel
        if path.is_symlink() or not path.is_file():
            problems.append(f"{rel} missing or not a regular file in the root")
        elif _file_digest(path, "sha256") != expected:
            problems.append(f"{rel} differs from the {PKG_DTB_PACKAGE} RPM payload")

    check_root_payload(
        PKG_DTB_VERSION, _rpm_payload_sha256(records, PKG_DTB_VERSION, dtb_rpm)
    )
    check_root_payload(PKG_DTB, pkg_dtb_digest)
    has_override = PKG_ESP_OVERRIDE in records
    if has_override:
        check_root_payload(
            PKG_ESP_OVERRIDE, _rpm_payload_sha256(records, PKG_ESP_OVERRIDE, dtb_rpm)
        )
    elif os.path.lexists(root / PKG_ESP_OVERRIDE):
        problems.append(
            f"{PKG_ESP_OVERRIDE} exists but is not owned by {PKG_DTB_PACKAGE}"
        )
    expect_dtb = has_override or pkg > fw

    entries = {}
    base = Path(esp_dir)
    if base.is_symlink() or not base.is_dir():
        return False, problems + [f"missing or non-directory ESP: {base}"]

    def on_error(exc):
        raise PolicyError(f"cannot traverse {exc.filename or base}: {exc}") from exc

    for dirpath, dirnames, filenames in os.walk(base, onerror=on_error):
        cur = Path(dirpath)
        for name in sorted(dirnames) + sorted(filenames):
            path = cur / name
            rel = path.relative_to(base).as_posix()
            key = rel.lower()
            mode = os.lstat(path).st_mode
            if stat.S_ISDIR(mode):
                kind = "dir"
            elif stat.S_ISREG(mode):
                kind = "file"
            else:
                problems.append(f"ESP entry {rel} is neither a file nor a directory")
                continue
            if key in entries:
                problems.append(f"ESP entries collide on FAT: {rel}")
                continue
            entries[key] = kind

    expected = {
        rel: ("dir" if rel in ESP_DIRS else "file")
        for rel in (
            ESP_BASE_ENTRIES | ESP_DTB_ENTRIES if expect_dtb else ESP_BASE_ENTRIES
        )
    }
    missing = sorted(set(expected) - set(entries))
    extra = sorted(set(entries) - set(expected))
    wrong = sorted(
        f"{rel} is a {entries[rel]}, expected a {kind}"
        for rel, kind in expected.items()
        if rel in entries and entries[rel] != kind
    )
    if missing:
        problems.append(f"ESP missing={missing}")
    if extra:
        problems.append(f"ESP extra={extra}")
    if wrong:
        problems.append(f"ESP wrong type={wrong}")
    if expect_dtb and not missing and not extra and not wrong:
        dtb_bytes = (base / ESP_DTB).read_bytes()
        got = hashlib.sha256(dtb_bytes).hexdigest()
        if got != pkg_dtb_digest:
            problems.append(
                f"ESP {ESP_DTB} sha256 {got} is not the packaged DTB's {pkg_dtb_digest}"
            )
        mark = (base / ESP_DTB_MARK).read_bytes()
        if mark != (pkg_dtb_digest + "\n").encode():
            problems.append(f"ESP {ESP_DTB_MARK} does not hold the DTB's digest")
    return (not problems, problems)


def overlay_esp_entries(overlay):
    """OVERLAY entries that would land on the ESP (our ESP is packages only)."""
    base = Path(overlay) / "boot"
    if not (base.exists() or base.is_symlink()):
        return []
    if base.is_symlink() or not base.is_dir():
        return [str(base)]
    efi = base / "efi"
    if not (efi.exists() or efi.is_symlink()):
        return []
    if efi.is_symlink() or not efi.is_dir():
        return [str(efi)]
    return sorted(str(p) for p in efi.rglob("*"))


# --- checked RPM manifests (NEVRA, %{ARCH}, sha256) --------------------------

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
RUN_ID_RE = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
RPM_MANIFEST_VERSION = 3
FWLOG_SRPM_PACKAGE = "cubie-a7a-fwlog"
RPM_ITEM_RE = re.compile(r"(?:noarch|aarch64)/[A-Za-z0-9_.+~-]+\.rpm")
RPM_SNAPSHOT_FIELDS = ("package", "nevra", "evr", "arch", "payload_sha256")
RPM_SNAPSHOT_QUERY = (
    r"%{NAME}\t%{NEVRA}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{PAYLOADSHA256}\n"
)


def rpm_run_id():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(4)


def new_rpm_run(buildroot):
    parent = Path(buildroot).resolve() / "runs"
    parent.mkdir(parents=True, exist_ok=True)
    run = parent / rpm_run_id()
    run.mkdir(mode=0o700)  # No reuse, even on a collision or a failed build.
    for name in ("srpms", "out"):
        (run / name).mkdir()
    return run


def _rpm_run_path(run):
    run = Path(run).resolve(strict=True)
    if (
        run.parent.name != "runs"
        or not RUN_ID_RE.fullmatch(run.name)
        or not run.is_dir()
    ):
        raise PolicyError(f"not a run directory from build-rpms.sh: {run}")
    return run


def _readonly_tree(tree):
    for root, dirs, files in os.walk(tree, topdown=False):
        for name in dirs + files:
            path = Path(root) / name
            path.chmod(path.stat().st_mode & ~0o222)
    tree.chmod(tree.stat().st_mode & ~0o222)


def _check_rpm_digest(path, expected):
    if path.is_symlink() or not path.is_file():
        raise PolicyError(f"missing or non-regular RPM: {path}")
    if _file_digest(path, "sha256") != expected:
        raise PolicyError(f"sha256 mismatch for snapshot RPM: {path}")


def _rpm_inventory(base, *, repodata=False):
    if base.is_symlink() or not base.is_dir():
        raise PolicyError(f"{base}: expected a regular RPM inventory directory")
    paths = []
    for arch in sorted(base.iterdir()):
        if (
            repodata
            and arch.name == "repodata"
            and arch.is_dir()
            and not arch.is_symlink()
        ):
            for entry in sorted(arch.iterdir()):
                if (
                    entry.is_symlink()
                    or not entry.is_file()
                    or entry.suffix.lower() == ".rpm"
                ):
                    raise PolicyError(f"{entry}: unexpected repository metadata entry")
            continue
        if (
            arch.name not in ("aarch64", "noarch")
            or arch.is_symlink()
            or not arch.is_dir()
        ):
            raise PolicyError(f"unexpected output directory: {arch}")
        for path in sorted(arch.iterdir()):
            rel = path.relative_to(base).as_posix()
            if (
                not RPM_ITEM_RE.fullmatch(rel)
                or path.is_symlink()
                or not path.is_file()
            ):
                raise PolicyError(f"unexpected output RPM: {path}")
            paths.append(path)
    return paths


def _check_rpm_inventory(base, wanted, *, repodata=False):
    found = {
        p.relative_to(base).as_posix() for p in _rpm_inventory(base, repodata=repodata)
    }
    extras = sorted(found - wanted)
    if extras:
        raise PolicyError(f"{base / extras[0]}: not in RPM snapshot")
    missing = sorted(wanted - found)
    if missing:
        raise PolicyError(f"{base / missing[0]}: missing from RPM inventory")


def _rpm_snapshot_identity(path):
    query = subprocess.run(
        ["rpm", "-qp", "--qf", RPM_SNAPSHOT_QUERY, str(path)],
        capture_output=True,
        text=True,
    )
    fields = tuple(query.stdout.strip().split("\t"))
    if (
        query.returncode
        or len(fields) != len(RPM_SNAPSHOT_FIELDS)
        or not all(fields)
        or not SHA256_HEX_RE.fullmatch(fields[-1])
    ):
        raise PolicyError(
            f"{path}: no valid RPM identity or PAYLOADSHA256: {query.stderr.strip()}"
        )
    return fields


def _allowed_rpm(package, arch):
    if arch == "noarch":
        return package in REQUIRED_BOARD_PACKAGES or package in OPTIONAL_NOARCH_PACKAGES
    return arch == "aarch64" and package in OPTIONAL_AARCH64_PACKAGES


def seal_rpm_run(run):
    run = _rpm_run_path(run)
    snapshot = run / "rpm-snapshot.json"
    repo = run / "repo"
    if os.path.lexists(snapshot) or os.path.lexists(repo):
        raise PolicyError(f"{run}: RPM snapshot or repository already exists")
    base = run / "out"
    paths = _rpm_inventory(base)
    checks = run / "rpm-checks"
    if checks.exists():
        selected = select_checked_rpms(base, checks)
        if {p for _, p in selected} != set(paths):
            raise PolicyError(
                f"{base}: RPM outputs do not match the checked build stages"
            )
    records = []
    seen = set()
    for path in paths:
        identity = _rpm_snapshot_identity(path)
        package, _, _, arch, _ = identity
        if (
            arch != path.parent.name
            or not _allowed_rpm(package, arch)
            or package in seen
        ):
            raise PolicyError(f"{path}: unexpected or duplicate {package} ({arch})")
        if arch == "aarch64" and not checks.exists():
            raise PolicyError(f"{path}: no bound aarch64 build stage")
        seen.add(package)
        records.append(
            {
                **dict(zip(RPM_SNAPSHOT_FIELDS, identity, strict=True)),
                "relpath": path.relative_to(base).as_posix(),
                "sha256": _file_digest(path, "sha256"),
            }
        )
    if not set(REQUIRED_BOARD_PACKAGES) <= seen:
        raise PolicyError(f"{base}: missing required board RPMs")
    with snapshot.open("x", encoding="utf-8") as fh:
        json.dump({"run_id": run.name, "rpms": records}, fh, indent=2)
        fh.write("\n")
    snapshot.chmod(0o444)
    _readonly_tree(base)
    repo.mkdir()
    for rec in records:
        path = repo / rec["relpath"]
        path.parent.mkdir(exist_ok=True)
        shutil.copyfile(base / rec["relpath"], path)
        _check_rpm_digest(path, rec["sha256"])
    subprocess.run(
        [
            os.environ.get("CREATEREPO_C", "createrepo_c"),
            "--checksum",
            "sha256",
            str(repo),
        ],
        check=True,
        stdout=sys.stderr,
    )
    _readonly_tree(repo)


def load_rpm_run(run):
    """Read the single snapshot once; bind exact local copy paths for DNF and sealing."""
    run = _rpm_run_path(run)
    snapshot = run / "rpm-snapshot.json"
    if snapshot.is_symlink() or not snapshot.is_file():
        raise PolicyError(f"{run}: missing sealed RPM snapshot")
    repo = run / "repo"
    if (
        repo.is_symlink()
        or not (repo / "repodata/repomd.xml").is_file()
        or repo.stat().st_mode & 0o222
    ):
        raise PolicyError(f"{repo}: missing sealed RPM repository")
    data = json.loads(snapshot.read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or data.get("run_id") != run.name
        or not isinstance(data.get("rpms"), list)
    ):
        raise PolicyError(f"{snapshot}: invalid run identity or RPM records")
    selected = []
    seen = set()
    relpaths = set()
    for rec in data["rpms"]:
        if not isinstance(rec, dict) or not all(
            isinstance(rec.get(key), str) and rec[key]
            for key in (*RPM_SNAPSHOT_FIELDS, "relpath", "sha256")
        ):
            raise PolicyError(f"{snapshot}: incomplete RPM record")
        package, arch, rel = rec["package"], rec["arch"], rec["relpath"]
        if (
            not RPM_ITEM_RE.fullmatch(rel)
            or not rel.startswith(arch + "/")
            or not SHA256_HEX_RE.fullmatch(rec["sha256"])
            or not SHA256_HEX_RE.fullmatch(rec["payload_sha256"])
            or not _allowed_rpm(package, arch)
            or package in seen
            or rel in relpaths
        ):
            raise PolicyError(
                f"{snapshot}: invalid or duplicate RPM record for {package!r}"
            )
        path = repo / rel
        if path.parent.is_symlink() or any(c in str(path) for c in "\t\n\r"):
            raise PolicyError(f"{snapshot}: unsupported RPM path: {path!r}")
        seen.add(package)
        relpaths.add(rel)
        selected.append({**rec, "path": str(path)})
    if not set(REQUIRED_BOARD_PACKAGES) <= seen:
        raise PolicyError(f"{snapshot}: missing required board RPMs")
    outputs = run / "out"
    _check_rpm_inventory(outputs, relpaths)
    _check_rpm_inventory(repo, relpaths, repodata=True)
    for rec in selected:
        source, copy = outputs / rec["relpath"], Path(rec["path"])
        # Both files must match the snapshot byte for byte; query the copy's
        # actual metadata rather than trusting the JSON identity fields.
        _check_rpm_digest(source, rec["sha256"])
        _check_rpm_digest(copy, rec["sha256"])
        if _rpm_snapshot_identity(copy) != tuple(rec[k] for k in RPM_SNAPSHOT_FIELDS):
            raise PolicyError(f"{copy}: RPM identity differs from snapshot")
    return selected


def check_installed_rpms(root, records):
    """Require exactly one installed match for every RPM selected for DNF."""
    if not isinstance(records, list) or not records:
        raise PolicyError("no selected RPM snapshot records")
    wanted = {}
    for rec in records:
        if not isinstance(rec, dict) or not all(
            isinstance(rec.get(key), str) and rec[key] for key in RPM_SNAPSHOT_FIELDS
        ):
            raise PolicyError("incomplete selected RPM snapshot record")
        name = rec["package"]
        if name in wanted or not SHA256_HEX_RE.fullmatch(rec["payload_sha256"]):
            raise PolicyError(
                f"{name}: invalid or duplicate selected RPM snapshot record"
            )
        wanted[name] = tuple(rec[key] for key in RPM_SNAPSHOT_FIELDS)
    query = subprocess.run(
        ["rpm", "--root", str(root), "-qa", "--qf", RPM_SNAPSHOT_QUERY],
        capture_output=True,
        text=True,
    )
    if query.returncode != 0:
        raise PolicyError(
            f"{root}: cannot query installed RPMs: {query.stderr.strip()}"
        )
    found = set()
    for line in query.stdout.splitlines():
        actual = tuple(line.split("\t"))
        name = actual[0]
        if name not in wanted:
            continue
        if name in found:
            raise PolicyError(f"{root}: multiple installed RPMs named {name}")
        expected = wanted[name]
        if actual != expected:
            raise PolicyError(
                f"{root}: installed {name} differs from snapshot "
                f"(NEVRA, EVR, ARCH, PAYLOADSHA256): got {actual[1:]}, expected {expected[1:]}"
            )
        found.add(name)
    missing = sorted(wanted.keys() - found)
    if missing:
        raise PolicyError(f"{root}: snapshot RPM not installed: {', '.join(missing)}")


def _rpm_name_nevra_arch(path):
    """(name, NEVRA, ARCH) of the RPM at PATH, or a PolicyError."""
    r = subprocess.run(
        ["rpm", "-qp", "--qf", "%{NAME} %{NEVRA} %{ARCH}", str(path)],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0 or not r.stdout.strip():
        raise PolicyError(f"cannot read RPM identity from {path}: {r.stderr.strip()}")
    fields = r.stdout.strip().split()
    if len(fields) != 3 or not all(fields):
        raise PolicyError(f"bad RPM identity from {path}: {r.stdout.strip()!r}")
    return fields[0], fields[1], fields[2]


def _srpm_record(rpms_dir, srpm_path):
    """{package, relpath, sha256} of the fwlog SRPM, relpath from RPMS_DIR's parent."""
    top = Path(rpms_dir).resolve().parent
    path = Path(srpm_path).resolve()
    if not path.is_file() or Path(srpm_path).is_symlink():
        raise PolicyError(f"missing or non-regular SRPM: {srpm_path}")
    try:
        rel = path.relative_to(top).as_posix()
    except ValueError as exc:
        raise PolicyError(f"SRPM {path} is outside {top}") from exc
    res = subprocess.run(
        ["rpm", "-qp", "--qf", "%{NAME} %{SOURCERPM}", str(path)],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0 or res.stdout.split(" ")[0] != FWLOG_SRPM_PACKAGE:
        raise PolicyError(f"{path} is not a {FWLOG_SRPM_PACKAGE} SRPM")
    if not path.name.endswith(".src.rpm") or res.stdout.split(" ", 1)[1] != "(none)":
        raise PolicyError(f"{path} is not a source RPM")
    return {
        "package": FWLOG_SRPM_PACKAGE,
        "relpath": rel,
        "sha256": _file_digest(path, "sha256"),
    }


def _check_srpm_record(rpms_dir, record, mpath):
    """Resolve and digest-check a recorded SRPM; return its path."""
    if (
        not isinstance(record, dict)
        or record.get("package") != FWLOG_SRPM_PACKAGE
        or not isinstance(record.get("relpath"), str)
        or not isinstance(record.get("sha256"), str)
        or not SHA256_HEX_RE.fullmatch(record["sha256"])
    ):
        raise PolicyError(f"{mpath}: invalid srpm record {record!r}")
    top = Path(rpms_dir).resolve().parent
    rel = Path(record["relpath"])
    if rel.is_absolute() or ".." in rel.parts:
        raise PolicyError(f"{mpath}: unsafe srpm relpath {record['relpath']!r}")
    path = top / rel
    if path.is_symlink() or not path.is_file():
        raise PolicyError(f"{mpath}: missing or non-regular SRPM {rel}")
    actual = _file_digest(path, "sha256")
    if actual != record["sha256"]:
        raise PolicyError(
            f"{mpath}: sha256 mismatch for SRPM {rel} "
            f"(actual {actual}, manifest {record['sha256']})"
        )
    return path


def write_rpm_manifest(
    rpms_dir,
    out_manifest,
    rpm_paths,
    kind="noarch",
    run_id=None,
    expect_aarch64=False,
    bind_noarch=None,
    srpm=None,
    bind_noarch_sha256=None,
):
    """Write an atomic checked-RPM manifest bound to one run_id with sha256s.

    Every RPM is recorded as {package, nevra, arch, relpath, sha256}; ARCH must
    be noarch (kind=noarch) or aarch64 (kind=aarch64) as the package expects.
    """
    srpm_record = None
    noarch_sha = None
    if kind not in ("noarch", "aarch64"):
        raise PolicyError(f"invalid rpm manifest kind: {kind!r}")
    if kind == "noarch":
        if bind_noarch is not None:
            raise PolicyError("--bind-noarch is only valid for kind='aarch64'")
        if run_id is None:
            run_id = rpm_run_id()
        if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
            raise PolicyError(f"invalid run_id: {run_id!r}")
        if bind_noarch_sha256 is not None:
            raise PolicyError("--bind-noarch-sha256 is only valid for kind='aarch64'")
        if expect_aarch64:
            if srpm is None:
                raise PolicyError("--expect-aarch64 requires --srpm (the fwlog SRPM)")
            srpm_record = _srpm_record(rpms_dir, srpm)
        elif srpm is not None:
            raise PolicyError("--srpm is only valid with --expect-aarch64")
    else:
        if srpm is not None:
            raise PolicyError("--srpm is only valid for kind='noarch'")
        if bind_noarch is None or bind_noarch_sha256 is None:
            raise PolicyError(
                "aarch64 manifest requires --bind-noarch and --bind-noarch-sha256"
            )
        noarch_sha = _file_digest(bind_noarch, "sha256")
        if noarch_sha != bind_noarch_sha256:
            raise PolicyError(
                f"{bind_noarch} changed during the run (sha256 {noarch_sha}, "
                f"bound {bind_noarch_sha256}): refusing to bind"
            )
        _, bound_run_id, bound_expect, bound_data = _load_rpm_manifest(
            rpms_dir,
            bind_noarch,
            "noarch",
            set(REQUIRED_BOARD_PACKAGES) | set(OPTIONAL_NOARCH_PACKAGES),
        )
        if _file_digest(bind_noarch, "sha256") != bind_noarch_sha256:
            raise PolicyError(f"{bind_noarch} changed during the run: refusing to bind")
        if not bound_expect:
            raise PolicyError(
                f"{bind_noarch}: noarch run did not expect aarch64 packages (FWREPO=none)"
            )
        if run_id is not None and run_id != bound_run_id:
            raise PolicyError(
                f"run_id {run_id!r} disagrees with bound noarch manifest run_id {bound_run_id!r}"
            )
        run_id = bound_run_id
        srpm_record = bound_data["srpm"]
        srpm_path = _check_srpm_record(rpms_dir, srpm_record, bind_noarch)
    allowed = (
        set(REQUIRED_BOARD_PACKAGES) | set(OPTIONAL_NOARCH_PACKAGES)
        if kind == "noarch"
        else set(OPTIONAL_AARCH64_PACKAGES)
    )
    expected_arch = "noarch" if kind == "noarch" else "aarch64"
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
        pkg, nevra, arch = _rpm_name_nevra_arch(path)
        if arch != expected_arch:
            raise PolicyError(
                f"{path} has ARCH {arch!r}, expected {expected_arch!r} for this run"
            )
        if kind == "aarch64":
            src = subprocess.run(
                ["rpm", "-qp", "--qf", "%{SOURCERPM}", str(path)],
                capture_output=True,
                text=True,
            )
            if src.returncode != 0 or src.stdout.strip() != srpm_path.name:
                raise PolicyError(
                    f"{path} was built from {src.stdout.strip()!r}, not the bound "
                    f"SRPM {srpm_path.name}"
                )
        if pkg not in allowed:
            raise PolicyError(f"unexpected {kind} board RPM package: {pkg}")
        if pkg in seen:
            raise PolicyError(f"duplicate {kind} board RPM package in run: {pkg}")
        seen.add(pkg)
        records.append(
            {
                "package": pkg,
                "nevra": nevra,
                "arch": arch,
                "relpath": rel,
                "sha256": _file_digest(path, "sha256"),
            }
        )
    if not records:
        raise PolicyError(f"no {kind} RPMs provided for manifest")
    payload = {
        "version": RPM_MANIFEST_VERSION,
        "kind": kind,
        "run_id": run_id,
        "count": len(records),
        "rpms": records,
    }
    if kind == "noarch":
        payload["expect_aarch64"] = bool(expect_aarch64)
        if srpm_record is not None:
            payload["srpm"] = srpm_record
    else:
        payload["noarch_manifest_sha256"] = noarch_sha
        payload["srpm"] = srpm_record
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
    if data.get("version") != RPM_MANIFEST_VERSION or data.get("kind") != expected_kind:
        raise PolicyError(
            f"invalid RPM manifest {mpath}: version={data.get('version')!r}, "
            f"kind={data.get('kind')!r}"
        )
    run_id = data.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise PolicyError(f"invalid RPM manifest {mpath}: missing or bad run_id")
    expect_aarch64 = None
    if expected_kind == "noarch":
        expect_aarch64 = data.get("expect_aarch64")
        if not isinstance(expect_aarch64, bool):
            raise PolicyError(
                f"invalid RPM manifest {mpath}: missing boolean expect_aarch64"
            )
        if expect_aarch64:
            _check_srpm_record(rpms_dir, data.get("srpm"), mpath)
        elif "srpm" in data:
            raise PolicyError(f"{mpath}: srpm recorded for an FWREPO=none run")
    else:
        _check_srpm_record(rpms_dir, data.get("srpm"), mpath)
        nsha = data.get("noarch_manifest_sha256")
        if not isinstance(nsha, str) or not SHA256_HEX_RE.fullmatch(nsha):
            raise PolicyError(f"{mpath}: missing noarch_manifest_sha256")
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
        expected_arch = entry.get("arch")
        want_arch = "noarch" if expected_kind == "noarch" else "aarch64"
        if (
            not isinstance(pkg, str)
            or pkg not in allowed_packages
            or not isinstance(rel, str)
            or not rel
            or not isinstance(expected_sha, str)
            or not SHA256_HEX_RE.fullmatch(expected_sha)
            or expected_arch != want_arch
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
    return selected, run_id, expect_aarch64, data


def stage_srpm(noarch_manifest, dest_dir):
    """Copy only the fwlog SRPM NOARCH_MANIFEST records into new DEST_DIR."""
    mpath = Path(noarch_manifest)
    try:
        raw = mpath.read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read {mpath}: {exc}") from exc
    msha = hashlib.sha256(raw).hexdigest()
    rpms_dir = mpath.parent.parent / "out"
    snap = Path(dest_dir) / ".noarch-manifest.json"
    dest = Path(dest_dir)
    try:
        dest.mkdir()
    except OSError as exc:
        raise PolicyError(f"run-private directory {dest} must be new: {exc}") from exc
    snap.write_bytes(raw)
    try:
        _sel, _run, expect, data = _load_rpm_manifest(
            rpms_dir,
            snap,
            "noarch",
            set(REQUIRED_BOARD_PACKAGES) | set(OPTIONAL_NOARCH_PACKAGES),
        )
    finally:
        snap.unlink()
    if not expect:
        raise PolicyError(f"{mpath}: noarch run did not expect aarch64 (FWREPO=none)")
    src = _check_srpm_record(rpms_dir, data["srpm"], mpath)
    copy = dest / src.name
    shutil.copyfile(src, copy)
    if _file_digest(copy, "sha256") != data["srpm"]["sha256"]:
        raise PolicyError(f"{copy}: copy does not match the recorded SRPM digest")
    return copy, msha


def select_checked_rpms(rpms_dir, checks_dir):
    """Validate both private build stages before snapshotting an aarch64 run."""
    base = Path(rpms_dir)
    noarch_manifest = checks_dir / "checked-rpms.json"
    selected, noarch_run_id, expect_aarch64, noarch_data = _load_rpm_manifest(
        base,
        noarch_manifest,
        "noarch",
        set(REQUIRED_BOARD_PACKAGES) | set(OPTIONAL_NOARCH_PACKAGES),
    )
    for req in REQUIRED_BOARD_PACKAGES:
        if req not in selected:
            raise PolicyError(f"{noarch_manifest}: missing required package {req}")
    aarch64_manifest = checks_dir / "checked-aarch64-rpms.json"
    has_aarch64 = aarch64_manifest.exists() or aarch64_manifest.is_symlink()
    if has_aarch64:
        if not expect_aarch64:
            raise PolicyError(
                f"{aarch64_manifest}: unexpected aarch64 manifest (noarch run {noarch_run_id} built with FWREPO=none)"
            )
        arch_selected, arch_run_id, _, arch_data = _load_rpm_manifest(
            base, aarch64_manifest, "aarch64", set(OPTIONAL_AARCH64_PACKAGES)
        )
        if arch_run_id != noarch_run_id:
            raise PolicyError(
                f"{aarch64_manifest}: run_id {arch_run_id} does not match "
                f"{noarch_manifest} run_id {noarch_run_id}"
            )
        noarch_sha = _file_digest(noarch_manifest, "sha256")
        if arch_data["noarch_manifest_sha256"] != noarch_sha:
            raise PolicyError(
                f"{aarch64_manifest}: bound to a different {noarch_manifest} "
                f"(sha256 {arch_data['noarch_manifest_sha256']}, now {noarch_sha})"
            )
        if arch_data["srpm"] != noarch_data["srpm"]:
            raise PolicyError(
                f"{aarch64_manifest}: built from a different SRPM than "
                f"{noarch_manifest} records"
            )
        selected.update(arch_selected)
    elif expect_aarch64:
        raise PolicyError(
            f"{aarch64_manifest}: missing aarch64 manifest for FWREPO run {noarch_run_id}"
        )
    order = (
        REQUIRED_BOARD_PACKAGES + OPTIONAL_AARCH64_PACKAGES + OPTIONAL_NOARCH_PACKAGES
    )
    return [(pkg, selected[pkg]) for pkg in order if pkg in selected]


def verify_rpmdb_list(root, packages_file):
    """Cross-check a captured `rpm --root ROOT -qa` listing against librpm."""
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
    """Fail-closed filesystem absence check using os.scandir / os.walk(onerror=...)."""
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
    p = sub.add_parser("unit-config")
    p.add_argument("root", type=Path)
    p.add_argument("unit")
    p.add_argument("--fixture", type=Path, required=True)
    p = sub.add_parser("unit-enabled")
    p.add_argument("root", type=Path)
    p.add_argument("unit")
    p.add_argument("--state", choices=("enabled", "masked"), required=True)
    p = sub.add_parser("initramfs-unpack")
    p.add_argument("img", type=Path)
    p.add_argument("dest", type=Path)
    p = sub.add_parser("esp-staged")
    p.add_argument("root", type=Path)
    p.add_argument("--esp-dir", type=Path, required=True)
    p.add_argument("--dtb-rpm", type=Path, required=True)
    p.add_argument("--dtb-rpm-sha256")
    p = sub.add_parser("overlay-esp")
    p.add_argument("overlay", type=Path)
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
    p.add_argument("--run-id")
    p.add_argument("--expect-aarch64", action="store_true")
    p.add_argument("--bind-noarch", type=Path)
    p.add_argument("--bind-noarch-sha256")
    p.add_argument("--srpm", type=Path)
    p.add_argument("rpms", nargs="+", type=Path)
    p = sub.add_parser("stage-srpm")
    p.add_argument("noarch_manifest", type=Path)
    p.add_argument("dest_dir", type=Path)
    p = sub.add_parser("select-rpms")
    p.add_argument("rpms_dir", type=Path)
    p.add_argument("checks_dir", type=Path)
    p = sub.add_parser("new-rpm-run")
    p.add_argument("buildroot", type=Path)
    p = sub.add_parser("seal-rpm-run")
    p.add_argument("run", type=Path)
    p = sub.add_parser("load-rpm-run")
    p.add_argument("run", type=Path)
    p = sub.add_parser("check-installed-rpms")
    p.add_argument("root", type=Path)
    p.add_argument("records")
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
    if a.cmd == "unit-config":
        try:
            ok, msg = unit_config(a.root, a.unit, a.fixture)
        except PolicyError as exc:
            print(f"unit-config: {exc}", file=sys.stderr)
            return 1
        if not ok:
            print(f"unit-config: {msg}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "check-installed-rpms":
        try:
            check_installed_rpms(a.root, json.loads(a.records))
        except (PolicyError, OSError, ValueError) as exc:
            print(f"check-installed-rpms: {exc}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "unit-enabled":
        try:
            ok, msg = unit_enabled(a.root, a.unit, a.state)
        except PolicyError as exc:
            print(f"unit-enabled: {exc}", file=sys.stderr)
            return 1
        if not ok:
            print(f"unit-enabled: {msg}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "initramfs-unpack":
        try:
            initramfs_unpack(a.img, a.dest)
        except PolicyError as exc:
            print(f"initramfs-unpack: {exc}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "esp-staged":
        try:
            ok, problems = esp_staged(
                a.root, a.esp_dir, a.dtb_rpm, dtb_rpm_sha256=a.dtb_rpm_sha256
            )
        except PolicyError as exc:
            print(f"esp-staged: {exc}", file=sys.stderr)
            return 1
        for problem in problems:
            print(problem, file=sys.stderr)
        return 0 if ok else 1
    if a.cmd == "overlay-esp":
        for hit in overlay_esp_entries(a.overlay):
            print(hit)
        return 0
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
            write_rpm_manifest(
                a.rpms_dir,
                a.manifest,
                a.rpms,
                kind=a.kind,
                run_id=a.run_id,
                expect_aarch64=a.expect_aarch64,
                bind_noarch=a.bind_noarch,
                srpm=a.srpm,
                bind_noarch_sha256=a.bind_noarch_sha256,
            )
        except PolicyError as exc:
            print(f"write-rpm-manifest: {exc}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "stage-srpm":
        try:
            copy, msha = stage_srpm(a.noarch_manifest, a.dest_dir)
        except PolicyError as exc:
            print(f"stage-srpm: {exc}", file=sys.stderr)
            return 1
        print(f"{copy}\t{msha}")
        return 0
    if a.cmd == "select-rpms":
        try:
            for pkg, rpm_path in select_checked_rpms(a.rpms_dir, a.checks_dir):
                print(f"{pkg}\t{rpm_path}")
        except PolicyError as exc:
            print(f"select-rpms: {exc}", file=sys.stderr)
            return 1
        return 0
    if a.cmd in ("new-rpm-run", "seal-rpm-run", "load-rpm-run"):
        try:
            if a.cmd == "new-rpm-run":
                print(new_rpm_run(a.buildroot))
            elif a.cmd == "seal-rpm-run":
                seal_rpm_run(a.run)
            else:
                records = load_rpm_run(a.run)
                print(json.dumps(records))
                for rec in records:
                    print(f"{rec['package']}\t{rec['sha256']}\t{rec['path']}")
        except (PolicyError, OSError, ValueError, subprocess.CalledProcessError) as exc:
            print(f"{a.cmd}: {exc}", file=sys.stderr)
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
