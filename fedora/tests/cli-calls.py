#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check repository callers against the actual Python CLI parsers.

runpy runs imports and module-level code. The sentinel stops the target after
argparse parses the sample, before the selected CLI action.
"""

import argparse
import ast
from collections import Counter, defaultdict
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
import hashlib
import io
from itertools import product
from pathlib import Path, PurePosixPath
import re
import runpy
import shlex
import subprocess
import sys
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
MIN_CLI_CALLS = 32
MIN_INLINE_CALLS = 14
MIN_MODULE_LOADS = 2
DIGEST = "a" * 64
VALUES = {
    # mkdevcard.sh: profile defaults, protective/maintenance choices and firmware fields.
    "BOOT_MODES": ("", "protective"),
    "GROW_ROOT": ("no", "yes"),
    "FIRST_BOOT": ("", "maintenance"),
    "FW_SHA%% *": (DIGEST,),
    "DTB_RPM_SHA": (DIGEST,),
    "SEEK": ("256",),
    "FW_SIZE": ("1024",),
    "BUILD_SOURCE": ("a" * 40,),
    "RPM_RUN##*/": ("fixture-run",),
    "RPM_RECORDS": ("[]",),
}
# Only the wrapper forwarding site takes arbitrary arguments from its own caller.
FORWARDED = {
    ("fedora/verify-devcard.sh", 39): (
        "verify-devcard.sh shifts IMAGE and MANIFEST at lines 12–15 and forwards $@; "
        "the required digest and optional firmware are in its usage; MAIN_BIN at "
        "21–30 conditionally appends --main-bin.",
        (
            ("--expect-manifest-sha256", DIGEST),
            ("--expect-manifest-sha256", DIGEST, "--firmware", "/stub/firmware.bin"),
        ),
    )
}
# Hand-written argv for the few source lines deliberately not tokenized. Bind
# each sample to its exact logical source line, including all continuations.
POLICY = "fedora/devcard-policy.py"
MANIFEST = "fedora/devcard-manifest.py"
INITRAMFS = "fedora/initramfs-policy.py"
STAGED = "fedora/staged-root-policy.py"
SELINUX = "fedora/selinux-label.py"
MKDEV = "fedora/mkdevcard.sh"
PROFILES = tuple(
    ("--boot-modes", boot, "--grow-root", grow, "--first-boot", first)
    for boot, grow, first in product(
        VALUES["BOOT_MODES"], VALUES["GROW_ROOT"], VALUES["FIRST_BOOT"]
    )
)
FIRMWARE = (
    "--firmware-sha256",
    DIGEST,
    "--firmware-seek",
    "256",
    "--firmware-size",
    "1024",
)
MANUAL_RECORDS = {
    ("fedora/build-aarch64-rpms.sh", 32): (
        "e1f97bac420a4e3888255828c3839b9366f020d41b69a80c8d85dcaa3f7dd525",
        POLICY,
        ("stage-srpm /stub/NOARCH_MANIFEST /stub/BUILD_SYS/sources",),
    ),
    ("fedora/build-rpms.sh", 37): (
        "5a742699b2a826504b1f3fd4923d00b5a42bbc0814b809f64d6113c72a783232",
        POLICY,
        ("new-rpm-run /stub/BR",),
    ),
    ("fedora/build-rpms.sh", 163): (
        "fb739d6c88aaffd5bd68c0f0125fb4aeda0ed207b9aae994d918dc8d304ca79f",
        POLICY,
        (
            "write-rpm-manifest /stub/RUN/out /stub/RUN/rpm-checks/checked-rpms.json "
            "--kind noarch --run-id fixture-run --expect-aarch64 --srpm /stub/fwlog.src.rpm "
            "/stub/RUN/out/noarch/board.rpm",
        ),
    ),
    (MKDEV, 187): (
        "51b9a1bba2d0dfa75146ec58dd9ce9bfa0f199ab75da3a9ab95389bc5bea5ca6",
        POLICY,
        ("load-rpm-run /stub/RPM_RUN",),
    ),
    (MKDEV, 378): (
        "b8b23efdca814575932844ca19f01b89af34d3f8c7d001caab628cc82dd4bb0f",
        POLICY,
        ("check-installed-rpms /stub/ROOT '[]'",),
    ),
    (MKDEV, 588): (
        "a9f1083f6b7e7e4c3eb46e628042fa96f79183d6b198dd7be74ec19ae7b956d2",
        POLICY,
        ("aic-provenance /stub/ROOT --report /stub/W/aic-provenance.tsv",),
    ),
    (MKDEV, 597): (
        "266d5bcd0c46572218271538bbeca6914f9dae8aacb3b252d61518c99e7ac031",
        INITRAMFS,
        (
            "capture-digest /stub/ROOT /stub/W/kernel.txt /stub/W/initramfs-digests.json",
        ),
    ),
    (MKDEV, 603): (
        "40fc6e105e73522ca3f567875f6bdf6274a2a123d00838b7661cb6b7852b9971",
        INITRAMFS,
        ("overlay /stub/OVERLAY",),
    ),
    (MKDEV, 605): (
        "42e0b7d6ddf234fbc71e925708a6dad5c712c46ed6d56cabba0975f01e00b425",
        STAGED,
        ("overlay /stub/OVERLAY",),
    ),
    (MKDEV, 614): (
        "b00cc7922af34a2c39f78f65076ebe21af023cf1284408d53e97cc0e49bd0495",
        POLICY,
        (
            "aic-overlay /stub/OVERLAY",
            "aic-overlay /stub/OVERLAY --manifest /stub/ROOT/usr/share/cubie-a7a/aic8800-d80-usb.manifest",
        ),
    ),
    (MKDEV, 618): (
        "258dcc19199c8288f7c11d2fc90f2b0ec98c4af5a33aec16fae93f650d2f5c8b",
        POLICY,
        ("overlay-esp /stub/OVERLAY",),
    ),
    (MKDEV, 630): (
        "d869f605432e06a5386bbd8144df4a6f2c7eb4467e3341f513b24457807a5d2b",
        POLICY,
        ("check-installed-rpms /stub/ROOT '[]'",),
    ),
    (MKDEV, 634): (
        "ef0d4ac2b7cd672aaeeb6b4d75226ae0dd439543b75d2b3c58a1389c2ea0baa0",
        POLICY,
        ("aic-provenance /stub/ROOT --report /stub/W/aic-provenance-final.tsv",),
    ),
    (MKDEV, 642): (
        "c5d1fcee9e105649cd58f846360101a04a411095cbc3a0eb93ad656cd2934bbd",
        INITRAMFS,
        ("root-modules /stub/ROOT /stub/k --board /stub/boot",),
    ),
    (MKDEV, 669): (
        "02d19c635041eea1a6e68f80b86a1c0d095e709784d59f0f7504235ba9a73a5a",
        STAGED,
        (
            "staged /stub/ROOT /stub/expected /stub/W/kernel.txt /stub/ROOT_UUID /stub/default_args /stub/def",
        ),
    ),
    (MKDEV, 707): (
        "0d8c064385e9d93e861a5fc0ca2115cba3ea57b38a1121d40b9eba42ded15b70",
        MANIFEST,
        ("check-fat /stub/esp",),
    ),
    (MKDEV, 710): (
        "fa105ba31e42ca14fbf83636c4bc3ff93d2519f207d3a2ae42d5884b54c37d8b",
        MANIFEST,
        ("esp-model /stub/ROOT/boot/efi /stub/W/esp-model.json",),
    ),
    (MKDEV, 719): (
        "6fcf166f6ae41a11000308def225c970e8c5996e284ae871fda7e406b94221ce",
        SELINUX,
        ("/stub/ROOT /stub/rootimg /stub/W/selinux",),
    ),
    (MKDEV, 720): (
        "0e47db519b97ff9c5b0b162c840458c518095bcdca7d1401b6766f2abb64ea2c",
        SELINUX,
        ("--verify /stub/ROOT /stub/rootimg /stub/W/selinux-verify",),
    ),
    (MKDEV, 723): (
        "513c9c1bca2e1315b2bc34f839c79b7fad9b055a745443a48f899f551da9bb5c",
        STAGED,
        ("packed /stub/rootimg", "packed /stub/rootimg --protective"),
    ),
    (MKDEV, 785): (
        "5ffbce4d8e73b0432cd3323f95dbcfd5c061b5ca370e7c4ceb9b94de4cfb9ffc",
        MANIFEST,
        tuple(
            shlex.join(
                (
                    "write",
                    "/stub/OUT",
                    "/stub/ROOT",
                    "[]",
                    "/stub/manifest",
                    "--esp-model",
                    "/stub/W/esp-model.json",
                    *profile,
                    *firmware,
                )
            )
            for profile, firmware in product(PROFILES, ((), FIRMWARE))
        ),
    ),
    (MKDEV, 795): (
        "b6b04e75a2a8195d8bb225b88bd71db35aa0e2dea687b922fe87dd0842e2bcc1",
        MANIFEST,
        tuple(
            shlex.join(
                (
                    "seal",
                    "/stub/OUT",
                    "/stub/manifest",
                    "/stub/receipt",
                    "/stub/RPM_SNAPSHOT",
                    "/stub/W/initramfs-digests.json",
                    *profile,
                    "--dram-identity",
                    "",
                    "--source-commit",
                    "a" * 40,
                    "--run-id",
                    "fixture-run",
                    "--started-utc",
                    "2026-01-01T00:00:00Z",
                    "--finished-utc",
                    "2026-01-01T00:01:00Z",
                    "--expect-manifest-sha256",
                    DIGEST,
                    "--expect-snapshot-sha256",
                    DIGEST,
                )
            )
            for profile in PROFILES
        ),
    ),
}


def reviewed_body(key):
    path, line = key
    if path == MKDEV and 305 < line < 672:
        return ("STAGE1", "'")
    if path == MKDEV and 698 < line < 724:
        return ("STAGE2", "'")
    return None


UNRESOLVED = {
    key: (
        target,
        tuple(tuple(shlex.split(sample)) for sample in samples),
        (
            f"quoted {body[0]} shell heredoc; sample checked against the parser"
            if (body := reviewed_body(key))
            else "substitution or quoted #; sample checked against the parser"
        ),
    )
    for key, (_, target, samples) in MANUAL_RECORDS.items()
}
# This exact sentence inside the quoted STAGE1 text is a comment, not a call.
HEREDOC_PROSE = {
    (
        MKDEV,
        616,
        ("STAGE1", "'"),
        "# The ESP holds the packages' files only (devcard-policy.py esp-staged, the",
    )
}

WORD = r"""(?:"[^"]*"|'[^']*'|[^\s();<>|&]+)"""
COMMAND_START = re.compile(r"(?:^\s*[@+-]?|\$\(|&&|\|\||[;|]|\b(?:do|then|else)\s+)\s*")
PREFIX = re.compile(rf"(?:(?:exec|command|env(?:\s+-u\s+\w+)?)|[A-Za-z_]\w*={WORD})\s+")
PYTHON = re.compile(
    r"(?:(?:.*/)?python(?:[23](?:\.\d+)?)?|\$\{?PYTHON\}?|\$\(PYTHON\))$"
)
VARIABLE = re.compile(r"\$\{([^}]*)\}|\$([A-Za-z_]\w*|[0-9]+)")
ARRAY = re.compile(r"\$\{(\w+)\[@\]\}")
ASSIGN = re.compile(r"^\s*(?:local\s+|export\s+)?(\w+)=([^;\s]+)\s*$")
ARRAY_ASSIGN = re.compile(r"^\s*(?:.*(?:\|\||&&)\s+)?(\w+)(\+?=)\((.*)\)\s*$")
STOP = frozenset("();<>|&")
SUBPROCESS = {"run", "Popen", "call", "check_call", "check_output"}


class Parsed(Exception):
    """Stop a target immediately after its CLI parser has accepted the argv."""


@dataclass
class Call:
    path: str
    line: int
    target: str
    variants: tuple
    category: str = "CLI"
    note: str = ""


def target_for(word, source, programs):
    if word in programs:
        return word
    for candidate in programs:
        if word.endswith("/" + candidate):
            return candidate
    relative = (PurePosixPath(source).parent / word).as_posix()
    if relative in programs:
        return relative
    matches = [program for program in programs if Path(program).name == word]
    return matches[0] if len(matches) == 1 else ""


def shell_lex(text, quote=None, comments=False):
    """Quote state at each unescaped character, before shlex removes quotes."""
    contexts = {}
    escaped = False
    for position, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if (
            comments
            and char == "#"
            and quote is None
            and (
                position == 0
                or text[position - 1].isspace()
                or text[position - 1] in STOP
            )
        ):
            return contexts, quote, position
        contexts[position] = quote
        if char == "\\" and quote != "'":
            escaped = True
        elif char == quote:
            quote = None
        elif quote is None and char in "\"'":
            quote = char
    return contexts, quote, len(text)


def shell_contexts(text):
    return shell_lex(text)[0].items()


HEREDOC_WORD = re.compile(
    r"""(?P<tabs>-?)[ \t]*(?P<quote>['"]?)(?P<word>[A-Za-z0-9_][A-Za-z0-9_-]*)(?P=quote)(?=$|[\s;|&<>)])"""
)


def shell_records(path, source):
    """Read heredoc bodies as data with exact physical delimiter matching."""
    # Bash compares the delimiter on physical LF-delimited lines. A CR or
    # trailing space is data, not part of an exact closing delimiter.
    lines = source.split("\n")
    index = 0
    end_quote = None
    spec_prose = False
    while index < len(lines):
        start = index
        text = lines[index]
        index += 1
        if path.endswith(".spec"):
            section = re.match(
                r"^\s*%(description|changelog|files|package|prep|build|install|check"
                r"|clean|generate_buildrequires|(?:pre|post)\w*"
                r"|(?:transfile|file)?trigger\w*|verifyscript)\b",
                text,
            )
            if section:
                spec_prose = section[1] in {"description", "changelog", "files"}
            if spec_prose:
                continue
        if end_quote is None and text.lstrip().startswith("#"):
            continue
        initial = end_quote
        # In substitution-bearing text the simple quote state is not enough
        # to decide where a shell comment begins. Keep those bytes.
        while True:
            contexts, end_quote, safe_end = shell_lex(
                text, initial, comments=initial is None and "$(" not in text
            )
            if not (
                text.endswith("\\")
                and safe_end == len(text)
                and len(text) - 1 in contexts
                and contexts[len(text) - 1] != "'"
                and index < len(lines)
            ):
                break
            text = text[:-1] + " " + lines[index]
            index += 1
        possible = [
            match.start() for match in re.finditer(r"(?<!<)<<(?!<)", text[:safe_end])
        ]
        if "$(" in text and possible:
            raise ValueError(f"{path}:{start + 1}: unsupported heredoc in substitution")
        redirects = [
            pos for pos in possible if pos in contexts and contexts[pos] is None
        ]
        redirect = None
        if redirects:
            if (
                len(redirects) != 1
                or initial is not None
                or any(
                    text[pos] in "({" and quote is None
                    for pos, quote in contexts.items()
                    if pos < redirects[0]
                )
            ):
                raise ValueError(f"{path}:{start + 1}: unsupported heredoc redirect")
            redirect = HEREDOC_WORD.match(text, redirects[0] + 2, safe_end)
            if not redirect:
                raise ValueError(f"{path}:{start + 1}: unsupported heredoc delimiter")
        yield start + 1, text, initial, safe_end, None
        if not redirect:
            continue
        delimiter = redirect["word"]
        strip_tabs = bool(redirect["tabs"])
        body_start = index
        while index < len(lines):
            candidate = lines[index].lstrip("\t") if strip_tabs else lines[index]
            if candidate == delimiter:
                break
            index += 1
        if index == len(lines):
            raise ValueError(f"{path}:{start + 1}: unterminated heredoc {delimiter}")
        body = lines[body_start:index]
        prefix = text[: redirects[0]]
        if redirect["quote"] and re.match(r"^\s*python3\s+-I\s+-(?:\s|$)", prefix):
            # A known stdin-Python invocation has its own syntax check. Names
            # of repo programs inside it still need explicit CLI evidence.
            try:
                ast.parse("\n".join(body), filename=f"{path}:{body_start + 1}")
            except SyntaxError as exc:
                raise ValueError(
                    f"{path}:{start + 1}: invalid inline Python heredoc: {exc}"
                ) from exc
        for number, row in enumerate(body, body_start + 1):
            first = number
            if number > body_start + 1 and lines[number - 2].endswith("\\"):
                continue
            while row.endswith("\\") and number < index:
                row = row[:-1] + " " + lines[number]
                number += 1
            yield first, row, None, len(row), (delimiter, redirect["quote"])
        index += 1


def shell_spans(text):
    """Split argv from syntax and retain raw spans for the coverage check."""
    start = 0
    for position, quote in shell_contexts(text):
        if quote is not None:
            continue
        char = text[position]
        if not (char.isspace() or char in STOP):
            continue
        if char == "(":
            raise ValueError("unquoted parenthesis in argv")
        if position > start:
            (word,) = shlex.split(text[start:position])
            yield word, start, position
        if char in STOP:
            return
        start = position + 1
    if start != len(text):
        (word,) = shlex.split(text[start:])
        yield word, start, len(text)


def word_values(word):
    if word.startswith("$(") and word.endswith(")"):
        return (
            ("2026-01-01T00:00:00Z",)
            if word.startswith("$(date ")
            else ("/stub/OUTPUT",)
        )
    matches = list(VARIABLE.finditer(word))
    if "$" in VARIABLE.sub("", word):
        raise ValueError(f"unresolved shell word {word!r}")
    variants = ("",)
    start = 0
    for match in matches:
        name = match[1] or match[2]
        values = VALUES.get(name, ("/stub/" + name.split("%")[0],))
        variants = tuple(
            left + word[start : match.start()] + value
            for left, value in product(variants, values)
        )
        start = match.end()
    return tuple(value + word[start:] for value in variants)


def expand(words, arrays, forwarded, seen=()):
    choices = []
    for word in words:
        if match := ARRAY.fullmatch(word):
            name = match[1]
            if name in seen or name not in arrays:
                raise ValueError(f"unresolved/cyclic shell array {name}")
            choices.append(
                tuple(
                    result
                    for args in arrays[name]
                    for result in expand(args, arrays, forwarded, (*seen, name))
                )
            )
        elif word == "$@":
            if not forwarded:
                raise ValueError("unresolved forwarded $@")
            choices.append(forwarded)
        else:
            choices.append(tuple((value,) for value in word_values(word)))
    return tuple(dict.fromkeys(sum(group, ()) for group in product(*choices)))


def manual_call(path, line, detail):
    try:
        target, variants, reason = UNRESOLVED[(path, line)]
    except KeyError:
        raise ValueError(f"{path}:{line}: unlisted unresolved call: {detail}") from None
    if not variants or not reason:
        raise ValueError(f"{path}:{line}: manual override lacks argv samples or reason")
    return Call(path, line, target, variants, "unresolved/sample", reason)


def shell_calls(path, source, programs, used_manual, used_forwarded):
    aliases = {}
    used_aliases = set()
    arrays = defaultdict(list)
    names = {PurePosixPath(program).name for program in programs}
    basename = re.compile(
        r"(?<![\w.-])(?:" + "|".join(map(re.escape, sorted(names))) + r")(?![\w.-])"
    )

    def unresolved(line, detail):
        if len(mentions) > 1:
            raise ValueError(
                f"{path}:{line}: multiple unresolved Python references; "
                f"split into separately inventoried calls: {detail}"
            )
        key = (path, line)
        if key in MANUAL_RECORDS:
            fingerprint = hashlib.sha256(raw.encode()).hexdigest()
            if fingerprint != MANUAL_RECORDS[key][0] or body != reviewed_body(key):
                raise ValueError(
                    f"{path}:{line}: source changed; re-audit the manual argv"
                )
        call = manual_call(path, line, detail)
        used_manual.add((path, line))
        used_aliases.update(
            match[1] or match[2]
            for match in VARIABLE.finditer(raw)
            if (match[1] or match[2]) in aliases
        )
        return call

    def alias_name(word):
        ref = VARIABLE.fullmatch(word)
        return (ref[1] or ref[2]) if ref else ""

    for line, raw, initial, safe_end, body in shell_records(path, source):
        raw_contexts = shell_lex(raw, initial)[0]
        end_quote = shell_lex(raw[:safe_end], initial)[1]
        uncertain = (
            initial is not None
            or end_quote is not None
            or "$(" in raw
            or any(
                raw[pos] == "#" and quote is not None
                for pos, quote in raw_contexts.items()
            )
        )
        text = raw if uncertain else raw[:safe_end]
        if PurePosixPath(path).name == "Makefile" or path.endswith(".mk"):
            # A simple make variable is not a shell command substitution.
            text = re.sub(r"(?<!\$)\$\(([A-Za-z_]\w*)\)", r"${\1}", text)
        contexts = shell_lex(text, initial)[0]
        mentions = {match.start(): match[0] for match in basename.finditer(text)}
        for match in VARIABLE.finditer(text):
            alias = (match[1] or match[2]).split("[", 1)[0]
            if alias in aliases:
                mentions[match.start()] = match[0]

        if (body or uncertain) and mentions:
            if body and (path, line, body, raw.strip()) in HEREDOC_PROSE:
                continue
            yield unresolved(
                line,
                (
                    "repository Python reference in heredoc body"
                    if body
                    else "repository Python reference on an ambiguous shell line"
                ),
            )
            continue
        if body or initial is not None:
            continue

        def cover(begin, end):
            for pos in tuple(mentions):
                if begin <= pos < end:
                    del mentions[pos]

        if match := ARRAY_ASSIGN.fullmatch(text):
            if mentions:
                yield unresolved(line, "repository Python reference in command array")
                continue
            name, operator, value = match.groups()
            args = tuple(shlex.split(value))
            if operator == "+=":
                arrays[name].extend(previous + args for previous in tuple(arrays[name]))
            else:
                arrays[name].append(args)
            continue
        if match := ASSIGN.fullmatch(text):
            name, value = match.groups()
            target = target_for(value.strip("\"'"), path, programs)
            if target and name not in aliases and len(mentions) == 1:
                aliases[name] = (target, line)
            elif mentions or name in aliases:
                yield unresolved(line, "ambiguous repository Python command assignment")
            continue
        for start in COMMAND_START.finditer(text):
            pos = start.start()
            if pos and (
                pos not in contexts
                or (
                    contexts[pos] is not None
                    and not (contexts[pos] == '"' and text.startswith("$(", pos))
                )
            ):
                continue
            offset = start.end()
            command = text[offset:]
            while prefix := PREFIX.match(command):
                offset += prefix.end()
                command = command[prefix.end() :]
            first = re.match(rf"({WORD}|\$\(PYTHON\))(?:\s|$)", command)
            if not first:
                continue
            word = first[1].strip("\"'")
            alias = alias_name(word)
            target = target_for(word, path, programs) or aliases.get(alias, ("", 0))[0]
            interpreter = PYTHON.fullmatch(word)
            if not interpreter and not target:
                continue
            tail = command[first.end() :]
            arg_offset = offset + first.end()
            if interpreter and re.match(r"^(?:-[IBEsS]+\s+)*(?:-c|-)(?:\s|$)", tail):
                yield Call(path, line, "interpreter", (), "not a CLI", "inline Python")
                continue
            try:
                tokens = list(shell_spans(tail))
                begin = offset + first.start(1)
                end = offset + first.end(1)
                if interpreter:
                    while tokens and re.fullmatch(r"-[IBEsSu]+", tokens[0][0]):
                        tokens.pop(0)
                    if not tokens:
                        raise ValueError("no script argument")
                    script, begin, end = tokens.pop(0)
                    begin += arg_offset
                    end += arg_offset
                    alias = alias_name(script)
                    target = (
                        target_for(script, path, programs)
                        or aliases.get(alias, ("", 0))[0]
                    )
                    if not target:
                        raise ValueError(f"unresolved script {script!r}")
                reason, forwarded = FORWARDED.get((path, line), ("", ()))
                if forwarded:
                    used_forwarded.add((path, line))
                variants = expand([token[0] for token in tokens], arrays, forwarded)
                if not variants:
                    raise ValueError("no representative argv")
            except ValueError as exc:
                yield unresolved(line, exc)
                mentions.clear()
            else:
                cover(begin, end)
                if alias in aliases:
                    used_aliases.add(alias)
                category = "unresolved/sample" if forwarded else "CLI"
                yield Call(path, line, target, variants, category, reason)
        if mentions:
            yield unresolved(
                line,
                "repository Python reference outside a resolved call: "
                + ", ".join(mentions.values()),
            )
    for alias in sorted(aliases.keys() - used_aliases):
        line = aliases[alias][1]
        yield manual_call(path, line, f"unused repository Python alias {alias}")
        used_manual.add((path, line))


def expression(node):
    """Resolve the executable/path forms commonly used in subprocess argv."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Attribute) and ast.unparse(node) == "sys.executable":
        return "python3"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return f"{expression(node.left) or '/stub'}/{expression(node.right)}"
    if isinstance(node, ast.Call) and node.args:
        name = ast.unparse(node.func)
        if name in ("str", "Path", "PurePosixPath"):
            return expression(node.args[0])
        if name.endswith(".with_name"):
            return expression(node.args[0])
        if name == "os.environ.get" and len(node.args) == 2:
            return expression(node.args[1])
    return None


def python_calls(path, source, programs, used_manual):
    tree = ast.parse(source, filename=path)
    assignments = defaultdict(list)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id].append(node.value)
    subprocess_names = {"subprocess"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            subprocess_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "subprocess"
            )
        if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            imported.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name in SUBPROCESS
            )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = ast.unparse(node.func)
        args = node.args or [
            keyword.value for keyword in node.keywords if keyword.arg == "args"
        ]
        if func in {"run_path", "runpy.run_path"} and args:
            if target := target_for(expression(args[0]) or "", path, programs):
                yield Call(path, node.lineno, target, (), "not a CLI", "module load")
            continue
        namespace, _, method = func.partition(".")
        if func not in imported and not (
            namespace in subprocess_names and method in SUBPROCESS
        ):
            continue
        if not args:
            continue
        argv = args[0]
        if isinstance(argv, ast.Name) and len(assignments[argv.id]) == 1:
            argv = assignments[argv.id][0]
        try:
            if isinstance(argv, (ast.List, ast.Tuple)) and argv.elts:
                words = [expression(item) for item in argv.elts]
            elif literal := expression(argv):
                words = shlex.split(literal)
            else:
                raise ValueError(f"dynamic subprocess argv {ast.unparse(argv)}")
            if not words or not words[0]:
                raise ValueError("dynamic subprocess executable")
            first, *words = words
            if PYTHON.fullmatch(first):
                while words and words[0] in ("-I", "-B", "-E", "-s", "-u"):
                    words.pop(0)
                if words and words[0] in ("-c", "-"):
                    yield Call(
                        path,
                        node.lineno,
                        "interpreter",
                        (),
                        "not a CLI",
                        "inline Python",
                    )
                    continue
                if not words or not words[0]:
                    raise ValueError("dynamic Python target")
                first = words.pop(0)
                if not target_for(first, path, programs):
                    raise ValueError(f"unresolved Python target {first!r}")
            target = target_for(first, path, programs)
            if target:
                if None in words:
                    raise ValueError(f"dynamic argv for {target}")
                yield Call(path, node.lineno, target, (tuple(words),))
        except ValueError as exc:
            yield manual_call(path, node.lineno, exc)
            used_manual.add((path, node.lineno))


def inventory():
    files = [
        name.decode()
        for name in subprocess.check_output(
            [
                "git",
                "--no-optional-locks",
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            cwd=ROOT,
        ).split(b"\0")
        if name
    ]
    programs = {name for name in files if name.endswith(".py")}
    found = []
    used_manual = set()
    used_forwarded = set()
    for name in sorted(set(files)):
        path = ROOT / name
        if not path.is_file():
            continue
        if name.endswith(".py"):
            # Python tests intentionally exercise rejected arguments, not shipping callers.
            if "/tests/" not in name:
                found.extend(
                    python_calls(name, path.read_text(), programs, used_manual)
                )
            continue
        if path.suffix in (".sh", ".bash", ".spec", ".mk") or path.name == "Makefile":
            scan = True
        elif not path.suffix:
            with path.open("rb") as stream:
                shebang = stream.readline(256)
            scan = shebang.startswith(b"#!") and re.search(rb"\b(?:ba)?sh\b", shebang)
        else:
            scan = False
        if scan:
            found.extend(
                shell_calls(
                    name,
                    path.read_bytes().decode(),
                    programs,
                    used_manual,
                    used_forwarded,
                )
            )
    if used_manual != UNRESOLVED.keys() or used_forwarded != FORWARDED.keys():
        raise ValueError("stale manually sampled call site")
    return found


def check_argv(target, argv):
    # These programs implement their argument check directly, without argparse.
    if target == "fedora/selinux-label.py":
        args = argv[1:] if argv[:1] == ("--verify",) else argv
        return (
            ""
            if len(args) == 3 and not any(arg.startswith("-") for arg in args)
            else ("expected [--verify] ROOT IMAGE WORKDIR (selinux-label.py:23–26)")
        )
    path = ROOT / target
    tree = ast.parse(path.read_bytes())
    if not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("parse_args", "parse_known_args")
        for node in ast.walk(tree)
    ):
        return "target has no argparse boundary; add an explicit argv check"
    parse_args = argparse.ArgumentParser.parse_args
    parse_known_args = argparse.ArgumentParser.parse_known_args

    def stop(parser, args=None, namespace=None):
        # The real parser internally calls parse_known_args (including subparsers).
        # Restore both original methods for that recursion before raising the sentinel.
        with (
            patch.object(argparse.ArgumentParser, "parse_args", parse_args),
            patch.object(argparse.ArgumentParser, "parse_known_args", parse_known_args),
        ):
            parse_args(parser, args, namespace)
        raise Parsed

    stderr = io.StringIO()
    try:
        with (
            patch.object(argparse.ArgumentParser, "parse_args", stop),
            patch.object(argparse.ArgumentParser, "parse_known_args", stop),
            patch.object(sys, "argv", [str(path), *argv]),
            patch.object(sys, "path", [str(path.parent), *sys.path]),
            patch.dict(
                sys.modules,
                {name: types.ModuleType(name) for name in ("rpm", "selinux")},
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(stderr),
        ):
            runpy.run_path(str(path), run_name="__main__")
    except Parsed:
        return ""
    except SystemExit as exc:
        message = stderr.getvalue().strip().splitlines()
        return (
            message[-1]
            if exc.code == 2 and message
            else f"exit before parse sentinel: {exc.code}"
        )
    return "program returned without reaching the parser sentinel"


def fixture_failures():
    target = "fedora/devcard-policy.py"
    folder = Path(__file__).parent / "fixtures" / "cli-calls"
    for source, diagnostic in (
        ("cat <<$dynamic\n", "unsupported heredoc delimiter"),
        ("cat <<END-PY\nEND\n", "unterminated heredoc END-PY"),
        ("cat <<END-PY\nEND-PY\r\n", "unterminated heredoc END-PY"),
    ):
        try:
            list(shell_records("<malformed heredoc fixture>", source))
        except ValueError as exc:
            if diagnostic not in str(exc):
                yield f"malformed heredoc fixture: unexpected error: {exc}"
        else:
            yield f"malformed heredoc fixture: no error for {source!r}"
    for name, expected_error, parsed_line in (
        ("case-arm.sh.fixture", "outside a resolved call", None),
        ("array-command.sh.fixture", "in command array", None),
        ("quoted-operator.sh.fixture", None, 1),
        ("quoted-comment-substitution.sh.fixture", "ambiguous shell line", None),
        ("inline-fake-heredoc.sh.fixture", None, 2),
        ("hyphenated-heredoc.sh.fixture", None, 4),
        ("unquoted-heredoc-body.sh.fixture", "in heredoc body", None),
    ):
        path = folder / name
        try:
            calls = list(
                shell_calls(
                    path.relative_to(ROOT).as_posix(),
                    path.read_bytes().decode(),
                    {target},
                    set(),
                    set(),
                )
            )
        except ValueError as exc:
            if (
                expected_error
                and "unlisted unresolved call:" in str(exc)
                and expected_error in str(exc)
            ):
                print(f"Fixture {name}: PASS (inventory rejected unresolved form)")
            else:
                yield f"fixture {name}: unexpected inventory error: {exc}"
            continue
        if expected_error:
            yield f"fixture {name}: unresolved form did not raise an inventory error"
            continue
        quoted = ("|",) if name == "quoted-operator.sh.fixture" else ()
        argv = ("passwd-sole-root", "/stub/path", *quoted, "--unexpected")
        actual = [
            (call.line, call.target, variant)
            for call in calls
            for variant in call.variants
        ]
        if actual != [(parsed_line, target, argv)]:
            yield f"fixture {name}: bad argv not inventoried as written: {actual!r}"
            continue
        message = check_argv(target, argv)
        if (
            f"unrecognized arguments: {' '.join((*quoted, '--unexpected'))}"
            not in message
        ):
            yield f"fixture {name}: real parser did not reject the full argv: {message!r}"
        else:
            print(
                f"Fixture {name}: PASS (parser rejected full argv at line {parsed_line})"
            )


def main():
    failures = list(fixture_failures())
    calls = inventory()
    counts = Counter(call.category for call in calls)
    inline = sum(call.note == "inline Python" for call in calls)
    loads = sum(call.note == "module load" for call in calls)
    cli = counts["CLI"] + counts["unresolved/sample"]
    print(f"Inventory: {cli} CLI calls, {inline} inline Python, {loads} module loads")
    if cli < MIN_CLI_CALLS or inline < MIN_INLINE_CALLS or loads < MIN_MODULE_LOADS:
        failures.append("inventory dropped below the pinned minimum")
    for call in calls:
        location = f"{call.path}:{call.line}"
        if not call.variants:
            print(f"{location}: {call.category} — {call.target} ({call.note})")
            continue
        failed = False
        for argv in call.variants:
            if message := check_argv(call.target, argv):
                failed = True
                failures.append(
                    f"{location}: {call.target} {shlex.join(argv)}: {message}"
                )
        status = "drift" if failed else "parsed OK"
        print(f"{location}: {status} — {call.target} [{len(call.variants)} argv]")
        if call.note:
            print(f"  {call.category}: {call.note}")
        for argv in call.variants:
            print(f"  {shlex.join(argv)}")
    for error in failures:
        print(f"FAIL: {error}", file=sys.stderr)
    print(
        f"Checked {sum(len(call.variants) for call in calls)} argv; {len(failures)} failure(s)"
    )
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
