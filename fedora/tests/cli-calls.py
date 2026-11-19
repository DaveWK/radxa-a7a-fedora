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
# An unresolved target/argv must have a location, explanation and explicit samples.
# The live scan fails on unlisted or stale overrides.
UNRESOLVED = {}

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


def logical_lines(source):
    """Keep the first physical line number while joining shell continuations."""
    text = ""
    for number, line in enumerate(source.splitlines(), 1):
        if not text:
            start = number
            if line.lstrip().startswith("#"):
                continue
        if line.endswith("\\"):
            text += line[:-1] + " "
            continue
        yield start, text + line
        text = ""
    if text:
        yield start, text


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


def shell_contexts(text):
    """Quote state at each unescaped character, before shlex removes quotes."""
    quote = None
    escaped = False
    for position, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        yield position, quote
        if char == "\\" and quote != "'":
            escaped = True
        elif char == quote:
            quote = None
        elif quote is None and char in "\"'":
            quote = char


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
    heredoc_end = None
    spec_prose = False
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
        call = manual_call(path, line, detail)
        used_manual.add((path, line))
        return call

    def alias_name(word):
        ref = VARIABLE.fullmatch(word)
        return (ref[1] or ref[2]) if ref else ""

    for line, text in logical_lines(source):
        if heredoc_end:
            if text.strip() == heredoc_end:
                heredoc_end = None
            continue
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
        if PurePosixPath(path).name == "Makefile" or path.endswith(".mk"):
            # A simple make variable is not a shell command substitution.
            text = re.sub(r"(?<!\$)\$\(([A-Za-z_]\w*)\)", r"${\1}", text)
        contexts = dict(shell_contexts(text))
        for pos, quote in contexts.items():
            if (
                text[pos] == "#"
                and quote is None
                and (pos == 0 or text[pos - 1].isspace() or text[pos - 1] in STOP)
            ):
                text = text[:pos]
                break
        mentions = {match.start(): match[0] for match in basename.finditer(text)}
        for match in VARIABLE.finditer(text):
            alias = (match[1] or match[2]).split("[", 1)[0]
            if alias in aliases:
                mentions[match.start()] = match[0]

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
                if marker := re.search(r"<<-?\s*['\"]?(\w+)", tail):
                    heredoc_end = marker[1]
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
                    name, path.read_text(), programs, used_manual, used_forwarded
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
    for name, fails_in_inventory in (
        ("case-arm.sh.fixture", True),
        ("array-command.sh.fixture", True),
        ("quoted-operator.sh.fixture", False),
    ):
        path = folder / name
        try:
            calls = list(
                shell_calls(
                    path.relative_to(ROOT).as_posix(),
                    path.read_text(),
                    {target},
                    set(),
                    set(),
                )
            )
        except ValueError as exc:
            if fails_in_inventory and "unlisted unresolved call:" in str(exc):
                print(f"Fixture {name}: PASS (inventory rejected unresolved form)")
            else:
                yield f"fixture {name}: unexpected inventory error: {exc}"
            continue
        if fails_in_inventory:
            yield f"fixture {name}: unresolved form did not raise an inventory error"
            continue
        argv = ("passwd-sole-root", "/stub/path", "|", "--unexpected")
        actual = [(call.target, variant) for call in calls for variant in call.variants]
        if actual != [(target, argv)]:
            yield f"fixture {name}: quoted operator or trailing option lost: {actual!r}"
            continue
        message = check_argv(target, argv)
        if "unrecognized arguments: | --unexpected" not in message:
            yield f"fixture {name}: real parser did not reject the full argv: {message!r}"
        else:
            print(f"Fixture {name}: PASS (parser rejected | --unexpected)")


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
