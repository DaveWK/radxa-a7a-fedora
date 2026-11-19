#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Static checks for TMPDIR at the image/build root boundary."""

import ast
from pathlib import Path
import re
import unittest

FEDORA = Path(__file__).resolve().parent.parent
WRAPPER = ("env", "-u", "TMPDIR")
CHROOT = re.compile(r"(?<![\w/-])(?:/[^\s'\";()]+/)?chroot(?=\s)")
INSTALLROOT = re.compile(r"(?<![\w-])--installroot(?=[=\s]|$)")
DNF = re.compile(r"(?<![\w/-])(?:/[^\s'\";()]+/)?(?:dnf5?|microdnf)(?=\s)")
SHELL_WRAPPER = re.compile(r"(?:^|[\s(])env\s+-u\s+TMPDIR\s+$")


def shell_calls(path):
    first = 1
    command = ""
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not command:
            first = number
            if line.lstrip().startswith("#"):
                continue
        if line.endswith("\\"):
            command += line[:-1] + " "
            continue
        command += line.split(" #", 1)[0]
        for call in CHROOT.finditer(command):
            yield first, SHELL_WRAPPER.search(command[: call.start()]) is not None
        for flag in INSTALLROOT.finditer(command):
            dnf = next(reversed(list(DNF.finditer(command[: flag.start()]))), None)
            yield first, dnf is not None and (
                SHELL_WRAPPER.search(command[: dnf.start()]) is not None
            )
        command = ""


def python_calls(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    argv = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            elements = node.args
        elif isinstance(node, (ast.List, ast.Tuple)):
            elements = node.elts
        else:
            continue
        for index, element in enumerate(elements):
            argv[element] = elements[:index]
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            if not node.values:
                continue
            flag = node.values[0]
        elif isinstance(node, ast.Constant):
            if node not in argv:
                continue
            flag = node
        else:
            continue
        if (
            not isinstance(flag, ast.Constant)
            or not isinstance(flag.value, str)
            or not INSTALLROOT.match(flag.value)
        ):
            continue
        prefix = [
            element.value if isinstance(element, ast.Constant) else None
            for element in argv.get(node, [])
        ]
        yield node.lineno, any(
            tuple(prefix[i : i + 3]) == WRAPPER
            and prefix[i + 3] in ("dnf", "dnf5", "microdnf")
            for i in range(len(prefix) - 3)
        )


class RootBoundaryTests(unittest.TestCase):
    def test_root_calls_clear_tmpdir(self):
        missing = []
        for path in sorted(FEDORA.rglob("*")):
            if path == Path(__file__).resolve() or not path.is_file():
                continue
            if path.suffix == ".py":
                calls = python_calls(path)
            elif path.suffix in (".sh", ".bash", ".spec"):
                calls = shell_calls(path)
            elif not path.suffix:
                with path.open("rb") as stream:
                    shebang = stream.readline(256)
                if not shebang.startswith(b"#!") or not re.search(
                    rb"\b(?:ba)?sh\b", shebang
                ):
                    continue
                calls = shell_calls(path)
            else:
                continue
            missing.extend(
                f"{path.relative_to(FEDORA)}:{line}"
                for line, wrapped in calls
                if not wrapped
            )
        self.assertFalse(missing, "missing env -u TMPDIR:\n" + "\n".join(missing))

    def test_rpm_preflight(self):
        source = (FEDORA / "mkdevcard.sh").read_text()
        self.assertIn(
            "python3 -I -c 'import selinux' 2>/dev/null || die "
            '"python3-libselinux not found"\n'
            "python3 -I -c 'import rpm' 2>/dev/null || die "
            '"python3-rpm not found"\n',
            source,
        )


if __name__ == "__main__":
    unittest.main()
