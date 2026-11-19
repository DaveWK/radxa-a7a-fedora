# SPDX-License-Identifier: GPL-2.0-only
"""Resolve POSIX paths in a staged tree without following a host symlink."""

import os
import stat
from collections import deque
from pathlib import PurePosixPath


class PathError(RuntimeError):
    """A path does not resolve to an admitted staged entry."""


def physical(root, relative, *, missing=False):
    """Check each ancestor with lstat, never following a staged symlink."""
    relative = PurePosixPath(relative)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise PathError(f"{relative}: expected a staged relative path")
    path = root
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise PathError(f"{path}: expected a real staged root directory")
    for part in relative.parts[:-1]:
        path /= part
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            if missing:
                return None
            raise
        if not stat.S_ISDIR(mode):
            raise PathError(f"{path}: expected a real staged directory")
    leaf = path / relative.name
    if missing:
        try:
            leaf.lstat()
        except FileNotFoundError:
            return None
    return leaf


def resolve(root, relative):
    relative = PurePosixPath(relative)
    if relative.is_absolute():
        raise PathError(f"{relative}: expected a staged relative path")
    parts = deque(relative.parts)
    resolved = []
    followed = 0
    while parts:
        part = parts.popleft()
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                raise PathError(f"{relative}: symlink escapes the staged root")
            resolved.pop()
            continue
        path = root.joinpath(*resolved, part)
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            name = path.relative_to(root)
            raise PathError(
                f"{relative}: staged member {name} is unavailable: {exc.strerror}"
            ) from exc
        if stat.S_ISLNK(mode):
            followed += 1
            if followed > 40:
                raise PathError(f"{relative}: symlink loop or more than 40 links")
            target = os.readlink(path)
            if target.startswith("/"):
                resolved.clear()
                target = target.lstrip("/")
            parts.extendleft(reversed(PurePosixPath(target).parts))
            continue
        if parts and not stat.S_ISDIR(mode):
            raise PathError(
                f"{relative}: staged component {path.relative_to(root)} is not a directory"
            )
        resolved.append(part)
    return root.joinpath(*resolved)


def walk(directory):
    """Enumerate physical entries, never descend through a symlink."""
    yield directory
    if not stat.S_ISDIR(directory.lstat().st_mode):
        return
    for path in sorted(directory.iterdir()):
        yield from walk(path)
