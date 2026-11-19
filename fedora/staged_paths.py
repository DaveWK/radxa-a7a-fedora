# SPDX-License-Identifier: GPL-2.0-only
"""Walk plain staged paths without following symlinks."""

import os
import stat
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


def walk(directory):
    """Enumerate physical entries, never descend through a symlink."""
    yield directory
    if not stat.S_ISDIR(directory.lstat().st_mode):
        return
    for path in sorted(directory.iterdir()):
        yield from walk(path)
