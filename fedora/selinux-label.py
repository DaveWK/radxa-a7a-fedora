#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Write SELinux file labels into an ext4 image built from a root tree.

A user namespace cannot set security.selinux on the build host, so
`mkfs.ext4 -d` produces an unlabeled root. Booted enforcing, systemd then
stays in kernel_t and freezes ("Failed to allocate manager object") before
/.autorelabel can run. This script looks up every path of ROOT in ROOT's own
targeted file_contexts (libselinux selabel, with the .subs equivalences) and
writes the labels into IMAGE with debugfs ea_set, without touching the host.

usage: selinux-label.py [--verify] ROOT IMAGE WORKDIR
"""

import errno
import os
from pathlib import Path
import subprocess
import sys

import selinux

verify = len(sys.argv) > 1 and sys.argv[1] == "--verify"
args = sys.argv[2:] if verify else sys.argv[1:]
if len(args) != 3:
    sys.exit("usage: selinux-label.py [--verify] ROOT IMAGE WORKDIR")
root, image, work = args
if not Path(image).is_file() or Path(image).is_block_device():
    sys.exit("selinux-label: IMAGE must be a regular file")
fc = os.path.join(root, "etc/selinux/targeted/contexts/files/file_contexts")
if not os.path.isfile(fc):
    sys.exit(f"selinux-label: no {fc}")
# selabel also loads file_contexts.subs and .subs_dist next to fc, and,
# unlike matchpathcon, resolves nothing against the build host's tree.
opt = selinux.selinux_opt()
opt.type = selinux.SELABEL_OPT_PATH
opt.value = fc
handle = selinux.selabel_open(selinux.SELABEL_CTX_FILE, opt, 1)
if not handle:
    sys.exit("selinux-label: target file_contexts could not be opened")

values = {}  # context -> file holding it, NUL-terminated as setfiles writes it
cmds = []
unlabeled = 0
checks = []


def value_file(ctx):
    if ctx not in values:
        path = os.path.join(work, f"ctx{len(values)}")
        with open(path, "wb") as f:
            f.write(ctx.encode() + b"\0")
        values[ctx] = path
    return values[ctx]


def debugfs_quote(path):
    # e2fsprogs v1.47.3 lib/ss/parse.c: backslashes are literal even in
    # quoted tokens; a pair of double quotes encodes one double quote.
    # Reject record delimiters so a filename can never create a command.
    if any(c in path for c in "\n\r\0"):
        sys.exit(f"selinux-label: cannot quote {path!r} for debugfs")
    return '"' + path.replace('"', '""') + '"'


def label(rel, mode):
    global unlabeled
    path = "/" + rel if rel else "/"
    quoted = debugfs_quote(path)
    try:
        _, ctx = selinux.selabel_lookup(handle, path, mode)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
        unlabeled += 1  # <<none>> entries such as /proc, /sys
        return
    if verify:
        dest = os.path.join(work, f"read{len(checks)}")
        Path(dest).unlink(missing_ok=True)
        cmds.append(f'ea_get -f {debugfs_quote(dest)} {quoted} security.selinux')
        checks.append((path, dest, ctx.encode() + b"\0"))
    else:
        cmds.append(f'ea_set -f {debugfs_quote(value_file(ctx))} {quoted} security.selinux')


os.makedirs(work, exist_ok=True)
debugfs_quote(os.path.abspath(work))


def walk_error(e):
    sys.exit(f"selinux-label: {e}")


for dirpath, dirnames, filenames in os.walk(root, onerror=walk_error):
    rel = os.path.relpath(dirpath, root)
    rel = "" if rel == "." else rel
    label(rel, os.lstat(dirpath).st_mode)
    for name in filenames + [
        d for d in dirnames if os.path.islink(os.path.join(dirpath, d))
    ]:
        p = os.path.join(dirpath, name)
        label(os.path.join(rel, name), os.lstat(p).st_mode)
    # os.walk does not descend into symlinked directories; they were labelled above.
if not os.path.lexists(os.path.join(root, "lost+found")):
    label("lost+found", 0o040700)  # made by mkfs.ext4, not in ROOT

script = os.path.join(work, "label.debugfs")
with open(script, "w") as f:
    f.write("\n".join(cmds) + "\n")
r = subprocess.run(
    ["debugfs", *([] if verify else ["-w"]), "-f", script, image], capture_output=True, text=True
)
errors = [
    line
    for line in r.stderr.splitlines()
    if line.strip() and not line.startswith("debugfs ")
]
if r.returncode or errors:
    sys.exit("selinux-label: debugfs failed:\n" + "\n".join(errors[:20]))
if verify:
    failures = [path for path, dest, expected in checks
                if not Path(dest).is_file() or Path(dest).read_bytes() != expected]
    if failures:
        sys.exit("selinux-label: wrong or missing image labels: " + ", ".join(failures[:20]))
selinux.selabel_close(handle)
print(
    f"selinux-label: {'verified' if verify else 'wrote'}: {len(cmds)} paths labelled, {unlabeled} without a label, {len(values)} contexts"
)
