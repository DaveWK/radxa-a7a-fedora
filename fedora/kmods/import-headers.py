#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Copy one kernel series' internal header sets into cubie-a7a-kmods.

dwmac-sun55i and the A733 PCIe glue include kernel-internal headers
(drivers/net/ethernet/stmicro/stmmac/*.h, drivers/pci/pci.h and
drivers/pci/controller/dwc/pcie-designware.h). Those carry struct layouts
and prototypes that change between kernel series, and kernel-devel does not
ship them, so cubie-a7a-kmods keeps one set per series it builds for:

  stmmac/k<SERIES>/*.h
  pcie/k<SERIES>/pci-internal.h      (drivers/pci/pci.h, byte-identical)
  pcie/k<SERIES>/pcie-designware.h   (its "../../pci.h" include relocated)

The Makefile adds the set's directory for the series dkms.conf names
(CUBIE_SERIES). The headers must come from the source of the kernel the
modules load into: Fedora's signed kernel SRPM, linux-<version> with
patch-<version>-redhat.patch applied.

Usage: import-headers.py SERIES FEDORA_TREE OUT_DIR
  SERIES       e.g. 7.4
  FEDORA_TREE  the patched Fedora kernel source tree
  OUT_DIR      fedora/kmods/cubie-a7a-kmods

Writes HEADERS-k<SERIES>.sha256 in OUT_DIR: destination, origin path and the
sha256 of each origin file. Record the SRPM and its sha256 in PROVENANCE.
"""

import hashlib
import os
import re
import sys

series, tree, out = sys.argv[1], os.path.abspath(sys.argv[2]), os.path.abspath(sys.argv[3])
assert re.fullmatch(r"[0-9]+\.[0-9]+", series), series
copied = []


def copy(path, dest, transform=None):
    data = open(os.path.join(tree, path), "rb").read()
    text = data.decode()
    if transform:
        text = transform(text)
    dst = os.path.join(out, dest)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    open(dst, "w").write(text)
    copied.append((dest, path, hashlib.sha256(data).hexdigest()))


def relocate_pci_h(text):
    text, n = re.subn(r'#include "\.\./\.\./pci\.h"', '#include "pci-internal.h"', text)
    assert n == 1, "pcie-designware.h: expected one ../../pci.h include"
    return text


for sub in ("stmmac", "pcie"):
    d = os.path.join(out, sub, "k" + series)
    if os.path.isdir(d):
        for name in os.listdir(d):
            os.unlink(os.path.join(d, name))

st = "drivers/net/ethernet/stmicro/stmmac/"
for name in sorted(os.listdir(os.path.join(tree, st))):
    if name.endswith(".h"):
        copy(st + name, f"stmmac/k{series}/{name}")
copy("drivers/pci/pci.h", f"pcie/k{series}/pci-internal.h")
copy(
    "drivers/pci/controller/dwc/pcie-designware.h",
    f"pcie/k{series}/pcie-designware.h",
    relocate_pci_h,
)

with open(os.path.join(out, f"HEADERS-k{series}.sha256"), "w") as f:
    f.write("# dest  origin path  sha256-of-origin-file\n")
    for dest, path, h in sorted(copied):
        f.write(f"{dest}  {path}  {h}\n")
print(f"{len(copied)} headers -> {out} (series {series})")
