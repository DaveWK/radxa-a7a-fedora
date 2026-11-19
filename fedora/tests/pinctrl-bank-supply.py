#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""pinctrl-sunxi per-bank supply bookkeeping under concurrent pin requests.

Pastes sunxi_pmx_request() and sunxi_pmx_free() of the pinctrl kmod, verbatim,
into a host model (pinctrl-bank-supply-host.c.in, next to this file) whose
threads call them the way drivers/pinctrl/pinmux.c does: serialised per pin,
not per bank. PASS means no refcount warning, no supply switched off under a
user, no handle used after its put, and nothing left behind once every pin is
free again.

--expect-race inverts the result: it is for showing that a source without the
bank lock (--source, for example the file from before the fix) loses the race
in this model. --fail-disable N makes N balanced regulator_disable calls
report an error: the driver must log each one with dev_err and still put and
clear the handle, so a later request gets a fresh regulator instead of
disabling the same one twice. A host model, not a board test.
"""

import argparse, re, subprocess, tempfile
from pathlib import Path

here = Path(__file__).resolve().parent
kmod = here.parent / "kmods/cubie-a7a-kmods/pinctrl"
p = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
)
p.add_argument("--source", type=Path, default=kmod / "pinctrl-sunxi.c")
p.add_argument("--header", type=Path, default=kmod / "pinctrl-sunxi.h")
p.add_argument("--rounds", type=int, default=20000)
p.add_argument("--runs", type=int, default=5)
p.add_argument(
    "--fail-disable",
    type=int,
    default=0,
    help="make this many balanced regulator_disable calls report an error "
    "(the driver must log each and keep the bookkeeping consistent)",
)
p.add_argument("--expect-race", action="store_true")
a = p.parse_args()
source, header = a.source.read_text(), a.header.read_text()


def function(name):
    start = source.index("static int " + name + "(")
    i = source.index("{", start)
    level, j = 1, i + 1
    while level:
        level += {"{": 1, "}": -1}.get(source[j], 0)
        j += 1
    return source[start:j]


struct = re.search(
    r"^struct sunxi_pinctrl_regulator \{.*?^\};", header, re.S | re.M
).group()
request, free = function("sunxi_pmx_request"), function("sunxi_pmx_free")
locked = "struct mutex" in struct
# The lock is only worth something if both functions take it.
assert not locked or all(
    "->lock)" in f for f in (request, free)
), "bank lock declared but not taken"
init = (
    (
        "\tfor (i = 0; i < ARRAY_SIZE(pctl.regulators); i++)\n"
        "\t\tmutex_init(&pctl.regulators[i].lock);\n"
    )
    if locked
    else ""
)
if locked:
    assert re.search(
        r"mutex_init\(&pctl->regulators\[i\]\.lock\)", source
    ), "bank locks never initialised"
c = (here / "pinctrl-bank-supply-host.c.in").read_text()
for token, text in (
    ("STRUCT_REGULATOR", struct),
    ("REQUEST", request),
    ("FREE", free),
    ("INIT_LOCKS", init),
):
    c = c.replace("@" + token + "@", text)
with tempfile.TemporaryDirectory(prefix="a7a-pinctrl-supply-") as td:
    td = Path(td)
    (td / "host.c").write_text(c)
    subprocess.run(
        [
            "gcc",
            "-std=gnu11",
            "-O2",
            "-pthread",
            "-Wall",
            "-Wextra",
            "-Wno-unused-function",
            "-Werror",
            str(td / "host.c"),
            "-o",
            str(td / "host"),
        ],
        check=True,
    )
    races, last = 0, ""
    for run in range(a.runs):
        # Two timings: tight (no sleeps in the regulator calls) and with jitter.
        argv = [str(td / "host"), str(a.rounds), str(0 if run % 2 else 3)]
        if a.fail_disable:
            argv.append(str(a.fail_disable))
        r = subprocess.run(argv, capture_output=True, text=True, timeout=600)
        assert r.returncode in (0, 1), r
        races += r.returncode
        last = r.stdout if r.returncode or not last else last
        if a.fail_disable:
            failed = re.search(r"^disable returned error +(\d+)$", r.stdout, re.M)
            logged = re.search(r"^driver dev_err calls +(\d+)$", r.stdout, re.M)
            assert failed and int(failed.group(1)) == a.fail_disable, r.stdout
            assert logged and int(logged.group(1)) == a.fail_disable, r.stdout
print(last, end="")
kind = "with the bank lock" if locked else "without a bank lock"
if a.fail_disable:
    kind += f", {a.fail_disable} disable failure(s) per run"
if a.expect_race:
    assert races, f"{a.source}: expected the race, {a.runs} runs were clean"
    print(
        f"PASS (expected) {kind}: {races}/{a.runs} runs lost the race in the host model"
    )
else:
    assert not races, f"{a.source}: {races}/{a.runs} runs lost the race"
    print(
        f"PASS {kind}: {a.runs} runs x {a.rounds} rounds clean in the host model; no board claim"
    )
