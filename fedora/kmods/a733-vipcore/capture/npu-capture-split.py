#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Split a vipcore command-stream capture into files (see ../CAPTURE.md).

    python3 npu-capture-split.py CAPTURE.bin OUT_DIR [--label TEXT]

CAPTURE.bin is /sys/kernel/debug/vipcore_capture/data from a vipcore built
with VIPCORE_CAPTURE=1. OUT_DIR gets:

    CAPTURE-DERIVED          the provenance stamp (every file here is data
                             captured from the closed VIPLite runtime)
    manifest.json            every record's header, and where its payload went
    cmd/                     command buffers as submitted
    mem/pre/, mem/post/      video memory blocks before the trigger and the
                             NPU-writable blocks after completion
    decode/task-*.txt        the command buffers decoded as Vivante FE
                             commands (opcodes and state names from Mesa's
                             public etnaviv rnndb headers), with the NN/TP
                             instruction addresses they load
    decode/nn/, decode/tp/   256 bytes at each NN/TP instruction address,
                             cut from the captured memory
    SHA256SUMS

Python standard library only; reads the capture as data, runs nothing.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

FILE_HDR = struct.Struct("<8sIIIIIIQ")  # 40 bytes
REC = struct.Struct("<IHHIIQ10IiIQQQQ16s")  # 120 bytes
REC_MAGIC = 0x31434552
TYPES = {1: "task", 2: "cmd", 3: "mem-pre", 4: "mem-post", 5: "done"}
CMD_KINDS = {0: "subtask", 1: "init", 2: "preload"}
F_UNMAPPED, F_TRUNCATED = 0x0100, 0x0200
REC_FIELDS = (
    "magic type flags seq task_id time_ns pid sub subtask_index "
    "subtask_count core_index core_cnt mem_id mem_flag allocator_type "
    "physical_num status reserved vip_address physical0 size "
    "payload_size name"
).split()

# Vivante front-end opcodes and the states the NN/TP path uses (Mesa
# src/etnaviv/hw/cmdstream.xml.h, state.xml.h, state_3d.xml.h; MIT).
FE_OPS = {
    1: "LOAD_STATE",
    2: "END",
    3: "NOP",
    7: "WAIT",
    8: "LINK",
    9: "STALL",
    10: "CALL",
    11: "RETURN",
    13: "CHIP_SELECT",
    15: "WAIT_FENCE",
    19: "SNAP_PAGES",
}
STATES = {
    0x3804: "GL_EVENT",
    0x3808: "GL_SEMAPHORE_TOKEN",
    0x380C: "GL_FLUSH_CACHE",
    0x384C: "GL_API_MODE",
    0x3850: "GL_CONTEXT_POINTER",
    0x3930: "GL_NN_CONFIG",
    0x393C: "GL_OCB_REMAP_START",
    0x3940: "GL_OCB_REMAP_END",
    0x3950: "GL_UNK03950",
    0x3A00: "GL_UNK03A00",
    0x3C00: "GL_STALL_TOKEN",
    0x10A0: "PS_NN_INST_ADDR",
    0x10A4: "PS_UNK10A4",
    0x10B8: "PS_TP_INST_ADDR",
}
INST_STATES = {0x10A0: "nn", 0x10B8: "tp"}
DESC_BYTES = 256


def records(data):
    magic, version, hsize, rsize, mode, max_tasks, _, arm_ns = FILE_HDR.unpack_from(
        data, 0
    )
    if (
        magic != b"A7NPUCAP"
        or version != 1
        or rsize != REC.size
        or hsize != FILE_HDR.size
    ):
        sys.exit("npu-capture-split: not a version 1 vipcore capture")
    header = {
        "version": version,
        "mode": mode,
        "max_tasks": max_tasks,
        "arm_time_ns": arm_ns,
    }
    off = hsize
    out = []
    while off + REC.size <= len(data):
        rec = dict(zip(REC_FIELDS, REC.unpack_from(data, off)))
        if rec["magic"] != REC_MAGIC:
            sys.exit(f"npu-capture-split: bad record magic at offset {off:#x}")
        rec["name"] = rec["name"].split(b"\0")[0].decode("ascii", "replace")
        start = off + REC.size
        payload = data[start : start + rec["payload_size"]]
        off = start + (rec["payload_size"] + 7) // 8 * 8
        out.append((rec, payload))
    return header, out


class Memory:
    """NPU address -> bytes, from the captured blocks (post wins over pre)."""

    def __init__(self):
        self.blocks = []

    def add(self, va, payload):
        if payload:
            self.blocks.append((va, payload))

    def read(self, va, size):
        for base, blob in reversed(self.blocks):
            if base <= va < base + len(blob):
                return blob[va - base : va - base + size]
        return None


def decode(words, base, mem, out, task, inst_dir):
    lines, i, n = [], 0, len(words)
    while i < n:
        w = words[i]
        op = w >> 27
        name = FE_OPS.get(op, f"OP{op}")
        addr = base + 4 * i
        if op == 1:
            count = (w >> 16) & 0x3FF or 1024
            state = (w & 0xFFFF) << 2
            vals = words[i + 1 : i + 1 + count]
            for k, v in enumerate(vals):
                s = state + 4 * k
                lines.append(
                    f"{addr:#010x}  LOAD_STATE {STATES.get(s, f'{s:#06x}')} = {v:#010x}"
                )
                kind = INST_STATES.get(s)
                if kind and v:
                    va = v & ~0x3F
                    blob = mem.read(va, DESC_BYTES)
                    if blob:
                        fn = os.path.join(
                            inst_dir, kind, f"task{task:08x}-{va:#010x}.bin"
                        )
                        os.makedirs(os.path.dirname(fn), exist_ok=True)
                        with open(fn, "wb") as f:
                            f.write(blob)
                        lines.append(
                            f"            -> {kind} instruction at {va:#010x}: {os.path.relpath(fn, out)}"
                        )
                    else:
                        lines.append(
                            f"            -> {kind} instruction at {va:#010x}: not in the capture"
                        )
            i += 1 + count
            i += i % 2  # commands are 64-bit aligned
        elif op in (7, 8, 10):
            arg = words[i + 1] if i + 1 < n else 0
            lines.append(f"{addr:#010x}  {name} {w & 0xFFFF:#x} -> {arg:#010x}")
            i += 2
        else:
            arg = words[i + 1] if i + 1 < n else 0
            lines.append(f"{addr:#010x}  {name} {w:#010x} {arg:#010x}")
            i += 2
    return lines


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("capture")
    ap.add_argument("out_dir")
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    with open(args.capture, "rb") as f:
        data = f.read()
    header, recs = records(data)
    out = args.out_dir
    if os.path.exists(out) and os.listdir(out):
        sys.exit(f"npu-capture-split: {out} is not empty")
    os.makedirs(out, exist_ok=True)

    mem = Memory()
    manifest = {
        "capture": os.path.basename(args.capture),
        "capture_sha256": hashlib.sha256(data).hexdigest(),
        "label": args.label,
        "tag": "CAPTURE-DERIVED",
        "header": header,
        "records": [],
    }
    cmds = {}
    for rec, payload in recs:
        kind = TYPES.get(rec["type"], str(rec["type"]))
        entry = {k: rec[k] for k in REC_FIELDS if k not in ("magic", "reserved")}
        entry["type"] = kind
        fn = None
        if kind == "cmd" and payload:
            ck = CMD_KINDS.get(rec["flags"] & 0xF, "cmd")
            fn = f"cmd/task{rec['task_id']:08x}-{rec['seq']:05d}-{ck}{rec['sub']}.bin"
            cmds.setdefault(rec["task_id"], []).append((rec, payload))
        elif kind in ("mem-pre", "mem-post") and payload:
            sub = "pre" if kind == "mem-pre" else "post"
            fn = (
                f"mem/{sub}/task{rec['task_id']:08x}-{rec['seq']:05d}-"
                f"id{rec['mem_id']:08x}-va{rec['vip_address']:010x}.bin"
            )
            mem.add(rec["vip_address"], payload)
        if fn:
            path = os.path.join(out, fn)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(payload)
            entry["file"] = fn
        entry["unmapped"] = bool(rec["flags"] & F_UNMAPPED)
        entry["truncated"] = bool(rec["flags"] & F_TRUNCATED)
        manifest["records"].append(entry)

    for task, bufs in cmds.items():
        lines = []
        for rec, payload in bufs:
            ck = CMD_KINDS.get(rec["flags"] & 0xF, "cmd")
            linked = " (linked in front)" if rec["flags"] & 0x10 else ""
            lines.append(
                f"# {ck}{rec['sub']} at {rec['vip_address']:#010x}, {rec['size']} bytes{linked}"
            )
            words = struct.unpack_from(f"<{len(payload) // 4}I", payload)
            lines += decode(
                words, rec["vip_address"], mem, out, task, os.path.join(out, "decode")
            )
        path = os.path.join(out, "decode", f"task-{task:08x}.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(
                "CAPTURE-DERIVED: decoded from a capture of the closed VIPLite runtime\n"
            )
            f.write("\n".join(lines) + "\n")

    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    with open(os.path.join(out, "CAPTURE-DERIVED"), "w") as f:
        f.write(
            "CAPTURE-DERIVED: data captured through the GPL vipcore driver while the\n"
            "closed VIPLite runtime ran (vipcore VIPCORE_CAPTURE=1, CAPTURE.md).\n"
            "Data capture only. Anything written from it must carry\n"
            "the CAPTURE-DERIVED tag. Not for git.\n"
            f"capture sha256 {manifest['capture_sha256']}\n"
        )
    sums = []
    for root, _, files in os.walk(out):
        for name in sorted(files):
            p = os.path.join(root, name)
            rel = os.path.relpath(p, out)
            if rel == "SHA256SUMS":
                continue
            with open(p, "rb") as f:
                sums.append(f"{hashlib.sha256(f.read()).hexdigest()}  {rel}")
    with open(os.path.join(out, "SHA256SUMS"), "w") as f:
        f.write("\n".join(sorted(sums, key=lambda s: s[66:])) + "\n")
    n = {
        t: sum(1 for e in manifest["records"] if e["type"] == t) for t in TYPES.values()
    }
    print(f"npu-capture-split: {len(recs)} records {n} -> {out}")


if __name__ == "__main__":
    main()
