# Capturing VIPLite's NPU command streams (prepared, not yet run)

Goal: record what the closed VIPLite runtime hands the A733 NPU through this
GPL driver: command buffers, NN/TP instruction descriptors, coefficient
(weight/bias) layouts, input and output tensors. Then compare that data with
what Mesa's etnaviv/Teflon emits for the same operation.

This is data capture only: no vendor binary is read or decoded, only the
buffers the runtime registers with vipcore. Everything derived from a
capture is tagged **CAPTURE-DERIVED** (see "Tagging" below).

Nothing here has run on a board yet.

## What gets captured

The capture is compiled in only with `VIPCORE_CAPTURE=1`. The packaged
module (`cubie-a7a-npu`, DKMS) is built without it and has no capture code.
A capture build creates `/sys/kernel/debug/vipcore_capture/`, disarmed:

| File | Use |
|---|---|
| `control` (0600) | write `arm [MODE [TASKS]]`, `disarm` or `free`; read the state (armed, tasks, records, bytes used, dropped) |
| `data` (0400) | the capture stream, from the file header to the last record |

While armed, for each of the next TASKS tasks (default 4) that any process
submits, the stream gets these records, in order:

| Record | When | Payload |
|---|---|---|
| `task` | before the trigger | none: task id, pid, subtask range, core range, trigger address |
| `cmd` | before the trigger | each command buffer of the submission: the init and preload buffers (flag 0x10 when linked in front of this submission), then every subtask's buffer, `used size` bytes each |
| `mem-pre` (MODE bit 0) | before the trigger | every video memory block the submitting process owns, whole, with its NPU address, size, flags, allocator and first physical segment. Each block once per arming, unless MODE bit 2 is set. Includes the command buffers, the NN/TP instruction buffers, the coefficients and the inputs |
| `mem-post` (MODE bit 1) | after the task completed successfully | the process's NPU-writable blocks again: outputs and intermediates |
| `done` | after the wait | the completion status |

The buffer is vmalloc'ed at `arm` (module parameter `capture_buf_mb`,
default 64 MiB) and freed at `free` or module unload. When it fills, records
keep their header but lose their payload (`truncated` in the manifest) and
`dropped` counts them.

Not captured: the MMU page tables (the NPU addresses in the records are
enough to resolve the command streams), registers (the existing hang dump,
`vpmdENABLE_HANG_DUMP` 2, still covers a hang), and anything the runtime
keeps in memory it never registers with vipcore.

The hooks: `task/vip_drv_task_common.c` (just before the trigger, and at the
end of `vipdrv_task_wait()`), `memory/vip_drv_video_memory.c`
(`vipdrv_mem_capture_walk()`: blocks without a kernel mapping are mapped
with the allocator's own callback for the copy and unmapped after; the CPU
cache is cleaned before a submission and invalidated after it, as the
runtime does), `os/linux/vip_drv_capture.c` (the stream and debugfs).

Side effects while armed: the submission waits for the copy (a few
milliseconds for a few MB), and memory frees by the same process wait while
a walk runs. Disarmed, a capture build only takes a mutex per task.

## Build

On the board (kernel-devel installed), or in a Fedora 45 aarch64 container
against `/usr/src/kernels/7.3.3-300.fc45.aarch64`:

    make -C /lib/modules/$(uname -r)/build M=$PWD VIPCORE_CAPTURE=1 modules

Built and checked against 7.3.3-300.fc45.aarch64 in such a container (W=1:
no warnings from the new code). The default build of the same tree still
builds and contains no capture symbols.

## Run (default DTB, i.e. vipcore bound, not the etnaviv test DTB)

1. Boot normally; the HAT service loads `sun55i_pck600` and `vipcore`.
2. Swap in the capture build (no NPU users may be running):

       rmmod vipcore
       insmod ./vipcore.ko            # the VIPCORE_CAPTURE=1 build
       cat /sys/kernel/debug/vipcore_capture/control   # armed 0

3. Capture the ShuffleNetV2 self-test, one inference:

       cd /opt/viplite/vpm_run
       capture/npu-capture.sh -l shufflenetv2-l1 -- \
           ./vpm_run -s sample.txt -l 1 -b 0 --show_top5 1

   then a second run with `-m 7 -n 8 -l shufflenetv2-l3` and `-l 3` loops,
   to see what changes between inferences.
4. Restore: `rmmod vipcore; modprobe vipcore` (or reboot).
5. Copy the run directory to the PC and split it:

       capture/npu-capture-split.py capture.bin split/ --label shufflenetv2-l1

## Where it goes

`/var/lib/cubie-a7a/npu-captures/<UTC time>-<label>/` on the board (the
runner's default; `-o` or `$NPU_CAPTURE_DIR` changes it), copied from there
to the PC. Never into git: captures hold the vendor NBG's weights and
command streams. Each run directory has `capture.bin`, `command.txt`,
`run.log`, `control-before.txt`, `control-after.txt`, `dmesg.txt`,
`vip_info.txt`, `CAPTURE-DERIVED` and `SHA256SUMS`. `split/` adds
`manifest.json`, `cmd/`, `mem/pre/`, `mem/post/`, `decode/task-*.txt` (the
command buffers as Vivante front-end commands, with the state names from
Mesa's public rnndb headers) and `decode/nn/`, `decode/tp/` (256 bytes at
each NN/TP instruction address the streams load), plus its own
`SHA256SUMS`.

## Size

ShuffleNetV2 1.0x has about 2.3 M parameters, so about 2.3 MB of uint8
weights before the NBG's compression. The self-test's command buffer is
0xbf0 bytes (`cmd size=0xbf0` in its log). Estimated per run
directory, one inference (`-m 3 -n 4`):

| Part | Estimate |
|---|---|
| command buffers | < 64 KiB |
| NN/TP instructions | 50-200 KiB (about 100-250 operations, 64-256 bytes each) |
| coefficients | 1.5-3 MB |
| input + output | 150 KiB + 1 KiB |
| activation pool / scratch | 1-4 MB, in `mem-pre` and again in `mem-post` |
| total `capture.bin` | about 5-12 MB, well inside the 64 MiB buffer |

With `-m 7 -n 8` every task repeats the whole snapshot: about 8 x that,
so raise `capture_buf_mb` to 128 for it. Split output is about 1.1 x the
capture.

## Tagging (CAPTURE-DERIVED)

- Every run directory and split directory carries a `CAPTURE-DERIVED` file
  stating what it is and the capture's sha256.
- Any note, table, constant or code written from a capture says
  `CAPTURE-DERIVED` and names the capture by its sha256 and label, e.g. a
  descriptor bit meaning in a Mesa patch comment, a commit message line, or
  a row in a findings file. Values seen only in a capture are not presented
  as documented.
- A list of capture sets kept beside them names, per set: the files, their
  sha256, and the source as "vipcore VIPCORE_CAPTURE=1 capture of the closed
  VIPLite 2.0.3 runtime running <model>, <date>". Captures are not
  published.

## What to do with it

1. Find the NN instruction for each ShuffleNetV2 layer in `decode/nn/` and
   line it up with Mesa's `struct etna_nn_params` field by field
   (`src/gallium/drivers/etnaviv/etnaviv_ml_nn.c`); look first at the
   fields the A733 adds over the T527 (native stride-2, NN transpose, the
   stream processor, ZRL_8BIT 0, 32 lanes per output cycle).
2. Compare the coefficient stream layout with Mesa's v8 encoder output for
   the same convolution (`ETNA_MESA_DEBUG=dump_shaders` writes Mesa's
   side).
3. Compare the GL_NN_CONFIG / OCB / semaphore sequence around each
   instruction with Mesa's `etna_ml_emit_operation_nn()`.
