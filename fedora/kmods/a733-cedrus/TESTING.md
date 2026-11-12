# a733-cedrus: first tests on the board

Nothing in this directory has run on hardware. The module compiles and
passes modpost for 7.3.3-300.fc45.aarch64; every register, clock and
power-domain assumption below is read from sources. All of this is
headless (ssh or serial).

## Before booting

1. Device tree: include `fedora/dts/cubie-a7a-video-codec.dtsi` from the
   board `.dts`, set `&video_codec { status = "okay"; };`, bump
   `DTB_VERSION`.
2. CMA: Fedora's default pool is 64 MiB (`CONFIG_CMA_SIZE_MBYTES=64`),
   too small for 1080p H.264 (16 reference frames plus bitstream and
   motion-vector buffers). Boot with `cma=256M` (4K: `cma=512M`):
   `grubby --update-kernel=ALL --args=cma=256M`. The decoder takes 32-bit
   addresses and has no IOMMU here, so the pool must lie below 4 GiB; the
   arm64 default placement does that. Check `grep -i cma /proc/meminfo` and
   the `cma: Reserved` line in `dmesg`.
3. Packages: `dkms kernel-devel` (module build), `v4l-utils` (`v4l2-ctl`,
   `media-ctl`), `gstreamer1-plugins-base`, `gstreamer1-plugins-good`,
   `gstreamer1-plugins-bad-free` (`v4l2codecs`: `v4l2slh264dec`,
   `v4l2slmpeg2dec`; `h264parse`, `mpegvideoparse`), `gstreamer1-plugin-libav`
   and/or `gstreamer1-plugin-openh264` (software H.264 reference; openh264
   comes from the fedora-cisco-openh264 repository),
   `gstreamer1-plugins-ugly-free` (`mpeg2dec`, software MPEG-2 reference),
   `git python3` (fluster). Confirm each element with `gst-inspect-1.0
   <name>` before relying on it; the list was not checked on an installed
   system.

## Sequence

Stop at the first step that fails and collect the items under "If it goes
wrong".

1. Load and probe.
   `modprobe a733-cedrus; dmesg | grep -i -e cedrus -e 1c0e000`
   Expected: `Device registered as /dev/videoN`, no `Failed to …` line, no
   `No system control registers` warning.
2. Identity and formats.
   `v4l2-ctl --list-devices` (card `a733-cedrus`)
   `v4l2-ctl -d /dev/videoN --all`
   `v4l2-ctl -d /dev/videoN --list-formats-out` (MPEG-2 and H.264 slice
   formats only, unless built with `A733_CEDRUS_EXPERIMENTAL=1`)
   `v4l2-ctl -d /dev/videoN --list-formats` (NV12 among them)
   `media-ctl -d /dev/mediaM -p` (model `a733-cedrus`, one decoder entity
   with source and sink)
3. Power and clocks while idle, then while decoding (step 4 in a second
   shell): `/sys/kernel/debug/pm_genpd/pm_genpd_summary` (VE_DEC),
   `grep -e ve-dec -e pll-ve0 /sys/kernel/debug/clk/clk_summary`
   (ve-dec0 at 624000000 under pll-ve0 while streaming).
4. H.264, small first (a 320x240 or 720p Baseline/Main clip, 8-bit 4:2:0):
   ```
   gst-launch-1.0 -e filesrc location=clip.mp4 ! qtdemux ! h264parse ! \
     v4l2slh264dec ! videoconvert ! video/x-raw,format=I420 ! \
     filesink location=hw.yuv
   gst-launch-1.0 -e filesrc location=clip.mp4 ! qtdemux ! h264parse ! \
     avdec_h264 ! videoconvert ! video/x-raw,format=I420 ! \
     filesink location=sw.yuv        # or openh264dec
   md5sum hw.yuv sw.yuv; ls -l hw.yuv sw.yuv
   ```
   The two files must have the same size and md5 (H.264 decoding is
   bit-exact). Watch `dmesg -w` for `frame processing timed out!` and
   `grep -i 1c0e000 /proc/interrupts` for the count rising by about one per
   frame. Then repeat with 1080p, with interlaced and with High-profile
   clips.
5. MPEG-2: the same with `mpegvideoparse ! v4l2slmpeg2dec` against
   `mpeg2dec` (or `avdec_mpeg2video`), from an MPEG-PS/TS clip through
   `mpegpsdemux`/`tsdemux`.
6. Conformance:
   ```
   git clone https://github.com/fluendo/fluster && cd fluster
   ./fluster.py list            # find the V4L2SL decoders gst exposes
   ./fluster.py download JVT-AVC_V1
   ./fluster.py run -d GStreamer-H.264-V4L2SL-Gst1.0 -ts JVT-AVC_V1 -s
   ```
   Keep the summary table. Mainline cedrus does not pass every vector on
   other SoCs either; compare against a published cedrus result rather
   than against 100 %. Use the MPEG-2 suite and decoder names `list` prints,
   if any.
7. Only after 4 to 6 pass: rebuild with
   `make A733_CEDRUS_EXPERIMENTAL=1` and repeat with `v4l2slh265dec`
   (8-bit, then 10-bit) and `v4l2slvp8dec`, fluster `JCT-VC-HEVC_V1` and
   `VP8-TEST-VECTORS`.
8. Unload and reload: `rmmod a733_cedrus; modprobe a733-cedrus`, step 4
   again.

## If it goes wrong

Record, per failing step: the exact command, full `dmesg`, `uname -r`, the
module's `modinfo`, `v4l2-ctl --all`, the two debugfs summaries of step 3,
the `/proc/interrupts` line before and after, `/proc/meminfo` CMA lines,
and for wrong pictures the first differing frame (`cmp hw.yuv sw.yuv`,
frame size = width x height x 3 / 2) plus both files for a short clip.

What the symptom points at:

- Probe fails on a clock, reset or power domain: the node against the CCU
  and PCK-600 modules (are they loaded before this one).
- `frame processing timed out!` and no interrupts: the block is not
  clocked or powered, the SRAM handover did not take, or the decoder
  cannot reach memory (IOMMU not passing the VE master through, MBUS gate
  off). Interrupts arriving but every frame failing: a status bit meaning
  an error, i.e. register or bitstream-address differences.
- Decode completes, output is garbage or all zero/green: buffer addresses
  (IOMMU, >4 GiB memory), the untiled output registers, or the SRAM.
- Output right for I frames only: reference or motion-vector buffer setup.
- Other devices (display, GPU, NPU, storage) misbehave once decoding
  starts: the AHB/MBUS master-gate registers (0x5c0, 0x5e0, 0x5e4). The
  vendor CCU treats them as keyed and their bits as not reading back; our
  CCU does a plain read-modify-write. Remove "ahb-gate" and "mbus-gate"
  from the node as the one-variable test.

Register reads are a last resort, one named 32-bit register per call and
never a window (bulk reads have hung this board), with the block powered
(while a decode is running or hung): system control 0x03000000 (bit 0) and
0x03000004 (bit 24), expected clear; VE 0x01c0e000 (mode), 0x01c0e0f0
(version, upper 16 bits), 0x01c0e228 (H.264 status), 0x01c0e804 (top
reset, bits 0 and 4 expected clear). Record the version value in any case:
it is the first hard evidence of which Cedar generation this block is.

## Codec selection at load time (cubie-a7a-vdec)

The packaged module (cubie-a7a-vdec, DKMS) has every codec built in. Which
ones the device offers is chosen when it loads; `dmesg` prints
`codecs offered: ...; built in, hidden: ...` at probe.

| Parameter | Default | Codec |
|-----------|---------|-------|
| `mpeg2`   | 1 | MPEG-2 |
| `h264`    | 1 | H.264 |
| `hevc`    | 1 | H.265 8 bit |
| `vp8`     | 1 | VP8 |
| `hevc10`  | 0 | H.265 10 bit, output as 8-bit NV12 (needs `hevc=1`) |
| `vp9`     | 0 | VP9 (`../a733-cedrus-vp9`) |
| `jpeg`    | 0 | second video node for baseline JPEG (`../a733-cedrus-jpeg`) |

For the one-codec-at-a-time order of this file and of the codec notes,
reload with only the codec under test, e.g.
`modprobe -r a733-cedrus; modprobe a733-cedrus mpeg2=0 hevc=0 vp8=0`
(H.264 only), and set lasting choices in
`/etc/modprobe.d/a733-cedrus.conf` (`options a733-cedrus vp9=1`). The
build switches of the Makefile (`A733_CEDRUS_*=0`) still leave a codec out
of the module altogether.
