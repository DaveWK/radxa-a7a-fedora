# NPU at 852 MHz (opt-in, untested)

`fedora/dts/cubie-a7a-npu-852m.dtsi` asks for 852 MHz instead of 492 MHz.
`platform_a733.c` grants it only when the chip's speed bin lists 852 MHz at
the rail's voltage; otherwise the clock stays at 492 MHz and the log says
why. The board DTS does not include the dtsi. Nothing here has run on a
board, and one item below (the PLL factors) must be settled on the board at
492 MHz before 852 MHz is tried.

Sources: **V** = `src/radxa-allwinner-bsp` (radxa/allwinner-bsp c83016d2),
**A** = `src/allwinner-bsp` (alexcaoys/allwinner-bsp 656a550c), **T** =
radxa/allwinner-bsp 2045a3ca, **CAP** = the vendor 6.6.98 capture of this
board (register captures of the vendor image, not included).

## Evidence

Voltage for each rate, from V `configs/linux-6.6/sun60iw2p1-cpu-vf.dtsi`
(`npu-opp-table`, `:2036-2139`; the capture's `sys/live.dts` agrees for 492
and 852 MHz). Where the 24 MHz and 26 MHz columns differ the higher is used.

| Bin (code) | 492 MHz `:2039-2067` | 852 MHz `:2069-2091` | At 800 mV |
|---|---|---|---|
| vf0000 (0x00) | 800 mV | 800 mV | 852 MHz |
| vf0200 (0x02), vf0201 (0x12) | 800 mV | 800 mV | 852 MHz |
| vf0400 (0x04), vf0500 (0x05), vf0501 (0x15) | 800 mV | 800 mV | 852 MHz |
| vf0401 (0x14) | 800 mV | 820 mV | 492 MHz |
| vf0300 (0x03) | 800 mV | no entry | 492 MHz |
| vf0100, vf0101, vf0600 (0x01, 0x11, 0x06) | no entry | no entry | 492 MHz |
| vf0202-vf0206 (880 mV or no entry) | 800 mV | - | no code maps to them |

| Fact | Source |
|---|---|
| Code to bin: `vf_mapping_table` | V `sun60iw2p1-cpu-vf.dtsi:3-17` |
| Code = efuse 0x4c bits 23:16 (`dvfs_bak`) if non-zero, else bits 15:8 (`dvfs_ori`) | V `sun60iw2p1.dtsi:1439-1448`; T `drivers/sid/sunxi-sid.c:604-625` |
| The vendor NPU driver does not read the bin on this SoC: it always uses vf0000 | T `drivers/npu/.../allwinner/vip_drv_device_platform.c:513-523`; CAP `20261007-regs/sw/dmesg.txt:669, 680` |
| Vendor image on this board: 1008 MHz at 800 mV, because its 960 mV request failed. Not a reference. | CAP `dmesg.txt:676-684` |
| NPU rail is DCDC2, shared with HDMI | CAP `sys/dbg-regulator_regulator_summary.txt:38-41` |
| DCDC2 fixed at 800 mV in our DT | `fedora/dts/series/sun60i-a733-cubie-a7a.dts:76-80` |
| This board: 26 MHz oscillator; bin is one of vf0400, vf0401, vf0500, vf0501 (the cpufreq lists match only those four). The efuse word was not captured, so which one is unknown. | CAP `sys/dbg-clk_clk_summary.txt:116`, `20261007-regs/sw/cpufreq.txt`, `sys/live.dts` cluster tables |
| SID window: A733 entry, 0x80 bytes, legacy cells | `kmods/cubie-a7a-kmods/nvmem/sunxi_sid.c:156, 209-212` |

## The bin read

One nvmem cell, `dvfs` = 4 bytes at SID 0x4c (`soc_dvfs` in the dtsi), read
with `nvmem_cell_read_u32()` at probe, and only when the DT asks for more
than 492 MHz. Bits 7:0 of that word are thermal calibration; bits 31:24 are
the vendor GPU driver's own code and are not used. The table is
`a733_npu_bins[]`. A CPU frequency driver needs the same cell, the same
`bak ?: ori` rule and the same code-to-vfNNNN map; the three can move to one
shared helper, with `uv_852m` staying here.

Rail voltage: `regulator_get_voltage()` of `npu-supply` if the node has one
(the dtsi adds it), else 800 mV. The driver never changes the rail.

## PLL factors: settle this at 492 MHz first

852 MHz comes from `pll-npu` (CCU 0x2a0) with the module divider at 1.

- Vendor: 24 MHz reference x N / M, N limited to 53-105, M in bits 22:20.
  852 MHz is N=71, M=2 (VCO 1704 MHz); 492 MHz is N=82, M=4. A
  `ccu-sun60iw2.c:398-418`; the capture's 1008 MHz is N=84, M=2
  (CAP `20261007-regs/ccu.txt:59`, 0x01105300).
- Our CCU (`kmods/cubie-a7a-kmods/ccu/ccu-sun60i-a733.c:410-422`) allows N
  from 11 and models bit 1 as an input divider. Its search returns N=71 with
  bit 1 set for 852 MHz, and N=41 with bit 1 set for 492 MHz: half the
  vendor's VCO frequency, through a bit no vendor source sets.

So today's 492 MHz already depends on bit 1 dividing by two. If it does not,
the NPU runs at twice the rate `clk_summary` shows (984 MHz now, 1704 MHz
with this opt-in). That is why step 2 of the checklist comes first. The
clean fix is in the CCU, not here: give `pll-npu` the vendor's N range
(53-105) and no input divider, which yields the vendor's factors for both
rates.

Done 2026-11-11 in `kmods/cubie-a7a-kmods/ccu/ccu-sun60i-a733.c` (N 53-105,
no input divider, bit 1 cleared at probe). The first board run at the old
factors hung inside the first network (hang dump: FE parked behind 15 NN
kicks, no AXI or MMU error, nothing outstanding, zero writes). To tell a
pll-npu fault from the rest of the NPU path without the CCU change, load
`vipcore alt_rate=480000000`: the module clock then comes from
pll-periph0-480M and pll-npu is not used.

## Before enabling (default DTB, 492 MHz)

1. Bin: `od -A x -t x4 -j 76 -N 4 /sys/bus/nvmem/devices/sunxi-sid0/nvmem`.
   Take bits 23:16, or bits 15:8 if those are zero, and look the code up
   above. 0x14 (vf0401) will stay at 492 MHz.
2. Real clock rate: run `cubie-a7a-npu-selftest 50` and record inference
   time and cycles. Cycles divided by time should be near 492 MHz, not
   984 MHz. If the tool's cycle count turns out not to follow the module
   clock, compare against the vendor image at a known rate instead. Do not
   go on until this is settled.
3. `grep dcdc2 /sys/kernel/debug/regulator/regulator_summary`: 800mV.
4. Idle temperatures: `cat /sys/class/thermal/thermal_zone*/temp`.

## Run (DTB with the dtsi)

1. `dmesg | grep -i npu`: either `speed bin vfNNNN (code 0x..), rail at
   800000 uV: 852000000 Hz allowed` or a `staying at 492000000 Hz` line with
   the reason.
2. `grep -E 'pll-npu|  npu ' /sys/kernel/debug/clk/clk_summary` during a
   run: both 852000000. `clk_freq` in `/sys/kernel/debug/viplite/` agrees.
3. `cubie-a7a-npu-selftest 50`: same top-5 as at 492 MHz; time per
   inference lower, cycles about the same.
4. Repeat for 15 minutes; the NPU is sensor 2. Then a Vulkan workload at the
   same time (a CPU load until the GPU runs), and HDMI output checked (same
   rail).

Failure signs: differing top-5, `vpm_run` timeout or non-zero exit, NPU
interrupt timeouts or `power on failed` in dmesg, a hang (the next boot
skips the step: `hat-enable.trying`), HDMI dropouts, NPU zone climbing
towards 110 C. Nothing throttles the NPU: its zone has only the critical
trip, as in the vendor tree (V `sun60iw2p1.dtsi:702-714`), and there is no
devfreq cooling here. Dynamic power rises by about 1.73x (852/492) at the
same voltage.

## Revert

Drop the include and rebuild the DTB; the module then never reads the bin.
`cubie_a7a.hat=0` keeps `vipcore` unloaded for one boot.

## Unverified

- Bit 1 of `pll-npu` as an input divider, and PLL lock and jitter at a
  492 or 852 MHz VCO.
- This board's bin code.
- That an unprogrammed bin field reads 0 (vf0000) rather than garbage.
- NPU timing at 852 MHz and 800 mV on any bin: the vendor image never ran
  that pair on this board.
