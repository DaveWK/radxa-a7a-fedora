# GPU at 800 MHz (opt-in, untested)

`cubie-a7a-gpu-800m.dtsi` moves the A733 GPU module clock from 600 MHz to
800 MHz and fixes its rail, DCDC4, at 840 mV. The board DTS does not include
it. Nothing here has run on a board.

Sources: **V** = `src/radxa-allwinner-bsp` (radxa/allwinner-bsp c83016d2),
**A** = `src/allwinner-bsp` (alexcaoys/allwinner-bsp 656a550c), **T** =
radxa/allwinner-bsp 2045a3ca, **CAP** = the vendor 6.6.98 capture of this
board (register captures of the vendor image, not included), **K** =
Fedora kernel 7.3.3 source.

## Evidence

| Fact | Source |
|---|---|
| 600 MHz: 800 mV on every bin | V `configs/linux-6.6/sun60iw2p1.dtsi:4682-4707` |
| 800 MHz: 840 mV default, vf0000, vf0100, vf0200; 820 mV vf0300, vf0800; 800 mV all other bins (incl. vf0400, vf0401, vf0500, vf0501) | same file `:4709-4734` |
| 1008 MHz: 860-960 mV, so 840 mV is below every bin's highest listed voltage | same file `:4736-4760` |
| 800 MHz = `gpu0` parented to `pll-peri0-800m`, divider 1 | T `modules/gpu/img-bxm/.../rgx_sunxi/sunxi_platform.c:303-309` |
| `gpu0` at CCU 0xb20, mux bits 26:24, input 1 = PERI0 800 MHz | A `drivers/clk/sunxi-ng/ccu-sun60iw2.c:1021-1041`; ours `kmods/cubie-a7a-kmods/ccu/ccu-sun60i-a733.c:867-885`, `CLK_PLL_PERIPH0_800M` = 5 |
| PERI0 800 MHz output = PLL_PERI0 (0xa0) bits 18:16; 800 MHz under the vendor boot chain | CAP `20261007-regs/ccu.txt:9` (0xFF126310), `sys/dbg-clk_clk_summary.txt:505` |
| GPU is the only consumer of DCDC4; vendor ran 600 MHz at 800 mV | CAP `sys/dbg-regulator_regulator_summary.txt:46-47`, `20261007-regs/sw/dmesg.txt:922-927` |
| DCDC4 steps 10 mV from 500 mV: 840 mV is selector 34 | `kmods/cubie-a7a-kmods/regulator/axp318-regulator.c:889-892, 924-927` |
| powervr sets no clock rate and takes no supply; it reports `clk_get_rate(core)` to the firmware | K `drivers/gpu/drm/imagination/pvr_device.c:97-114`, `pvr_fw.c:368`, `pvr_power.c:276` |
| `assigned-clock-*` are applied when the platform device probes | K `drivers/base/platform.c:1497` |
| A regulator with min = max gets that voltage when it registers; failure fails the registration | K `drivers/regulator/of_regulator.c:110-111`, `core.c:1313-1352` |

The vendor GPU driver takes its bin from efuse 0x4c bits 31:24
(`sunxi_platform.c:369, 439-441`), a different field from the SoC bin the
CPU and NPU use. Nothing in this tree reads it; 840 mV covers every bin.

## Voltage before frequency

1. `axp318-regulator` registers DCDC1..9 in order and fails as a whole if
   one fails. Registering DCDC4 with 840/840 mV sets 840 mV there.
2. The SD slot's `vmmc-supply` is `swout2`, registered by the same probe
   after DCDC4, so the root file system cannot be mounted before step 1.
3. The GPU device cannot probe before its power domain provider is bound.
   `sun55i_pck600` is blacklisted and loaded by `cubie-a7a-hat-enable` from
   the root file system; `powervr` follows it. The clock parent and rate are
   applied at that probe and not before.

This is an ordering of this image's boot, not something the drivers enforce:
the GPU node has no supply the driver would wait for. Root on anything other
than the SD slot, or `sun55i_pck600` in the initramfs, breaks step 2 or 3.
Step 1 of the checklist is therefore not optional.

## Before the first run

1. Boot with `cubie_a7a.hat=0` and confirm the rail:
   `grep dcdc4 /sys/kernel/debug/regulator/regulator_summary` shows 840mV.
2. `grep -E 'pll-periph0-(4x|800M)|pll-gpu0' /sys/kernel/debug/clk/clk_summary`:
   `pll-periph0-800M` must read 800000000 under our boot chain (only the
   vendor chain is captured). If `pll-gpu0` reads 800, 1600 or 3200 MHz the
   clock framework may pick it instead; stop and report.
3. Note the idle temperatures: `cat /sys/class/thermal/thermal_zone*/temp`.

## Run

1. Remove `cubie_a7a.hat=0`, reboot, let `cubie-a7a-hat-enable` load `powervr`.
2. `grep -E ' gpu0 ' /sys/kernel/debug/clk/clk_summary`: 800000000, under
   `pll-periph0-800M`. Rail still 840mV.
3. `dmesg | grep -i powervr`: firmware loaded, no errors.
4. Vulkan workload for 15 minutes (`vkcube`, then `vkmark` or a longer
   scene); watch `thermal_zone*/temp` (GPU is sensor 4) and the fan.

Failure signs: powervr firmware timeouts or device-lost in dmesg, rendering
corruption, a hang (the next boot skips the module: `hat-enable.trying`),
GPU zone above 90 C. The mainline driver has no devfreq, so nothing throttles
the GPU; only the fan (60 C) and the 110 C critical trip act. The vendor
throttles from 60 C with a 2.4 W budget (V `sun60iw2p1.dtsi:652-697`).
Dynamic power rises by about 1.47x (800/600 x (840/800)^2), and the rail
stays at 840 mV whether the GPU runs or not.

## Revert

Drop the include and rebuild the DTB (rail back to 800-960 mV at its boot
value, clock 600 MHz). To get a shell first: `cubie_a7a.hat=0`.

## Unverified

- `pll-periph0-800M` rate and DCDC4's voltage at kernel entry under oreboot.
- GPU firmware and driver behaviour at 800 MHz: the vendor image on this
  board only ever ran 600 MHz.
