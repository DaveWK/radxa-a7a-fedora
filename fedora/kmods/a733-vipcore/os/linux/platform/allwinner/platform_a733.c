// SPDX-License-Identifier: GPL-2.0-only
/*
 * Allwinner A733 (sun60iw2) glue for the VIPLite kernel driver on a mainline
 * kernel: bus/module clocks, resets and the PCK-600 NPU power domain from
 * the device tree. No vendor SID/SMC, IOMMU or devfreq dependencies.
 *
 * The NPU rail is not scaled here. The module clock runs at the node's
 * "clock-frequency" (default 492 MHz, the vendor table's rate that every
 * speed bin runs at the rail's 800 mV boot voltage). A higher rate is an
 * opt-in (SPEED.md): it is honoured only when the chip's efuse speed bin
 * lists it at the voltage the rail is at, otherwise the clock stays at
 * 492 MHz.
 */
#include <linux/bits.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nvmem-consumer.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/regulator/consumer.h>
#include <linux/reset.h>

#include "vip_drv_device_driver.h"
#include "vip_drv_device_platform_config.h"

#define A733_NPU_DEFAULT_HZ	492000000ULL
#define A733_NPU_BOOST_HZ	852000000ULL
/* DCDC2 as this tree fixes it; used when the node names no "npu-supply". */
#define A733_NPU_RAIL_UV	800000

/*
 * Speed bins, from the vendor tree (configs/linux-6.6 of radxa/allwinner-bsp):
 *  - the bin code is in the efuse word at SID offset 0x4c (nvmem cell
 *    "dvfs", 4 bytes): bits 23:16 ("dvfs_bak") if non-zero, else bits 15:8
 *    ("dvfs_ori"), as sunxi_get_soc_dvfs() combines them;
 *  - vf_mapping_table (sun60iw2p1-cpu-vf.dtsi) turns the code into the
 *    vfNNNN column of the operating-point tables;
 *  - uv_852m is the opp-852 entry of npu-opp-table for that column, the
 *    higher of the 24 MHz and 26 MHz oscillator variants; 0 where the table
 *    has no 852 MHz entry for the bin.
 * A code that is not in the mapping table gets no boost.
 */
static const struct a733_npu_bin {
	u8 code;
	u16 vf;
	u32 uv_852m;
} a733_npu_bins[] = {
	{ 0x00, 0x0000, 800000 },
	{ 0x01, 0x0100, 0 },
	{ 0x11, 0x0101, 0 },
	{ 0x02, 0x0200, 800000 },
	{ 0x12, 0x0201, 800000 },
	{ 0x03, 0x0300, 0 },
	{ 0x04, 0x0400, 800000 },
	{ 0x14, 0x0401, 820000 },
	{ 0x05, 0x0500, 800000 },
	{ 0x15, 0x0501, 800000 },
	{ 0x06, 0x0600, 0 },
};

/*
 * Diagnostic: run the module clock at this rate from whichever existing
 * parent of the "npu" mux gives it exactly (pll-periph0-480M for 480 MHz),
 * leaving pll-npu alone. Separates a pll-npu programming fault from the rest
 * of the NPU path. Capped at the 492 MHz baseline; 0 = normal (pll-npu).
 */
static unsigned long alt_rate;
module_param(alt_rate, ulong, 0444);
MODULE_PARM_DESC(alt_rate, "test: module clock rate in Hz from an existing parent instead of pll-npu (<= 492000000, 0 = off)");

/*
 * SYS_CFG +0x08 bit 1 routes the SRAM bank the NPU uses as its on-chip VIP
 * SRAM (512 KiB on this core, vip_feature_database.h): set, the reset
 * default ("boot mode"), the bank stays with the boot path; clear, it is the
 * NPU's. The vendor U-Boot (sunxi_set_sramc_mode()) and the Radxa vendor
 * kernel driver (radxa/allwinner-bsp 57c4003, cubie-aiot-v1.4.8) clear it;
 * our firmware does not, and without it the NPU front end runs but the NN
 * core never completes a layer. The vendor running image reads 0x00000000
 * here. Firmware runtime code lives in DRAM, so the bank is free once Linux
 * runs.
 */
#define A733_SYS_CFG_SRAM_CTRL2	0x03000008
#define A733_SRAM_CTRL2_BOOT	BIT(1)

static int sram_to_npu = 1;
module_param(sram_to_npu, int, 0444);
MODULE_PARM_DESC(sram_to_npu,
		 "clear SYS_CFG+0x8 bit 1 at probe to give the shared SRAM to the NPU (default 1; 0 leaves the firmware setting)");

static void a733_npu_route_sram(struct device *dev)
{
	void __iomem *reg;
	u32 before, after;

	reg = ioremap(A733_SYS_CFG_SRAM_CTRL2, sizeof(u32));
	if (!reg) {
		dev_warn(dev, "cannot map SYS_CFG+0x8, SRAM routing left as is\n");
		return;
	}
	before = readl(reg);
	if (sram_to_npu && (before & A733_SRAM_CTRL2_BOOT))
		writel(before & ~A733_SRAM_CTRL2_BOOT, reg);
	after = readl(reg);
	iounmap(reg);
	dev_info(dev, "SYS_CFG+0x8 0x%08x -> 0x%08x: shared SRAM with the %s\n",
		 before, after,
		 (after & A733_SRAM_CTRL2_BOOT) ? "boot path, not the NPU" : "NPU");
}

static const char * const a733_npu_gates[] = {
	"clk_ahb_gate", "clk_mbus_gate", "clk_bus",
};

static struct {
	struct device *dev;
	struct clk *mclk;
	struct clk *pclk;
	struct clk_bulk_data gates[ARRAY_SIZE(a733_npu_gates)];
	struct reset_control *resets;
	u64 freq;
	u64 limit;
	bool alt;
	bool pm;
	bool on;
	struct mutex lock;
} npu;

static int a733_npu_set_rate(u64 freq)
{
	long rounded;
	int ret;

	if (npu.alt) {
		/* Let the mux pick a parent that gives the rate exactly. */
		rounded = clk_round_rate(npu.mclk, freq);
		if (rounded != freq) {
			dev_err(npu.dev, "alt_rate %llu Hz: no parent gives it exactly (%ld)\n",
				freq, rounded);
			return -EINVAL;
		}
		return clk_set_rate(npu.mclk, freq);
	}
	ret = clk_set_rate(npu.pclk, freq);
	if (ret)
		return ret;
	ret = clk_set_parent(npu.mclk, npu.pclk);
	if (ret)
		return ret;
	return clk_set_rate(npu.mclk, freq);
}

/*
 * Decide whether a rate above the 492 MHz baseline may be used. Anything
 * that cannot be established (bin, rail voltage, an unlisted rate) keeps
 * the baseline.
 */
static u64 a733_npu_check_boost(struct device *dev, u64 want)
{
	const struct a733_npu_bin *bin = NULL;
	struct regulator *rail;
	u32 word, code;
	int uv = A733_NPU_RAIL_UV;
	int i, ret;

	if (want != A733_NPU_BOOST_HZ) {
		dev_warn(dev, "%llu Hz is not a validated rate, staying at %llu Hz\n",
			 want, A733_NPU_DEFAULT_HZ);
		return A733_NPU_DEFAULT_HZ;
	}
	ret = nvmem_cell_read_u32(dev, "dvfs", &word);
	if (ret) {
		dev_warn(dev, "speed bin not readable (nvmem cell \"dvfs\": %d), staying at %llu Hz\n",
			 ret, A733_NPU_DEFAULT_HZ);
		return A733_NPU_DEFAULT_HZ;
	}
	code = (word >> 16) & 0xff;
	if (!code)
		code = (word >> 8) & 0xff;
	for (i = 0; i < ARRAY_SIZE(a733_npu_bins); i++)
		if (a733_npu_bins[i].code == code)
			bin = &a733_npu_bins[i];
	if (!bin) {
		dev_warn(dev, "unknown speed bin code 0x%02x (efuse 0x4c = 0x%08x), staying at %llu Hz\n",
			 code, word, A733_NPU_DEFAULT_HZ);
		return A733_NPU_DEFAULT_HZ;
	}

	rail = regulator_get_optional(dev, "npu");
	if (!IS_ERR(rail)) {
		uv = regulator_get_voltage(rail);
		regulator_put(rail);
	} else if (PTR_ERR(rail) != -ENODEV) {
		uv = PTR_ERR(rail);
	}
	if (uv <= 0) {
		dev_warn(dev, "rail voltage not readable (%d), staying at %llu Hz\n",
			 uv, A733_NPU_DEFAULT_HZ);
		return A733_NPU_DEFAULT_HZ;
	}
	if (!bin->uv_852m || uv < bin->uv_852m) {
		dev_warn(dev, "speed bin vf%04x (code 0x%02x) needs %u uV for %llu Hz, rail is at %d uV: staying at %llu Hz\n",
			 bin->vf, code, bin->uv_852m, want, uv,
			 A733_NPU_DEFAULT_HZ);
		return A733_NPU_DEFAULT_HZ;
	}
	dev_info(dev, "speed bin vf%04x (code 0x%02x), rail at %d uV: %llu Hz allowed\n",
		 bin->vf, code, uv, want);
	return want;
}

static int a733_npu_power(bool on)
{
	int ret = 0;

	mutex_lock(&npu.lock);
	if (on == npu.on)
		goto out;
	if (!on) {
		clk_disable_unprepare(npu.mclk);
		clk_bulk_disable_unprepare(ARRAY_SIZE(npu.gates), npu.gates);
		reset_control_assert(npu.resets);
		if (npu.pm)
			pm_runtime_put_sync(npu.dev);
		npu.on = false;
		goto out;
	}
	if (npu.pm) {
		ret = pm_runtime_resume_and_get(npu.dev);
		if (ret)
			goto out;
	}
	ret = reset_control_deassert(npu.resets);
	if (ret)
		goto err_pm;
	ret = clk_bulk_prepare_enable(ARRAY_SIZE(npu.gates), npu.gates);
	if (ret)
		goto err_reset;
	ret = a733_npu_set_rate(npu.freq);
	if (!ret)
		ret = clk_prepare_enable(npu.mclk);
	if (ret)
		goto err_gates;
	npu.on = true;
	dev_info_once(npu.dev, "module clock %lu Hz from %s (pll-npu %lu Hz)\n",
		      clk_get_rate(npu.mclk),
		      __clk_get_name(clk_get_parent(npu.mclk)),
		      clk_get_rate(npu.pclk));
	goto out;
err_gates:
	clk_bulk_disable_unprepare(ARRAY_SIZE(npu.gates), npu.gates);
err_reset:
	reset_control_assert(npu.resets);
err_pm:
	if (npu.pm)
		pm_runtime_put_sync(npu.dev);
out:
	mutex_unlock(&npu.lock);
	if (ret)
		dev_err(npu.dev, "power %s failed: %d\n", on ? "on" : "off", ret);
	return ret;
}

vip_address_t vipdrv_drv_get_vipphysical(vip_address_t cpu_physical)
{
	return cpu_physical;
}

vip_address_t vipdrv_drv_get_cpuphysical(vip_address_t vip_physical)
{
	return vip_physical;
}

static const struct of_device_id vipcore_dev_match[] = {
	{ .compatible = "allwinner,sun60i-a733-npu" },
	{ }
};
MODULE_DEVICE_TABLE(of, vipcore_dev_match);

vip_int32_t vipdrv_drv_platform_init(vipdrv_driver_t *kdriver)
{
	kdriver->pdrv->driver.of_match_table = vipcore_dev_match;
	return 0;
}

vip_int32_t vipdrv_drv_platform_uninit(vipdrv_driver_t *kdriver)
{
	return 0;
}

vip_int32_t vipdrv_drv_adjust_param(vipdrv_driver_t *kdriver)
{
	struct platform_device *pdev = kdriver->pdev;
	struct device *dev;
	struct resource *res;
	u32 hz;
	int i, irq;

	if (!pdev)
		return -1;
	dev = &pdev->dev;
	mutex_init(&npu.lock);
	npu.dev = dev;
	npu.on = false;

#if vpmdENABLE_VIDEO_MEMORY_HEAP
	if (!kdriver->cpu_physical[0])
		kdriver->cpu_physical[0] = VIDEO_MEMORY_HEAP_BASE_ADDRESS;
	if (!kdriver->heap_infos[0].vip_memsize)
		kdriver->heap_infos[0].vip_memsize = VIDEO_MEMORY_HEAP_SIZE;
	if (!vipdrv_os_strcmp("", kdriver->heap_infos[0].name))
		kdriver->heap_infos[0].name = ALLOCATOR_NAME_HEAP_RESERVED;
#endif
	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;
	kdriver->irq_line[0] = irq;
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;
	if (!kdriver->vip_reg_phy[0])
		kdriver->vip_reg_phy[0] = res->start;
	if (!kdriver->vip_reg_size[0])
		kdriver->vip_reg_size[0] = resource_size(res);
	if (!kdriver->axi_sram_base)
		kdriver->axi_sram_base = AXI_SRAM_BASE_ADDRESS;
	if (!kdriver->axi_sram_size[0])
		kdriver->axi_sram_size[0] = AXI_SRAM_SIZE;
	kdriver->device_core_number[0] = 1;
	kdriver->core_count = 1;
	kdriver->sys_heap_size = SYSTEM_MEMORY_HEAP_SIZE;

	npu.mclk = devm_clk_get(dev, "clk_npu");
	if (IS_ERR(npu.mclk))
		return dev_err_probe(dev, PTR_ERR(npu.mclk), "clk_npu\n");
	npu.pclk = devm_clk_get(dev, "clk_parent");
	if (IS_ERR(npu.pclk))
		return dev_err_probe(dev, PTR_ERR(npu.pclk), "clk_parent\n");
	for (i = 0; i < ARRAY_SIZE(a733_npu_gates); i++)
		npu.gates[i].id = a733_npu_gates[i];
	i = devm_clk_bulk_get(dev, ARRAY_SIZE(npu.gates), npu.gates);
	if (i)
		return dev_err_probe(dev, i, "bus clocks\n");
	npu.resets = devm_reset_control_array_get_exclusive(dev);
	if (IS_ERR(npu.resets))
		return dev_err_probe(dev, PTR_ERR(npu.resets), "resets\n");

	npu.freq = A733_NPU_DEFAULT_HZ;
	if (!of_property_read_u32(dev->of_node, "clock-frequency", &hz) && hz)
		npu.freq = hz;
	if (npu.freq > A733_NPU_DEFAULT_HZ)
		npu.freq = a733_npu_check_boost(dev, npu.freq);
	if (alt_rate) {
		if (alt_rate > A733_NPU_DEFAULT_HZ) {
			dev_warn(dev, "alt_rate %lu Hz above %llu Hz, ignored\n",
				 alt_rate, A733_NPU_DEFAULT_HZ);
		} else {
			npu.alt = true;
			npu.freq = alt_rate;
			dev_warn(dev, "alt_rate: module clock %lu Hz from an existing parent, not pll-npu (test)\n",
				 alt_rate);
		}
	}
	npu.limit = max(npu.freq, A733_NPU_DEFAULT_HZ);
	/* Before the NPU is first powered (vipdrv_drv_device_init). */
	a733_npu_route_sram(dev);
	npu.pm = of_property_present(dev->of_node, "power-domains");
	if (npu.pm)
		pm_runtime_enable(dev);
	dev_info(dev, "A733 NPU at %pR, irq %d, %llu Hz, power domain %s\n",
		 res, irq, npu.freq, npu.pm ? "managed" : "none");
	return 0;
}

vip_int32_t vipdrv_drv_unadjust_param(vipdrv_driver_t *kdriver)
{
	a733_npu_power(false);
	if (npu.pm)
		pm_runtime_disable(npu.dev);
	return 0;
}

vip_int32_t vipdrv_drv_device_init(vipdrv_driver_t *kdriver, vip_uint32_t core)
{
	int ret = a733_npu_power(true);

	vipdrv_os_delay(2);
	return ret;
}

vip_int32_t vipdrv_drv_device_uninit(vipdrv_driver_t *kdriver, vip_uint32_t core)
{
	return a733_npu_power(false);
}

/* Frequency and voltage hooks of the driver's debug interface. */
vip_int32_t vipdrv_drv_get_supported_frequency(struct device *dev, u64 *max_freq,
					       u32 *npu_vol, u64 arr[], u32 size)
{
	if (max_freq)
		*max_freq = npu.freq;
	if (npu_vol)
		*npu_vol = 0;
	if (arr && size)
		arr[0] = npu.freq;
	return 1;
}

vip_int32_t vipdrv_drv_update_clk_freq(const u64 freq)
{
	int ret = 0;

	/* The debug interface cannot go past what probe allowed. */
	if (freq > npu.limit)
		return -EINVAL;
	mutex_lock(&npu.lock);
	if (npu.on)
		ret = a733_npu_set_rate(freq);
	if (!ret)
		npu.freq = freq;
	mutex_unlock(&npu.lock);
	return ret;
}

vip_uint64_t vipdrv_drv_get_clk_freq(void)
{
	return npu.on ? clk_get_rate(npu.mclk) : npu.freq;
}

vip_int32_t vipdrv_drv_update_vol_regul(const int vol)
{
	return -EOPNOTSUPP;
}

vip_uint32_t vipdrv_drv_get_vol_regul(void)
{
	return 0;
}
