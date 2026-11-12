// SPDX-License-Identifier: GPL-2.0-only
/*
 * Allwinner PCK-600 power domain support
 *
 * Copyright (c) 2025 Chen-Yu Tsai <wens@csie.org>
 *
 * The hardware is likely based on the Arm PCK-600 IP, since some of
 * the registers match Arm's documents, with additional delay controls
 * that are in registers listed as reserved.
 *
 * Documents include:
 * - "Arm CoreLink PCK-600 Power Control Kit" TRM
 * - "Arm Power Policy Unit" architecture specification (DEN0051E)
 */

#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/container_of.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dev_printk.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/ktime.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/reset.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/string_choices.h>

#define PPU_PWPR    0x0
#define PPU_PMER    0x4
#define PPU_PWSR    0x8
#define PPU_DISR    0x10
#define PPU_MISR    0x14
#define PPU_STSR    0x18
#define PPU_PWCR    0x20
#define PPU_PTCR    0x24
#define PPU_IMR     0x30
#define PPU_AIMR    0x34
#define PPU_ISR     0x38
#define PPU_AISR    0x3c
#define PPU_IESR    0x40
#define PPU_OPSR    0x44
#define PPU_EDTR0   0x160
#define PPU_EDTR1   0x164
#define PPU_DCDR0   0x170
#define PPU_DCDR1   0x174
#define PPU_IDR0    0xfb0
#define PPU_IDR1    0xfb4
#define PPU_IIDR    0xfc8
#define PPU_AIDR    0xfcc

/* shared definition for PPU_PWPR and PPU_PWSR */
#define PPU_PWR_STATUS	GENMASK(3, 0)
/* PWPR: dynamic policy enable; PWSR: dynamic policy in effect */
#define PPU_PWR_DYN	BIT(8)
#define PPU_POWER_MODE_ON	0x8
#define PPU_POWER_MODE_OFF	0x0

#define PPU_REG_SIZE	0x1000

/*
 * GPU_CORE bring-up experiments, one per boot (sun55i_pck600.gpu_core_seq=N).
 * They apply only to a domain that names its inner device (GPU_CORE):
 *  0  static ON; if it has not completed within 10 ms, keep the request,
 *     the device clocks and the released reset for up to settle_ms more,
 *     logging the PPU whenever its status or inputs change; then withdraw.
 *  1  static ON left pending at probe, no withdrawal, as the vendor's own
 *     resume code does for this one domain; the domain is published off.
 *  2  dynamic policy, OFF as minimum: the PPU follows the device's
 *     activity input instead of a static request.
 * Every frame is logged once at probe; debugfs pck600-regs re-reads them.
 */
static unsigned int gpu_core_seq;
module_param(gpu_core_seq, uint, 0444);
MODULE_PARM_DESC(gpu_core_seq, "GPU_CORE power-on sequence: 0 static, 1 static left pending, 2 dynamic");

static unsigned int settle_ms = 1000;
module_param(settle_ms, uint, 0444);
MODULE_PARM_DESC(settle_ms, "extra wait for GPU_CORE after 10 ms, at most 5000 ms");

/*
 * The GPU domains are switched on on demand: genpd powers GPU_TOP, then
 * GPU_CORE, when the GPU device (powervr) attaches or runtime-resumes, and
 * off again when it suspends or detaches. A GPU domain found on at probe
 * (left on by an earlier kernel across a warm reset, or by other boot
 * firmware) is switched off before it is published, GPU_CORE before
 * GPU_TOP: genpd would otherwise keep it on (genpd_power_off_unused runs
 * before this module loads, and an on domain stays on until the provider's
 * sync_state, which waits for every consumer to probe). With
 * gpu_core_always_on=1 the provider instead switches GPU_CORE (and GPU_TOP
 * first) on at probe and keeps it on, as up to cubie-a7a-board-support 0.12;
 * the gpu_core_seq experiments then run at probe, before the GPU driver owns
 * its reset.
 */
static bool gpu_core_always_on;
module_param(gpu_core_always_on, bool, 0444);
MODULE_PARM_DESC(gpu_core_always_on, "switch GPU_CORE (and GPU_TOP) on at probe and keep it on, as before 0.13 (default: on demand; GPU domains found on at probe are switched off)");

struct sunxi_pck600_pd_desc {
	const char *name;
	unsigned int flags;
	/* Enclosing domain, listed before this one; it must be on first. */
	const char *parent;
	/*
	 * The device inside the domain. A PPU transition completes only when
	 * that device answers on its power-control channel, which it cannot do
	 * with its clocks gated or while held in reset. Its clocks and reset,
	 * named on the provider node, are therefore held for the transition
	 * only. All three are optional in the device tree.
	 */
	const char *dev_clk;
	const char *dev_bus_clk;
	const char *dev_rst;
	/*
	 * Clocks held enabled while the domain is on (GPU_TOP: the GPU's AHB
	 * and MBUS master gates, which the GPU binding does not name). Both
	 * optional in the device tree.
	 */
	const char *on_clk[2];
	/*
	 * Powered only on demand: a domain found on at probe is switched off
	 * before it is published (unless gpu_core_always_on).
	 */
	bool on_demand;
};

struct sunxi_pck600_desc {
	const struct sunxi_pck600_pd_desc *pd_descs;
	unsigned int num_domains;
	u32 logic_power_switch0_delay_offset;
	u32 logic_power_switch1_delay_offset;
	u32 off2on_delay_offset;
	u32 device_ctrl0_delay;
	u32 device_ctrl1_delay;
	u32 logic_power_switch0_delay;
	u32 logic_power_switch1_delay;
	u32 off2on_delay;
	bool has_rst_clk;
};

struct sunxi_pck600_pd {
	struct generic_pm_domain genpd;
	struct sunxi_pck600 *pck;
	void __iomem *base;
	/* Could not be switched on at probe; published as an off domain. */
	bool degraded;
	struct clk *dev_clk;
	struct clk *dev_bus_clk;
	/* reset-names entry of the inner device, if the node has one */
	const char *dev_rst;
	struct clk *on_clk[2];
	/* on_clk enabled: the domain is published on */
	bool on_clk_held;
	/* enclosing domain, or NULL */
	struct sunxi_pck600_pd *parent;
};

struct sunxi_pck600 {
	struct device *dev;
	struct genpd_onecell_data genpd_data;
	unsigned int num_domains;
	struct sunxi_pck600_pd pds[];
};

#define to_sunxi_pd(gpd) container_of(gpd, struct sunxi_pck600_pd, genpd)

/*
 * A static request also clears the dynamic enable, so that a domain once
 * put under dynamic policy goes back to software control.
 */
static void sunxi_pck600_pd_request(struct sunxi_pck600_pd *pd, u32 val)
{
	u32 reg;

	reg = readl(pd->base + PPU_PWPR) & ~PPU_PWR_DYN;
	FIELD_MODIFY(PPU_PWR_STATUS, &reg, val);
	writel(reg, pd->base + PPU_PWPR);

	/* push write out to hardware */
	reg = readl(pd->base + PPU_PWPR);
}

/*
 * Clock the inner device and release its reset for a transition. The reset
 * line belongs to the device's own driver once it binds: it is taken here
 * only if no one else holds it, and handed back right after.
 */
static struct reset_control *sunxi_pck600_dev_get(struct sunxi_pck600_pd *pd)
{
	struct device *dev = pd->pck->dev;
	struct reset_control *rst;
	int ret;

	ret = clk_prepare_enable(pd->dev_bus_clk);
	if (ret)
		dev_warn(dev, "domain \"%s\": bus clock: %d\n", pd->genpd.name, ret);
	ret = clk_prepare_enable(pd->dev_clk);
	if (ret)
		dev_warn(dev, "domain \"%s\": clock: %d\n", pd->genpd.name, ret);

	if (!pd->dev_rst)
		return NULL;
	rst = reset_control_get_exclusive_released(dev, pd->dev_rst);
	if (IS_ERR(rst))
		return NULL;
	if (reset_control_acquire(rst)) {
		/* bound consumer owns the line and sequences it itself */
		reset_control_put(rst);
		return NULL;
	}
	reset_control_deassert(rst);
	udelay(1);
	return rst;
}

static void sunxi_pck600_dev_put(struct sunxi_pck600_pd *pd,
				 struct reset_control *rst)
{
	if (rst) {
		reset_control_assert(rst);
		reset_control_release(rst);
		reset_control_put(rst);
	}
	clk_disable_unprepare(pd->dev_clk);
	clk_disable_unprepare(pd->dev_bus_clk);
}

/* One PPU frame: architected registers and the three delay registers. */
#define PPU_DUMP_FMT \
	"PWPR 0x%x PMER 0x%x PWSR 0x%x DISR 0x%x MISR 0x%x STSR 0x%x PWCR 0x%x PTCR 0x%x IMR 0x%x AIMR 0x%x ISR 0x%x AISR 0x%x IESR 0x%x OPSR 0x%x EDTR 0x%x/0x%x DCDR 0x%x/0x%x c00 0x%x c04 0x%x c10 0x%x"
#define PPU_DUMP_ARGS(b) \
	readl((b) + PPU_PWPR), readl((b) + PPU_PMER), readl((b) + PPU_PWSR), \
	readl((b) + PPU_DISR), readl((b) + PPU_MISR), readl((b) + PPU_STSR), \
	readl((b) + PPU_PWCR), readl((b) + PPU_PTCR), readl((b) + PPU_IMR), \
	readl((b) + PPU_AIMR), readl((b) + PPU_ISR), readl((b) + PPU_AISR), \
	readl((b) + PPU_IESR), readl((b) + PPU_OPSR), readl((b) + PPU_EDTR0), \
	readl((b) + PPU_EDTR1), readl((b) + PPU_DCDR0), readl((b) + PPU_DCDR1), \
	readl((b) + 0xc00), readl((b) + 0xc04), readl((b) + 0xc10)
#define PPU_ID_FMT "IDR0 0x%x IDR1 0x%x IIDR 0x%x AIDR 0x%x"
#define PPU_ID_ARGS(b) \
	readl((b) + PPU_IDR0), readl((b) + PPU_IDR1), readl((b) + PPU_IIDR), \
	readl((b) + PPU_AIDR)

static void sunxi_pck600_pd_dump(struct sunxi_pck600_pd *pd, const char *tag,
				 bool stuck)
{
	struct device *dev = pd->pck->dev;
	void __iomem *b = pd->base;

	if (stuck)
		dev_warn(dev, "domain \"%s\" %s: " PPU_DUMP_FMT "\n",
			 pd->genpd.name, tag, PPU_DUMP_ARGS(b));
	else
		dev_info(dev, "domain \"%s\" %s: " PPU_DUMP_FMT "\n",
			 pd->genpd.name, tag, PPU_DUMP_ARGS(b));
}

static bool sunxi_pck600_has_dev(struct sunxi_pck600_pd *pd)
{
	return pd->dev_clk || pd->dev_bus_clk || pd->dev_rst;
}

/* What the inner device looked like when the transition was requested. */
static void sunxi_pck600_dev_log(struct sunxi_pck600_pd *pd,
				 struct reset_control *rst)
{
	dev_info(pd->pck->dev,
		 "domain \"%s\": device clock %lu Hz, bus clock %lu Hz, reset %s (%d)\n",
		 pd->genpd.name, clk_get_rate(pd->dev_clk),
		 clk_get_rate(pd->dev_bus_clk),
		 !pd->dev_rst ? "none" : rst ? "held by provider" : "not taken",
		 rst ? reset_control_status(rst) : -ENOENT);
}

/*
 * Keep waiting, sleeping, for a transition that missed the first 10 ms.
 * Status, device inputs, events and the c10 register are logged whenever
 * they change (at most 16 times), so a late or partial transition shows.
 */
static int sunxi_pck600_pd_settle(struct sunxi_pck600_pd *pd, u32 val)
{
	unsigned int ms = min(settle_ms, 5000U), t, logged = 0;
	ktime_t start = ktime_get();
	void __iomem *b = pd->base;
	u32 last[4] = { ~0U, ~0U, ~0U, ~0U }, now[4];
	char tag[32];

	for (t = 0; t < ms; t++) {
		usleep_range(1000, 1100);
		now[0] = readl(b + PPU_PWSR);
		now[1] = readl(b + PPU_DISR);
		now[2] = readl(b + PPU_ISR) | readl(b + PPU_AISR);
		now[3] = readl(b + 0xc10);
		if (memcmp(now, last, sizeof(now)) && logged < 16) {
			memcpy(last, now, sizeof(now));
			snprintf(tag, sizeof(tag), "+%lld us",
				 ktime_us_delta(ktime_get(), start) + 10000);
			sunxi_pck600_pd_dump(pd, tag, false);
			logged++;
		}
		if (FIELD_GET(PPU_PWR_STATUS, now[0]) == val) {
			dev_info(pd->pck->dev, "domain \"%s\" reached 0x%x after %lld us\n",
				 pd->genpd.name, val,
				 ktime_us_delta(ktime_get(), start) + 10000);
			return 0;
		}
	}
	return -ETIMEDOUT;
}

/*
 * @probe: the first switch-on at probe, where gpu_core_seq 1 leaves a
 * stalled request pending instead of waiting for it.
 */
static int sunxi_pck600_pd_set_power(struct sunxi_pck600_pd *pd, bool on,
				     bool probe)
{
	struct sunxi_pck600 *pck = pd->pck;
	struct generic_pm_domain *genpd = &pd->genpd;
	bool trace = on && sunxi_pck600_has_dev(pd);
	unsigned int seq = trace ? gpu_core_seq : 0;
	struct reset_control *rst;
	int ret;
	u32 val, reg;

	val = on ? PPU_POWER_MODE_ON : PPU_POWER_MODE_OFF;

	rst = sunxi_pck600_dev_get(pd);
	if (trace) {
		/* drop stale events: what ISR/AISR show next is this request's */
		writel(readl(pd->base + PPU_ISR), pd->base + PPU_ISR);
		writel(readl(pd->base + PPU_AISR), pd->base + PPU_AISR);
		sunxi_pck600_dev_log(pd, rst);
		if (pd->parent)
			sunxi_pck600_pd_dump(pd->parent, "parent", false);
		sunxi_pck600_pd_dump(pd, seq == 2 ? "before dynamic" : "before", false);
	}
	if (seq == 2) {
		/* minimum OFF; the device's activity input decides */
		reg = readl(pd->base + PPU_PWPR);
		FIELD_MODIFY(PPU_PWR_STATUS, &reg, PPU_POWER_MODE_OFF);
		writel(reg | PPU_PWR_DYN, pd->base + PPU_PWPR);
		readl(pd->base + PPU_PWPR);
	} else {
		sunxi_pck600_pd_request(pd, val);
	}

	ret = readl_poll_timeout_atomic(pd->base + PPU_PWSR, reg,
					FIELD_GET(PPU_PWR_STATUS, reg) == val,
					0, 10000);
	if (ret && trace && !(probe && seq == 1))
		ret = sunxi_pck600_pd_settle(pd, val);
	if (trace)
		sunxi_pck600_pd_dump(pd, ret ? "after" : "on", false);
	if (ret) {
		dev_err(pck->dev, "failed to turn domain \"%s\" %s: %d\n",
			genpd->name, str_on_off(on), ret);
		sunxi_pck600_pd_dump(pd, "stuck", true);
	}
	sunxi_pck600_dev_put(pd, rst);

	return ret;
}

/* Enable or disable the clocks a domain holds while it is on. */
static void sunxi_pck600_on_clk(struct sunxi_pck600_pd *pd, bool on)
{
	unsigned int i;
	int ret;

	if (on == pd->on_clk_held)
		return;
	for (i = 0; i < ARRAY_SIZE(pd->on_clk); i++) {
		if (!on) {
			clk_disable_unprepare(pd->on_clk[i]);
			continue;
		}
		ret = clk_prepare_enable(pd->on_clk[i]);
		if (ret)
			dev_warn(pd->pck->dev, "domain \"%s\": clock %u: %d\n",
				 pd->genpd.name, i, ret);
	}
	pd->on_clk_held = on;
}

static int sunxi_pck600_power_on(struct generic_pm_domain *domain)
{
	struct sunxi_pck600_pd *pd = to_sunxi_pd(domain);
	int ret;

	ret = sunxi_pck600_pd_set_power(pd, true, false);
	if (!ret)
		sunxi_pck600_on_clk(pd, true);
	return ret;
}

static int sunxi_pck600_power_off(struct generic_pm_domain *domain)
{
	struct sunxi_pck600_pd *pd = to_sunxi_pd(domain);
	int ret;

	sunxi_pck600_on_clk(pd, false);
	ret = sunxi_pck600_pd_set_power(pd, false, false);
	if (ret)
		/* still on: so are its clocks */
		sunxi_pck600_on_clk(pd, true);
	return ret;
}

/* debugfs pck600-regs: every frame, read on demand (the bus clock stays on). */
static int sunxi_pck600_regs_show(struct seq_file *s, void *data)
{
	struct sunxi_pck600 *pck = dev_get_drvdata(s->private);
	unsigned int i;

	for (i = 0; i < pck->num_domains; i++) {
		void __iomem *b = pck->pds[i].base;

		seq_printf(s, "%-8s " PPU_DUMP_FMT "\n", pck->pds[i].genpd.name,
			   PPU_DUMP_ARGS(b));
	}
	return 0;
}

static void sunxi_pck600_pd_setup(struct sunxi_pck600_pd *pd,
				  const struct sunxi_pck600_desc *desc)
{
	writel(desc->device_ctrl0_delay, pd->base + PPU_DCDR0);
	writel(desc->device_ctrl1_delay, pd->base + PPU_DCDR1);
	writel(desc->logic_power_switch0_delay,
	       pd->base + desc->logic_power_switch0_delay_offset);
	writel(desc->logic_power_switch1_delay,
	       pd->base + desc->logic_power_switch1_delay_offset);
	writel(desc->off2on_delay, pd->base + desc->off2on_delay_offset);
}

/* Index of domain i's parent, or -1. A parent is listed before its child. */
static int sunxi_pck600_parent(const struct sunxi_pck600_desc *desc,
			       unsigned int i)
{
	const char *name = desc->pd_descs[i].parent;
	unsigned int j;

	if (!name)
		return -1;
	for (j = 0; j < i; j++)
		if (!strcmp(desc->pd_descs[j].name, name))
			return j;
	return -1;
}

/* Flags of domain i: GPU_CORE is always-on only with gpu_core_always_on. */
static unsigned int sunxi_pck600_flags(const struct sunxi_pck600_desc *desc,
				       unsigned int i)
{
	const struct sunxi_pck600_pd_desc *pd_desc = &desc->pd_descs[i];

	if (gpu_core_always_on && pd_desc->dev_clk)
		return pd_desc->flags | GENPD_FLAG_ALWAYS_ON;
	return pd_desc->flags;
}

/* Domain i must be on at probe: always-on, or the parent of such a domain. */
static bool sunxi_pck600_hold_on(const struct sunxi_pck600_desc *desc,
				 unsigned int i)
{
	unsigned int j;

	if (sunxi_pck600_flags(desc, i) & GENPD_FLAG_ALWAYS_ON)
		return true;
	for (j = i + 1; j < desc->num_domains; j++)
		if (sunxi_pck600_parent(desc, j) == (int)i &&
		    sunxi_pck600_hold_on(desc, j))
			return true;
	return false;
}

static bool sunxi_pck600_is_on(struct sunxi_pck600_pd *pd)
{
	return FIELD_GET(PPU_PWR_STATUS, readl(pd->base + PPU_PWSR)) ==
	       PPU_POWER_MODE_ON;
}

/*
 * Switch off the on-demand domains found on at probe, children before their
 * parent, through the same callback genpd uses: the domain's held clocks
 * (GPU_TOP: the GPU master gates) are taken to match the on state first,
 * so the child's transition runs with its parent fully up and the gates end
 * up off in hardware; GPU_CORE's transition clocks the GPU and releases its
 * reset for the handshake and hands both back. A domain that does not
 * switch off, or whose child is still on, stays on and is published on.
 */
static void sunxi_pck600_off_unused(struct sunxi_pck600 *pck,
				    const struct sunxi_pck600_desc *desc)
{
	int i, j;

	if (gpu_core_always_on)
		return;
	for (i = 0; i < desc->num_domains; i++) {
		struct sunxi_pck600_pd *pd = &pck->pds[i];

		if (desc->pd_descs[i].on_demand && sunxi_pck600_is_on(pd))
			sunxi_pck600_on_clk(pd, true);
	}
	for (i = desc->num_domains - 1; i >= 0; i--) {
		struct sunxi_pck600_pd *pd = &pck->pds[i];
		int ret;

		if (!desc->pd_descs[i].on_demand || !sunxi_pck600_is_on(pd))
			continue;
		for (j = i + 1; j < desc->num_domains; j++)
			if (sunxi_pck600_parent(desc, j) == i &&
			    sunxi_pck600_is_on(&pck->pds[j]))
				break;
		if (j < desc->num_domains) {
			dev_warn(pck->dev, "domain \"%s\" left on: \"%s\" is on\n",
				 pd->genpd.name, desc->pd_descs[j].name);
			continue;
		}
		sunxi_pck600_pd_setup(pd, desc);
		ret = sunxi_pck600_power_off(&pd->genpd);
		if (ret)
			dev_warn(pck->dev, "domain \"%s\" on at probe, left on (%d)\n",
				 pd->genpd.name, ret);
		else
			dev_info(pck->dev, "domain \"%s\" on at probe, switched off (on demand)\n",
				 pd->genpd.name);
	}
}

static int sunxi_pck600_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct sunxi_pck600_desc *desc;
	struct genpd_onecell_data *genpds;
	struct sunxi_pck600 *pck;
	struct reset_control *rst;
	struct clk *clk;
	void __iomem *base;
	unsigned int c;
	int i, parent, ret;
	u32 state;

	desc = of_device_get_match_data(dev);

	pck = devm_kzalloc(dev, struct_size(pck, pds, desc->num_domains), GFP_KERNEL);
	if (!pck)
		return -ENOMEM;

	pck->dev = &pdev->dev;
	pck->num_domains = desc->num_domains;
	platform_set_drvdata(pdev, pck);

	genpds = &pck->genpd_data;
	genpds->num_domains = desc->num_domains;
	genpds->domains = devm_kcalloc(dev, desc->num_domains,
				       sizeof(*genpds->domains), GFP_KERNEL);
	if (!genpds->domains)
		return -ENOMEM;

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return PTR_ERR(base);

	if (desc->has_rst_clk) {
		rst = devm_reset_control_get_exclusive_released(dev, NULL);
		if (IS_ERR(rst))
			return dev_err_probe(dev, PTR_ERR(rst), "failed to get reset control\n");
	}

	clk = devm_clk_get_enabled(dev, NULL);
	if (IS_ERR(clk))
		return dev_err_probe(dev, PTR_ERR(clk), "failed to get clock\n");

	for (i = 0; i < desc->num_domains; i++) {
		struct sunxi_pck600_pd *pd = &pck->pds[i];
		const struct sunxi_pck600_pd_desc *pd_desc = &desc->pd_descs[i];

		pd->pck = pck;
		pd->genpd.name = pd_desc->name;
		pd->genpd.power_off = sunxi_pck600_power_off;
		pd->genpd.power_on = sunxi_pck600_power_on;
		pd->genpd.flags = sunxi_pck600_flags(desc, i);
		pd->base = base + PPU_REG_SIZE * i;

		if (pd_desc->dev_clk) {
			pd->dev_clk = devm_clk_get_optional(dev, pd_desc->dev_clk);
			if (IS_ERR(pd->dev_clk))
				return dev_err_probe(dev, PTR_ERR(pd->dev_clk),
						     "failed to get clock %s\n",
						     pd_desc->dev_clk);
		}
		if (pd_desc->dev_bus_clk) {
			pd->dev_bus_clk = devm_clk_get_optional(dev, pd_desc->dev_bus_clk);
			if (IS_ERR(pd->dev_bus_clk))
				return dev_err_probe(dev, PTR_ERR(pd->dev_bus_clk),
						     "failed to get clock %s\n",
						     pd_desc->dev_bus_clk);
		}
		if (pd_desc->dev_rst &&
		    of_property_match_string(dev->of_node, "reset-names",
					     pd_desc->dev_rst) >= 0)
			pd->dev_rst = pd_desc->dev_rst;
		for (c = 0; c < ARRAY_SIZE(pd->on_clk); c++) {
			if (!pd_desc->on_clk[c])
				continue;
			pd->on_clk[c] = devm_clk_get_optional(dev, pd_desc->on_clk[c]);
			if (IS_ERR(pd->on_clk[c]))
				return dev_err_probe(dev, PTR_ERR(pd->on_clk[c]),
						     "failed to get clock %s\n",
						     pd_desc->on_clk[c]);
			if (!pd->on_clk[c])
				dev_warn(dev, "domain \"%s\": no clock %s in the device tree\n",
					 pd->genpd.name, pd_desc->on_clk[c]);
		}

		parent = sunxi_pck600_parent(desc, i);
		pd->parent = parent >= 0 ? &pck->pds[parent] : NULL;
		/* As firmware left it, before this driver writes anything. */
		sunxi_pck600_pd_dump(pd, "at probe", false);
		dev_info(dev, "domain \"%s\" id: " PPU_ID_FMT "\n", pd->genpd.name,
			 PPU_ID_ARGS(pd->base));
	}

	/* Nothing of the hardware is written before this point. */
	sunxi_pck600_off_unused(pck, desc);

	for (i = 0; i < desc->num_domains; i++) {
		struct sunxi_pck600_pd *pd = &pck->pds[i];

		/* The provider must describe hardware state, not firmware intent.
		 * This driver supports only stable OFF and ON. Reject retention,
		 * transitional or otherwise unsupported status before publishing.
		 */
		state = FIELD_GET(PPU_PWR_STATUS, readl(pd->base + PPU_PWSR));
		if (state != PPU_POWER_MODE_OFF && state != PPU_POWER_MODE_ON) {
			ret = dev_err_probe(dev, -EBUSY, "unsupported PPU state %u\n", state);
			goto err_remove_pds;
		}
		sunxi_pck600_pd_setup(pd, desc);
		/*
		 * genpd requires always-on domains already ON at initialization,
		 * and a domain cannot come up inside a parent that is off, so a
		 * parent of an always-on domain is switched on first.
		 */
		if (state == PPU_POWER_MODE_OFF && sunxi_pck600_hold_on(desc, i)) {
			if (pd->parent && pd->parent->degraded)
				ret = -ENODEV;
			else
				ret = sunxi_pck600_pd_set_power(pd, true, true);
			state = FIELD_GET(PPU_PWR_STATUS, readl(pd->base + PPU_PWSR));
			if (ret && state != PPU_POWER_MODE_ON) {
				/*
				 * One stuck domain must not take the provider,
				 * and every other domain, down with it: withdraw
				 * the request and publish this one as an ordinary
				 * off domain, so a consumer's power-on retries.
				 * gpu_core_seq 1 leaves the request pending.
				 */
				if (!(sunxi_pck600_has_dev(pd) && gpu_core_seq == 1))
					sunxi_pck600_pd_request(pd, PPU_POWER_MODE_OFF);
				pd->degraded = true;
				pd->genpd.flags &= ~GENPD_FLAG_ALWAYS_ON;
				dev_warn(dev, "domain \"%s\" left off (%d), PWSR 0x%x\n",
					 pd->genpd.name, ret,
					 readl(pd->base + PPU_PWSR));
			}
			state = pd->degraded ? PPU_POWER_MODE_OFF : PPU_POWER_MODE_ON;
		}
		ret = pm_genpd_init(&pd->genpd, NULL, state == PPU_POWER_MODE_OFF);
		if (ret) {
			dev_err_probe(dev, ret, "failed to initialize power domain\n");
			goto err_remove_pds;
		}
		/*
		 * published on: as firmware left it (an on-demand domain that
		 * would not switch off above), or switched on above
		 */
		if (state == PPU_POWER_MODE_ON)
			sunxi_pck600_on_clk(pd, true);

		genpds->domains[i] = &pd->genpd;
	}

	/* The links keep a parent on while an always-on child is on. */
	for (i = 0; i < desc->num_domains; i++) {
		parent = sunxi_pck600_parent(desc, i);
		if (parent < 0)
			continue;
		ret = pm_genpd_add_subdomain(genpds->domains[parent],
					     genpds->domains[i]);
		if (ret)
			dev_warn(dev, "domain \"%s\" not linked to \"%s\": %d\n",
				 desc->pd_descs[i].name, desc->pd_descs[parent].name,
				 ret);
	}

	ret = of_genpd_add_provider_onecell(dev_of_node(dev), genpds);
	if (ret) {
		dev_err_probe(dev, ret, "failed to add PD provider\n");
		goto err_remove_pds;
	}

	debugfs_create_devm_seqfile(dev, "pck600-regs", NULL,
				    sunxi_pck600_regs_show);

	return 0;

err_remove_pds:
	for (i--; i >= 0; i--)
		pm_genpd_remove(genpds->domains[i]);
	/* also a domain left on above but not initialized yet */
	for (i = 0; i < desc->num_domains; i++)
		sunxi_pck600_on_clk(&pck->pds[i], false);

	return ret;
}

static const struct sunxi_pck600_pd_desc sun55i_a523_pck600_pds[] = {
	{ "VE", }, { "GPU", }, { "VI", }, { "VO0", }, { "VO1", },
	{ "DE", }, { "NAND", }, { "PCIE", },
};

static const struct sunxi_pck600_desc sun55i_a523_pck600_desc = {
	.pd_descs = sun55i_a523_pck600_pds,
	.num_domains = ARRAY_SIZE(sun55i_a523_pck600_pds),
	.logic_power_switch0_delay_offset = 0xc00,
	.logic_power_switch1_delay_offset = 0xc04,
	.off2on_delay_offset = 0xc10,
	.device_ctrl0_delay = 0xffffff,
	.device_ctrl1_delay = 0xffff,
	.logic_power_switch0_delay = 0x8080808,
	.logic_power_switch1_delay = 0x808,
	.off2on_delay = 0x8,
	.has_rst_clk = true,
};

static const struct sunxi_pck600_pd_desc sun60i_a733_pck600_pds[] = {
	{ "VI", }, { "DE_SYS", }, { "VE_DEC", }, { "VE_ENC", }, { "NPU", },
	/* GPU_CORE is treated as nested in GPU_TOP: with both off at boot,
	 * GPU_CORE alone timed out, and the vendor boot leaves both on.
	 * With GPU_TOP on it still timed out with the GPU clocks gated and
	 * its reset asserted, so the GPU is clocked and released for the
	 * transition when the provider node names them.
	 * Both are on demand (not always-on): off until the GPU device
	 * attaches, and switched off at probe if found on, unless
	 * gpu_core_always_on=1. GPU_TOP holds the GPU's bus master gates while
	 * it is on.
	 */
	{ "GPU_TOP", .on_clk = { "gpu-ahb", "gpu-mbus" }, .on_demand = true, },
	{ "GPU_CORE", 0, "GPU_TOP", "gpu", "gpu-bus", "gpu", .on_demand = true, },
	/* Cubie native SERDES holds the shared baseline while bound.
	 * System/runtime domain power-down needs coordinated lane consumers;
	 * retain these two domains until that contract is implemented/tested.
	 */
	{ "PCIE", GENPD_FLAG_ALWAYS_ON }, { "USB2", GENPD_FLAG_ALWAYS_ON },
	{ "VO", }, { "VO1", },
};

static const struct sunxi_pck600_desc sun60i_a733_pck600_desc = {
	.pd_descs = sun60i_a733_pck600_pds,
	.num_domains = ARRAY_SIZE(sun60i_a733_pck600_pds),
	.logic_power_switch0_delay_offset = 0xc00,
	.logic_power_switch1_delay_offset = 0xc04,
	.off2on_delay_offset = 0xc10,
	.device_ctrl0_delay = 0x1f1f1f,
	.device_ctrl1_delay = 0x1f1f,
	.logic_power_switch0_delay = 0x8080808,
	.logic_power_switch1_delay = 0x808,
	.off2on_delay = 0x8,
	.has_rst_clk = false,
};

static const struct of_device_id sunxi_pck600_of_match[] = {
	{
		.compatible	= "allwinner,sun55i-a523-pck-600",
		.data		= &sun55i_a523_pck600_desc,
	},
	{
		.compatible	= "allwinner,sun60i-a733-pck-600",
		.data		= &sun60i_a733_pck600_desc,
	},
	{}
};
MODULE_DEVICE_TABLE(of, sunxi_pck600_of_match);

static struct platform_driver sunxi_pck600_driver = {
	.probe = sunxi_pck600_probe,
	.driver = {
		.name   = "sunxi-pck-600",
		.of_match_table = sunxi_pck600_of_match,
		/* Power domains cannot be removed if in use. */
		.suppress_bind_attrs = true,
	},
};
/* genpd providers are permanent: no module-exit path may unmap live domains. */
static int __init sunxi_pck600_init(void)
{
	return platform_driver_register(&sunxi_pck600_driver);
}
module_init(sunxi_pck600_init);

MODULE_DESCRIPTION("Allwinner PCK-600 power domain driver");
MODULE_AUTHOR("Chen-Yu Tsai <wens@csie.org>");
MODULE_LICENSE("GPL");
