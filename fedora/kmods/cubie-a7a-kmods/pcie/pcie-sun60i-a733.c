// SPDX-License-Identifier: GPL-2.0-only
/* A733 Cubie A7A root complex, native Fedora DesignWare consumer.
 * Copyright(c) 2020 - 2023 Allwinner Technology Co.,Ltd. All rights reserved.
 * Register contract: alexcaoys/allwinner-bsp
 * 656a550c826787e7e72fae58ca793df9e0988ac8 pcie-sunxi-{plat,rc}.c/.h.
 * Use stock Linux DesignWare enumeration/iATU/MSI, and the paired native PHY.
 * PPU power-on is currently the identified oreboot prerequisite. No native
 * deep suspend, PME wake, eDMA, AER event handling or physical acceptance.
 */
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/reset.h>
#include "pcie-designware.h"

#define A7A_LTSSM 0xc00
#define A7A_LINK 0xe0c
#define A7A_MASK 0xe00
#define A7A_STATUS 0xe08
#define A7A_INTX GENMASK(8, 5)

enum a7a_hw_flag {
	A7A_RAILS, A7A_CONTROLLER, A7A_POWER, A7A_AUX, A7A_SLV,
	A7A_ITS_RESET, A7A_ITS_CLOCK, A7A_PHY_INIT, A7A_PHY_POWER, A7A_MMIO,
};
struct a7a_pcie {
	struct dw_pcie pci;
	void __iomem *app;
	struct clk_bulk_data clocks[3];
	struct reset_control_bulk_data resets[3];
	struct regulator_bulk_data supplies[2];
	struct gpio_desc *perst, *power, *wake;
	struct phy *phy;
	struct irq_domain *intx;
	raw_spinlock_t irq_lock;
	unsigned int flags;
	int app_irq;
	bool irq_requested;
};
#define a7a_from_pci(p) container_of(p, struct a7a_pcie, pci)

static void a7a_pcie_update(void __iomem *reg, u32 mask, u32 value)
{
	writel((readl(reg) & ~mask) | (value & mask), reg);
}

static bool a7a_pcie_link_up(struct dw_pcie *pci)
{
	struct a7a_pcie *pcie = a7a_from_pci(pci);

	return (readl(pcie->app + A7A_LINK) & 3) == 3;
}

static int a7a_pcie_start_link(struct dw_pcie *pci)
{
	struct a7a_pcie *pcie = a7a_from_pci(pci);

	/* DT describes physical PERST# as ACTIVE_LOW; logical 0 releases it.
	 * hw_on has already held it for the full CEM100ms power/refclk delay.
	 */
	gpiod_set_value_cansleep(pcie->perst, 0);
	a7a_pcie_update(pcie->app + A7A_LTSSM, BIT(0), BIT(0));
	return 0;
}

static void a7a_pcie_stop_link(struct dw_pcie *pci)
{
	struct a7a_pcie *pcie = a7a_from_pci(pci);

	a7a_pcie_update(pcie->app + A7A_LTSSM, BIT(0), 0);
	gpiod_set_value_cansleep(pcie->perst, 1);
}

static const struct dw_pcie_ops a7a_pcie_ops = {
	.link_up = a7a_pcie_link_up,
	.start_link = a7a_pcie_start_link,
	.stop_link = a7a_pcie_stop_link,
};

static void a7a_pcie_hw_off(struct a7a_pcie *pcie)
{
	unsigned int i;

	if (pcie->flags & BIT(A7A_MMIO)) {
		writel(0, pcie->app + A7A_MASK);
		a7a_pcie_stop_link(&pcie->pci);
	}
	gpiod_set_value_cansleep(pcie->perst, 1);
	/* DesignWare removes its chained MSI handler before this teardown.
	 * Drain any handler already running before clocking off its DBI MMIO.
	 */
	for (i = 0; i < MAX_MSI_CTRLS; i++)
		if (pcie->pci.pp.msi_irq[i] > 0)
			synchronize_irq(pcie->pci.pp.msi_irq[i]);
	if (pcie->flags & BIT(A7A_PHY_POWER))
		phy_power_off(pcie->phy);
	if (pcie->flags & BIT(A7A_PHY_INIT))
		phy_exit(pcie->phy);
	if (pcie->flags & BIT(A7A_ITS_CLOCK))
		clk_disable_unprepare(pcie->clocks[2].clk);
	if (pcie->flags & BIT(A7A_ITS_RESET))
		reset_control_assert(pcie->resets[2].rstc);
	if (pcie->flags & BIT(A7A_SLV))
		clk_disable_unprepare(pcie->clocks[1].clk);
	if (pcie->flags & BIT(A7A_AUX))
		clk_disable_unprepare(pcie->clocks[0].clk);
	if (pcie->flags & BIT(A7A_POWER))
		reset_control_assert(pcie->resets[1].rstc);
	if (pcie->flags & BIT(A7A_CONTROLLER))
		reset_control_assert(pcie->resets[0].rstc);
	if (pcie->flags & BIT(A7A_RAILS)) {
		gpiod_set_value_cansleep(pcie->power, 0);
		regulator_bulk_disable(ARRAY_SIZE(pcie->supplies), pcie->supplies);
	}
	pcie->flags = 0;
}

static int a7a_pcie_hw_on(struct a7a_pcie *pcie)
{
	int ret;

	ret = regulator_bulk_enable(ARRAY_SIZE(pcie->supplies), pcie->supplies);
	if (ret)
		return ret;
	pcie->flags |= BIT(A7A_RAILS);
	gpiod_set_value_cansleep(pcie->power, 1);
	ret = reset_control_deassert(pcie->resets[0].rstc);
	if (ret)
		goto fail;
	pcie->flags |= BIT(A7A_CONTROLLER);
	ret = reset_control_deassert(pcie->resets[1].rstc);
	if (ret)
		goto fail;
	pcie->flags |= BIT(A7A_POWER);
	ret = clk_prepare_enable(pcie->clocks[0].clk);
	if (ret)
		goto fail;
	pcie->flags |= BIT(A7A_AUX);
	ret = clk_set_rate(pcie->clocks[1].clk, 400000000);
	if (ret)
		goto fail;
	if (clk_get_rate(pcie->clocks[1].clk) != 400000000) {
		ret = -EINVAL;
		goto fail;
	}
	ret = clk_prepare_enable(pcie->clocks[1].clk);
	if (ret)
		goto fail;
	pcie->flags |= BIT(A7A_SLV);
	ret = reset_control_deassert(pcie->resets[2].rstc);
	if (ret)
		goto fail;
	pcie->flags |= BIT(A7A_ITS_RESET);
	ret = clk_prepare_enable(pcie->clocks[2].clk);
	if (ret)
		goto fail;
	pcie->flags |= BIT(A7A_ITS_CLOCK);
	ret = phy_set_mode(pcie->phy, PHY_MODE_PCIE);
	if (ret)
		goto fail;
	ret = phy_init(pcie->phy);
	if (ret)
		goto fail;
	pcie->flags |= BIT(A7A_PHY_INIT);
	ret = phy_power_on(pcie->phy);
	if (ret)
		goto fail;
	pcie->flags |= BIT(A7A_PHY_POWER) | BIT(A7A_MMIO);
	/* Replace the complete device-type field, preserving unrelated bits. */
	a7a_pcie_update(pcie->app + A7A_LTSSM, GENMASK(7, 4) | BIT(0), BIT(6));
	/* Native driver owns all SII sources; only INTx assertions are enabled
	 * by its IRQ chip. Unimplemented SII DMA/AER/link events remain masked.
	 */
	writel(0, pcie->app + A7A_MASK);
	writel(A7A_INTX, pcie->app + A7A_STATUS);
	msleep(PCIE_T_PVPERL_MS);
	return 0;
fail:
	a7a_pcie_hw_off(pcie);
	return ret;
}

static void a7a_intx_mask(struct irq_data *data)
{
	struct a7a_pcie *pcie = irq_data_get_irq_chip_data(data);
	unsigned long flags;
	u32 bit = BIT(irqd_to_hwirq(data) + 5);

	raw_spin_lock_irqsave(&pcie->irq_lock, flags);
	a7a_pcie_update(pcie->app + A7A_MASK, bit, 0);
	raw_spin_unlock_irqrestore(&pcie->irq_lock, flags);
}

static void a7a_intx_unmask(struct irq_data *data)
{
	struct a7a_pcie *pcie = irq_data_get_irq_chip_data(data);
	unsigned long flags;
	u32 bit = BIT(irqd_to_hwirq(data) + 5);

	raw_spin_lock_irqsave(&pcie->irq_lock, flags);
	/* W1C only this line: never read/OR/write the shared status register. */
	writel(bit, pcie->app + A7A_STATUS);
	a7a_pcie_update(pcie->app + A7A_MASK, bit, bit);
	raw_spin_unlock_irqrestore(&pcie->irq_lock, flags);
}

static struct irq_chip a7a_intx_chip = {
	.name = "a733-pcie-intx",
	.irq_mask = a7a_intx_mask,
	.irq_unmask = a7a_intx_unmask,
};

static int a7a_intx_map(struct irq_domain *domain, unsigned int irq, irq_hw_number_t hwirq)
{
	if (hwirq >= PCI_NUM_INTX)
		return -EINVAL;
	irq_set_chip_and_handler(irq, &a7a_intx_chip, handle_simple_irq);
	irq_set_chip_data(irq, domain->host_data);
	return 0;
}

static const struct irq_domain_ops a7a_intx_domain_ops = {
	.map = a7a_intx_map,
	.xlate = irq_domain_xlate_onecell,
};

static irqreturn_t a7a_pcie_irq(int irq, void *data)
{
	struct a7a_pcie *pcie = data;
	unsigned long flags;
	u32 pending;
	unsigned int i;

	raw_spin_lock_irqsave(&pcie->irq_lock, flags);
	pending = readl(pcie->app + A7A_MASK) & readl(pcie->app + A7A_STATUS) & A7A_INTX;
	writel(pending, pcie->app + A7A_STATUS);
	raw_spin_unlock_irqrestore(&pcie->irq_lock, flags);
	for (i = 0; i < PCI_NUM_INTX; i++)
		if (pending & BIT(i + 5))
			generic_handle_domain_irq(pcie->intx, i);
	return pending ? IRQ_HANDLED : IRQ_NONE;
}

static void a7a_intx_exit(struct a7a_pcie *pcie)
{
	writel(0, pcie->app + A7A_MASK);
	if (pcie->irq_requested) {
		devm_free_irq(pcie->pci.dev, pcie->app_irq, pcie);
		pcie->irq_requested = false;
	}
	if (pcie->intx) {
		irq_domain_remove(pcie->intx);
		pcie->intx = NULL;
	}
}

static int a7a_intx_init(struct a7a_pcie *pcie)
{
	struct device *dev = pcie->pci.dev;
	struct device_node *node;
	int ret;

	node = of_get_child_by_name(dev->of_node, "legacy-interrupt-controller");
	if (!node)
		return -EINVAL;
	pcie->intx = irq_domain_create_linear(of_fwnode_handle(node), PCI_NUM_INTX, &a7a_intx_domain_ops, pcie);
	of_node_put(node);
	if (!pcie->intx)
		return -ENOMEM;
	ret = devm_request_irq(dev, pcie->app_irq, a7a_pcie_irq, 0, dev_name(dev), pcie);
	if (ret) {
		irq_domain_remove(pcie->intx);
		pcie->intx = NULL;
		return ret;
	}
	pcie->irq_requested = true;
	return 0;
}

static const struct dw_pcie_host_ops a7a_host_ops = { };

static int a7a_pcie_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct a7a_pcie *pcie;
	struct resource *res;
	int ret;

	pcie = devm_kzalloc(dev, sizeof(*pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;
	pcie->pci.dev = dev;
	pcie->pci.ops = &a7a_pcie_ops;
	pcie->pci.mode = DW_PCIE_RC_TYPE;
	/* Do not set DW_PCIE_CAP_REQ_RES: this glue owns clocks, resets and
	 * PERST. A second generic reset-GPIO acquisition would conflict.
	 */
	pcie->pci.pp.ops = &a7a_host_ops;
	pcie->pci.pp.num_vectors = MAX_MSI_IRQS;
	platform_set_drvdata(pdev, pcie);
	raw_spin_lock_init(&pcie->irq_lock);
	/* Require disjoint mappings, including app and the complete16-pair ATU.
	 * No DBI+offset access beyond a short virtual mapping is permitted.
	 */
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "app");
	if (!res || resource_size(res) < 0x1000)
		return -EINVAL;
	pcie->app = devm_ioremap_resource(dev, res);
	if (IS_ERR(pcie->app))
		return PTR_ERR(pcie->app);
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "atu");
	if (!res || resource_size(res) < 0x2000)
		return -EINVAL;
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "dbi");
	if (!res || resource_size(res) < 0x1000)
		return -EINVAL;
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "config");
	if (!res || resource_size(res) < 0x10000)
		return -EINVAL;
	pcie->app_irq = platform_get_irq_byname(pdev, "app");
	if (pcie->app_irq < 0)
		return pcie->app_irq;
	pcie->pci.pp.irq = platform_get_irq_byname(pdev, "msi");
	if (pcie->pci.pp.irq < 0)
		return pcie->pci.pp.irq;
	pcie->phy = devm_phy_get(dev, "pcie-phy");
	if (IS_ERR(pcie->phy))
		return dev_err_probe(dev, PTR_ERR(pcie->phy), "paired PCIe PHY\n");
	if (!of_property_present(dev->of_node, "pcie1v8-supply") ||
	    !of_property_present(dev->of_node, "pcie3v3-supply"))
		return -EINVAL;
	pcie->supplies[0].supply = "pcie1v8";
	pcie->supplies[1].supply = "pcie3v3";
	ret = devm_regulator_bulk_get(dev, ARRAY_SIZE(pcie->supplies), pcie->supplies);
	if (ret)
		return ret;
	pcie->clocks[0].id = "aux";
	pcie->clocks[1].id = "slv";
	/* ITS PCIe AXI master clock, generic DW binding name. */
	pcie->clocks[2].id = "mstr";
	ret = devm_clk_bulk_get(dev, ARRAY_SIZE(pcie->clocks), pcie->clocks);
	if (ret)
		return ret;
	pcie->resets[0].id = "app";
	pcie->resets[1].id = "pwr";
	/* ITS core reset. */
	pcie->resets[2].id = "core";
	ret = devm_reset_control_bulk_get_exclusive(dev, ARRAY_SIZE(pcie->resets), pcie->resets);
	if (ret)
		return ret;
	pcie->perst = devm_gpiod_get(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(pcie->perst))
		return PTR_ERR(pcie->perst);
	pcie->power = devm_gpiod_get(dev, "power", GPIOD_OUT_LOW);
	if (IS_ERR(pcie->power))
		return PTR_ERR(pcie->power);
	/* WAKE# is an endpoint output. Reserve it as an input; native wake
	 * interrupt/PME suspend routing remains unsupported, not advertised.
	 */
	pcie->wake = devm_gpiod_get(dev, "wake", GPIOD_IN);
	if (IS_ERR(pcie->wake))
		return PTR_ERR(pcie->wake);
	ret = a7a_pcie_hw_on(pcie);
	if (ret)
		return dev_err_probe(dev, ret, "PCIe hardware initialization\n");
	ret = a7a_intx_init(pcie);
	if (ret)
		goto off;
	ret = dw_pcie_host_init(&pcie->pci.pp);
	if (ret) {
		a7a_intx_exit(pcie);
		goto off;
	}
	return 0;
off:
	a7a_pcie_hw_off(pcie);
	return ret;
}

static void a7a_pcie_remove(struct platform_device *pdev)
{
	struct a7a_pcie *pcie = platform_get_drvdata(pdev);

	dw_pcie_host_deinit(&pcie->pci.pp);
	a7a_intx_exit(pcie);
	a7a_pcie_hw_off(pcie);
}

static void a7a_pcie_shutdown(struct platform_device *pdev)
{
	struct a7a_pcie *pcie = platform_get_drvdata(pdev);
	unsigned int i;

	/* Shutdown callbacks do not free endpoint IRQ mappings. Quiesce their
	 * parent interrupts and endpoint, retaining clocked controller/PHY/rail
	 * resources until firmware reset. Do not remove live IRQ domains or
	 * expose a pending MSI handler to clock-gated MMIO during shutdown.
	 */
	writel(0, pcie->app + A7A_MASK);
	disable_irq(pcie->app_irq);
	for (i = 0; i < MAX_MSI_CTRLS; i++)
		if (pcie->pci.pp.msi_irq[i] > 0)
			disable_irq(pcie->pci.pp.msi_irq[i]);
	a7a_pcie_stop_link(&pcie->pci);
}

static const struct of_device_id a7a_pcie_match[] = {
	{ .compatible = "allwinner,sun60i-a733-cubie-a7a-pcie" },
	{ }
};
MODULE_DEVICE_TABLE(of, a7a_pcie_match);
static struct platform_driver a7a_pcie_driver = {
	.probe = a7a_pcie_probe,
	.remove = a7a_pcie_remove,
	.shutdown = a7a_pcie_shutdown,
	.driver = {
		.name = "sun60i-a733-pcie",
		.of_match_table = a7a_pcie_match,
		.suppress_bind_attrs = true,
	},
};
module_platform_driver(a7a_pcie_driver);
MODULE_DESCRIPTION("A733 fixed A7A native DesignWare root complex");
MODULE_LICENSE("GPL");
