// SPDX-License-Identifier: GPL-2.0-only
/*
 * A733 fixed Cubie A7A USB0 / PCIe1 combo PHY provider.
 * Copyright(c) 2020 - 2023 Allwinner Technology Co.,Ltd. All rights reserved.
 * Copyright (C) 2024 Allwinner Electronics Co., Ltd.
 *
 * The register sequences derive from sunxi-cadence-combophy.c at
 * alexcaoys/allwinner-bsp 656a550c826787e7e72fae58ca793df9e0988ac8.
 * USB2 analog controls use that pin's drivers/usb/dwc3/phy-sunxi-plat.c,
 * selected by the captured A7A v1-compatible/rext_mode2/tune143338d6 node.
 * This driver deliberately has one shared resource owner. Neither child's
 * exit, failed handshake, nor DWC3 system suspend asserts the shared reset.
 * Keep common power/clocks while bound: safe retention is a baseline, not
 * deep-sleep or optimal-power support. No DP/Type-C mode switching is exposed.
 */
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/reset.h>
#include <dt-bindings/phy/phy.h>

#include "phy-core.h"

struct a7a_serdes;
struct a7a_lane {
	struct a7a_serdes *parent;
	unsigned int index;
};

struct a7a_serdes {
	struct a7a_serdes_io io;
	struct mutex lock;
	struct clk_bulk_data clocks[6];
	struct reset_control *reset;
	struct regulator *supply;
	struct phy *phys[3];
	struct a7a_lane lanes[3];
};

static int a7a_phy_init(struct phy *phy)
{
	struct a7a_lane *lane = phy_get_drvdata(phy);
	struct a7a_serdes *parent = lane->parent;
	int ret;

	mutex_lock(&parent->lock);
	if (lane->index == 2) {
		a7a_usb2_start(&parent->io);
		ret = 0;
	} else {
		ret = a7a_lane_start(&parent->io, lane->index);
	}
	mutex_unlock(&parent->lock);
	return ret;
}

static int a7a_phy_exit(struct phy *phy)
{
	struct a7a_lane *lane = phy_get_drvdata(phy);
	struct a7a_serdes *parent = lane->parent;

	mutex_lock(&parent->lock);
	if (lane->index == 2)
		a7a_usb2_park(&parent->io);
	else
		a7a_lane_park(&parent->io, lane->index);
	mutex_unlock(&parent->lock);
	return 0;
}

static int a7a_phy_set_mode(struct phy *phy, enum phy_mode mode, int submode)
{
	struct a7a_lane *lane = phy_get_drvdata(phy);

	if (submode)
		return -EINVAL;
	if (lane->index == 1)
		return mode == PHY_MODE_PCIE ? 0 : -EINVAL;
	if (lane->index == 2)
		return mode == PHY_MODE_USB_HOST || mode == PHY_MODE_USB_HOST_HS ? 0 : -EINVAL;
	return mode == PHY_MODE_USB_HOST || mode == PHY_MODE_USB_HOST_SS ? 0 : -EINVAL;
}

static const struct phy_ops a7a_phy_ops = {
	.init = a7a_phy_init,
	.exit = a7a_phy_exit,
	.set_mode = a7a_phy_set_mode,
	.owner = THIS_MODULE,
};

static struct phy *a7a_phy_xlate(struct device *dev, const struct of_phandle_args *args)
{
	struct a7a_serdes *parent = dev_get_drvdata(dev);

	if (args->args_count != 1)
		return ERR_PTR(-EINVAL);
	switch (args->args[0]) {
	case PHY_TYPE_USB3:
		return parent->phys[0];
	case PHY_TYPE_PCIE:
		return parent->phys[1];
	case PHY_TYPE_USB2:
		return parent->phys[2];
	default:
		return ERR_PTR(-EINVAL);
	}
}

static void a7a_supply_off(void *data)
{
	regulator_disable(data);
}

static void a7a_clocks_off(void *data)
{
	struct a7a_serdes *parent = data;

	clk_bulk_disable_unprepare(ARRAY_SIZE(parent->clocks), parent->clocks);
}

static void a7a_reset_assert(void *data)
{
	reset_control_assert(data);
}

static void __iomem *a7a_map(struct platform_device *pdev, const char *name,
			   resource_size_t minimum)
{
	struct resource *res = platform_get_resource_byname(pdev, IORESOURCE_MEM, name);

	if (!res || resource_size(res) < minimum)
		return ERR_PTR(-EINVAL);
	return devm_ioremap_resource(&pdev->dev, res);
}

static int a7a_serdes_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct phy_provider *provider;
	struct a7a_serdes *parent;
	static const char * const names[] = { "bus", "mbus", "cfg", "ref0", "ref1", "rescal" };
	unsigned int i;
	int ret;

	parent = devm_kzalloc(dev, sizeof(*parent), GFP_KERNEL);
	if (!parent)
		return -ENOMEM;
	mutex_init(&parent->lock);
	platform_set_drvdata(pdev, parent);
	parent->io.subsys = a7a_map(pdev, "subsys", 0x400);
	if (IS_ERR(parent->io.subsys))
		return PTR_ERR(parent->io.subsys);
	parent->io.map = a7a_map(pdev, "map", 0x2000);
	if (IS_ERR(parent->io.map))
		return PTR_ERR(parent->io.map);
	parent->io.top[0] = a7a_map(pdev, "combo0-top", 0xa00);
	if (IS_ERR(parent->io.top[0]))
		return PTR_ERR(parent->io.top[0]);
	parent->io.csr[0] = a7a_map(pdev, "combo0-phy", 0x20000);
	if (IS_ERR(parent->io.csr[0]))
		return PTR_ERR(parent->io.csr[0]);
	parent->io.top[1] = a7a_map(pdev, "combo1-top", 0xa00);
	if (IS_ERR(parent->io.top[1]))
		return PTR_ERR(parent->io.top[1]);
	parent->io.csr[1] = a7a_map(pdev, "combo1-phy", 0x20000);
	if (IS_ERR(parent->io.csr[1]))
		return PTR_ERR(parent->io.csr[1]);
	parent->io.u2 = a7a_map(pdev, "usb2-phy", 0x800);
	if (IS_ERR(parent->io.u2))
		return PTR_ERR(parent->io.u2);
	parent->io.rescal = a7a_map(pdev, "rescal", 0xc);
	if (IS_ERR(parent->io.rescal))
		return PTR_ERR(parent->io.rescal);

	/* Every provider must exist before any MMIO: no dummy supply or silent
	 * firmware-clock fallback. DCXO refs come from the native RTC CCU.
	 */
	if (!of_property_present(dev->of_node, "serdes1v8-supply"))
		return dev_err_probe(dev, -EINVAL, "missing SERDES1v8 supply\n");
	parent->supply = devm_regulator_get(dev, "serdes1v8");
	if (IS_ERR(parent->supply))
		return dev_err_probe(dev, PTR_ERR(parent->supply), "SERDES1v8 supply\n");
	for (i = 0; i < ARRAY_SIZE(names); i++)
		parent->clocks[i].id = names[i];
	ret = devm_clk_bulk_get(dev, ARRAY_SIZE(parent->clocks), parent->clocks);
	if (ret)
		return dev_err_probe(dev, ret, "SERDES clocks\n");
	parent->reset = devm_reset_control_get_exclusive(dev, "serdes");
	if (IS_ERR(parent->reset))
		return dev_err_probe(dev, PTR_ERR(parent->reset), "SERDES reset\n");
	ret = regulator_set_voltage(parent->supply, 1800000, 1800000);
	if (ret)
		return ret;
	ret = regulator_enable(parent->supply);
	if (ret)
		return ret;
	ret = devm_add_action_or_reset(dev, a7a_supply_off, parent->supply);
	if (ret)
		return ret;
	ret = clk_set_rate(parent->clocks[2].clk, 100000000);
	if (ret)
		return ret;
	if (clk_get_rate(parent->clocks[2].clk) != 100000000)
		return dev_err_probe(dev, -EINVAL, "SERDES requires 100 MHz\n");
	ret = clk_bulk_prepare_enable(ARRAY_SIZE(parent->clocks), parent->clocks);
	if (ret)
		return ret;
	ret = devm_add_action_or_reset(dev, a7a_clocks_off, parent);
	if (ret)
		return ret;
	/* Never cycle the common reset on warm firmware handoff. */
	ret = reset_control_deassert(parent->reset);
	if (ret)
		return ret;
	ret = devm_add_action_or_reset(dev, a7a_reset_assert, parent->reset);
	if (ret)
		return ret;
	/* Stock DWC3 reads its core ID before phy_init(). Its child is created
	 * only after these bus gates are live. Retain USB2 UTMI and leave the
	 * mode selectors unchanged until the USB lane consumer starts it.
	 */
	a7a_update(parent->io.subsys + 8, BIT(17) | BIT(16) | BIT(4),
		   BIT(17) | BIT(16) | BIT(4));
	for (i = 0; i < ARRAY_SIZE(parent->phys); i++) {
		parent->lanes[i].parent = parent;
		parent->lanes[i].index = i;
		parent->phys[i] = devm_phy_create(dev, dev->of_node, &a7a_phy_ops);
		if (IS_ERR(parent->phys[i]))
			return PTR_ERR(parent->phys[i]);
		phy_set_drvdata(parent->phys[i], &parent->lanes[i]);
	}
	/* Populate before publishing the PHY provider: no fallible step follows
	 * publication, so PCIe cannot acquire a PHY from a failed parent probe.
	 * DWC3 may read its now-clocked ID, then defer its PHY lookup until the
	 * provider is registered. Managed child removal precedes PHY destruction
	 * and common resource cleanup; provider lookup is unpublished first.
	 */
	ret = devm_of_platform_populate(dev);
	if (ret)
		return ret;
	provider = devm_of_phy_provider_register(dev, a7a_phy_xlate);
	return PTR_ERR_OR_ZERO(provider);
}

static const struct of_device_id a7a_serdes_match[] = {
	{ .compatible = "allwinner,sun60i-a733-cubie-a7a-serdes" },
	{ }
};
MODULE_DEVICE_TABLE(of, a7a_serdes_match);

static struct platform_driver a7a_serdes_driver = {
	.probe = a7a_serdes_probe,
	.driver = {
		.name = "sun60i-a733-serdes",
		.of_match_table = a7a_serdes_match,
		.suppress_bind_attrs = true,
	},
};
module_platform_driver(a7a_serdes_driver);
MODULE_DESCRIPTION("A733 fixed A7A USB2 and paired USB3/PCIe PHY provider");
MODULE_LICENSE("GPL");
