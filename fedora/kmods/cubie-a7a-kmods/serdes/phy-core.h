/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2020 - 2023 Allwinner Technology Co.,Ltd. All rights reserved.
 * Copyright (C) 2024 Allwinner Electronics Co., Ltd.
 * Fixed A7A lane sequences from pinned sunxi-cadence-combophy.c; no DP
 * connector, Type-C switching, SSC override or common-reset ownership here.
 * The caller serializes both lanes and supplies powered, clocked mappings.
 */
#include "tables.h"

struct a7a_serdes_io {
	void __iomem *subsys, *map, *top[2], *csr[2], *u2, *rescal;
};

static void a7a_update(void __iomem *reg, u32 mask, u32 value)
{
	writel((readl(reg) & ~mask) | (value & mask), reg);
}

/* Captured A7A sunxi-plat-phy v1, rext_mode2, tune143338d6. Offsets in
 * rescal are relative to SYSCFG+0x160. Only this owner accesses shared
 * calibration; retain it across USB exit so PCIe cannot lose its trim.
 * Invoke after the DWC3 consumer has enabled its bus/reference clocks.
 */
static void a7a_usb2_start(struct a7a_serdes_io *io)
{
	a7a_update(io->rescal, BIT(0) | BIT(10), BIT(10));
	a7a_update(io->rescal + 8, GENMASK(15, 8), 0);
	a7a_update(io->u2 + 0x10, BIT(10) | BIT(5) | BIT(3), BIT(10) | BIT(5));
	writel(0x143338d6, io->u2 + 0x18);
}

static void a7a_usb2_park(struct a7a_serdes_io *io)
{
	/* Lane-local SIDDQ only. No shared calibration/reset/clock changes. */
	a7a_update(io->u2 + 0x10, BIT(10) | BIT(5) | BIT(3), BIT(3));
}

static int a7a_poll(void __iomem *reg, u32 mask, u32 value, unsigned int us)
{
	u32 v;

	return readl_poll_timeout(reg, v, (v & mask) == value, 5, us);
}

static void a7a_table(struct a7a_serdes_io *io, unsigned int lane,
		      const struct a7a_op *ops, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (ops[i].kind == A7A_CSR16)
			writew(ops[i].value, io->csr[lane] + ops[i].offset);
		else
			a7a_update(io->top[lane] + ops[i].offset,
				   ops[i].mask, ops[i].value);
	}
}

/* Do not touch shared SERDES reset, clocks, USB2 UTMI, or the other lane.
 * PCIe stop reverses only the two local reset releases in its BSP sequence.
 * The Linux PCIe consumer must stop its controller before phy_exit().
 */
static void a7a_lane_park(struct a7a_serdes_io *io, unsigned int lane)
{
	void __iomem *top = io->top[lane];

	if (lane == 0) {
		a7a_update(top, BIT(0) | BIT(4) | BIT(8), 0);
		a7a_update(top + 0xc, BIT(0) | GENMASK(9, 4), 0);
		a7a_update(top + 8, 3, 3);
		a7a_update(io->map + 0x100, 0xf, 0xf);
		a7a_update(io->map + 0x104, 0xf, 0xf);
	} else {
		a7a_update(top + 0x100, BIT(0), 0);
		a7a_update(top, BIT(0), 0);
	}
}

static int a7a_usb_start(struct a7a_serdes_io *io)
{
	void __iomem *top = io->top[0], *csr = io->csr[0];
	int ret;

	/* Full USB3 uses the combo PIPE, with the USB2 PHY UTMI. Keep the
	 * USB2 reset released even when USB3 exits or fails.
	 */
	a7a_update(io->subsys + 8, BIT(21) | BIT(20) | BIT(17) | BIT(16) | BIT(4),
		   BIT(17) | BIT(16) | BIT(4));
	udelay(10);
	a7a_update(top, BIT(0) | BIT(4) | BIT(5) | BIT(8), 0);
	usleep_range(1000, 1100);
	a7a_update(top + 8, 3, 0);
	a7a_update(top + 4, BIT(24) | BIT(20) | BIT(0), BIT(24) | BIT(20) | BIT(0));
	a7a_update(io->map + 0x100, 0xf, 0);
	a7a_update(io->map + 0x104, 0xf, 0);
	a7a_table(io, 0, a7a_usb_table, ARRAY_SIZE(a7a_usb_table));
	/* Fixed blue Type-A normal routing. Orientation is static in reset. */
	a7a_update(top, BIT(12), 0);
	a7a_update(top, BIT(0), BIT(0));
	ret = a7a_poll(top, BIT(0), BIT(0), 1000);
	if (ret)
		return ret;
	a7a_update(io->map + 4, BIT(0) | GENMASK(11, 4), BIT(0) | GENMASK(11, 4));
	usleep_range(1000, 1100);
	a7a_update(top, BIT(4), BIT(4));
	a7a_update(top + 0xc, BIT(0), BIT(0));
	ret = a7a_poll(top + 0xc, BIT(0), BIT(0), 1000);
	if (ret)
		return ret;
	a7a_update(top + 0xc, GENMASK(9, 4), BIT(4));
	a7a_update(top, BIT(8), BIT(8));
	if (!(readl(top + 0x900) & BIT(0))) {
		usleep_range(10000, 11000);
		writew(readw(csr + 0x18010) & ~GENMASK(11, 8), csr + 0x18010);
		return a7a_poll(top + 0x900, BIT(0), BIT(0), 5000);
	}
	return 0;
}

static int a7a_pcie_start(struct a7a_serdes_io *io)
{
	void __iomem *top = io->top[1], *csr = io->csr[1];
	int ret;

	/* PCIe's own gates, reference auto-gate override and PIPE route only. */
	a7a_update(io->subsys + 4, GENMASK(18, 16), GENMASK(18, 16));
	a7a_update(io->subsys + 0xf0, BIT(29), BIT(29));
	writel(1, io->map + 0xc44);
	a7a_lane_park(io, 1);
	a7a_table(io, 1, a7a_pcie_table, ARRAY_SIZE(a7a_pcie_table));
	/* The pinned BSP explicitly uses 32-bit access for these three CSRs. */
	a7a_update(csr + 0x98, 3, 2);
	a7a_update(csr + 0xa8, 3, 2);
	a7a_update(csr + 0xd8, 3, 2);
	a7a_update(top, BIT(0), BIT(0));
	a7a_update(top + 0x100, BIT(0), BIT(0));
	ret = a7a_poll(top + 0x900, BIT(0), BIT(0), 100000);
	if (ret)
		return ret;
	writew(0x270, csr + 0xa0);
	writew(readw(csr + 0x98) | BIT(4), csr + 0x98);
	writew(readw(csr + 0x18000) | BIT(0), csr + 0x18000);
	a7a_update(top + 4, BIT(28), BIT(28));
	return 0;
}

static int a7a_lane_start(struct a7a_serdes_io *io, unsigned int lane)
{
	int ret = lane ? a7a_pcie_start(io) : a7a_usb_start(io);

	if (ret)
		a7a_lane_park(io, lane);
	return ret;
}
