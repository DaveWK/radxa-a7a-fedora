/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Stand-in for the vendor kernel's SID (efuse) interface. The stock kernel
 * has no SoC revision query of this shape; compat/bsp_stubs.c answers these.
 * Neither caller is on the A733 path (DE v350 bridge setup, Innosilicon PHY).
 */
#ifndef A733_SUNXI_DRM_SUNXI_SID_H
#define A733_SUNXI_DRM_SUNXI_SID_H

unsigned int sunxi_get_soc_ver(void);
unsigned int sunxi_get_soc_markid(void);

#endif
