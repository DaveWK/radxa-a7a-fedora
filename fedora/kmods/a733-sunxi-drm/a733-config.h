/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Build configuration for the out-of-tree A733 (sun60iw2) HDMI-only build of
 * the Allwinner sunxi-drm driver. These stand in for the vendor Kconfig
 * symbols; everything not listed is off (DSI, LVDS, RGB, eDP, DE offline
 * mode, vendor IOMMU, vendor SMC, extcon reporting).
 */
#ifndef A733_SUNXI_DRM_CONFIG_H
#define A733_SUNXI_DRM_CONFIG_H

#define CONFIG_ARCH_SUN60IW2		1
#define CONFIG_AW_DRM			1
#define CONFIG_AW_DRM_DE		1
#define CONFIG_AW_DRM_TCON		1
#define CONFIG_AW_DRM_TCON_TV		1
#define CONFIG_AW_DRM_TCON_TOP		1
#define CONFIG_AW_DRM_HDMI_TX		1
#define CONFIG_AW_DRM_HDMI20		1
#define CONFIG_AW_DRM_BOOT_COLORBAR	0
/*
 * CONFIG_AW_DRM_DE_OFFLINE_MODE (DE write-back composition) stays undefined:
 * the DE code stubs it out and sunxi_drm_drv.c skips its pre-init.
 */

/*
 * The vendor HDMI code reports hot-plug through an extcon device as well and
 * reaches into drivers/extcon/extcon.h to name it. KMS hot-plug events are
 * enough here, so that block is compiled out for this module.
 */
#undef CONFIG_EXTCON

#endif
