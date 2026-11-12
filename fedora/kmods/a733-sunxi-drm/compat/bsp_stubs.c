// SPDX-License-Identifier: GPL-2.0-only
/*
 * Answers for vendor-kernel interfaces the stock kernel does not have, and
 * for the parts of the driver left out of this build.
 */
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "sunxi-sid.h"
#include "dw_dev.h"
#include "dw_hdcp22.h"

/*
 * The sub-device drivers only join the component master if they are bound
 * when the master probes, and they defer until their power domains exist.
 */
MODULE_SOFTDEP("pre: sun55i-pck600");

/* SID: only DE v350 and the Innosilicon HDMI PHY ask; neither is the A733. */
unsigned int sunxi_get_soc_ver(void)
{
	return 0;
}

unsigned int sunxi_get_soc_markid(void)
{
	return 0;
}

/*
 * HDCP 2.x: dw_hdcp22.c and the ESM host library are not built (they need
 * the vendor's ESM firmware image). Report "no firmware, not encrypting".
 * The two data-path accessors are the vendor's own register writes, kept
 * because the HDCP 1.x code uses them to pin the controller to its 1.x path.
 */
void dw_hdcp2x_ovr_set_path(u8 ovr_val, u8 ovr_en)
{
	dw_write_mask(HDCP22REG_CTRL, HDCP22REG_CTRL_HDCP22_OVR_VAL_MASK, ovr_val);
	dw_write_mask(HDCP22REG_CTRL, HDCP22REG_CTRL_HDCP22_OVR_EN_MASK, ovr_en);
}

u8 dw_hdcp2x_get_path(void)
{
	return dw_read_mask(HDCP22REG_STS, HDCP22REG_STS_HDCP22_SWITCH);
}

int dw_hdcp2x_get_encrypt_state(void)
{
	return DW_HDCP_DISABLE;
}

int dw_hdcp2x_enable(void)
{
	return -ENODEV;
}

int dw_hdcp2x_disable(void)
{
	return 0;
}

int dw_hdcp2x_firmware_state(void)
{
	return 0;	/* not loaded */
}

int dw_hdcp2x_firmware_update(const u8 *data, size_t size)
{
	return -ENODEV;
}

int dw_hdcp2x_init(void)
{
	return 0;
}

void dw_hdcp2x_exit(void)
{
}

ssize_t dw_hdcp2x_dump(char *buf)
{
	return sprintf(buf, "hdcp2x: not built\n");
}
