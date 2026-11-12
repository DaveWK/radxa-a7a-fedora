// SPDX-License-Identifier: GPL-2.0
/*
 * Cedrus VPU driver
 *
 * Copyright (C) 2016 Florent Revest <florent.revest@free-electrons.com>
 * Copyright (C) 2018 Paul Kocialkowski <paul.kocialkowski@bootlin.com>
 * Copyright (C) 2018 Bootlin
 *
 * Based on the vim2m driver, that is:
 *
 * Copyright (c) 2009-2010 Samsung Electronics Co., Ltd.
 * Pawel Osciak, <pawel@osciak.com>
 * Marek Szyprowski, <m.szyprowski@samsung.com>
 */

#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/clk.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <linux/io.h>

#include <media/videobuf2-core.h>
#include <media/v4l2-mem2mem.h>

#include "cedrus.h"
#include "cedrus_hw.h"
#include "cedrus_regs.h"

/*
 * a733-cedrus: system control (0x03000000) and VE top registers, as the
 * vendor cedar_ve driver writes them for sun60iw2.
 */
#define A733_SYSCFG_VE_SRAM_REG		0x0
#define A733_SYSCFG_VE_SRAM_CPU		BIT(0)
#define A733_SYSCFG_SRAM_C_REG		0x4
#define A733_SYSCFG_SRAM_C_CPU		BIT(24)

#define A733_VE_TOP_RESET		0x804
#define A733_VE_TOP_RESET_VCU		(BIT(0) | BIT(4))

/*
 * Hand the VE SRAMs from the CPU to the decoder. Fedora's sunxi_sram has no
 * A733 system-control entry, so sunxi_sram_claim() cannot do it; the two
 * bits are the ones the H616 "VE" section (reg 0x0 bit 0) and the A64 "C"
 * section (reg 0x4 bit 24) describe there, 1 = CPU, 0 = device.
 */
static void cedrus_a733_sram_claim(struct cedrus_dev *dev)
{
	u32 val;

	if (!dev->syscfg)
		return;

	val = readl(dev->syscfg + A733_SYSCFG_VE_SRAM_REG);
	writel(val & ~A733_SYSCFG_VE_SRAM_CPU,
	       dev->syscfg + A733_SYSCFG_VE_SRAM_REG);

	val = readl(dev->syscfg + A733_SYSCFG_SRAM_C_REG);
	writel(val & ~A733_SYSCFG_SRAM_C_CPU,
	       dev->syscfg + A733_SYSCFG_SRAM_C_REG);
}

/*
 * Read the version registers once and report them. No source says which
 * Cedar generation the A733 carries, and the vendor H.265 library switches
 * register details on the decoder IP version (cedrus_h265.c). Needs the
 * block clocked and out of reset.
 */
static void cedrus_a733_read_ip_version(struct cedrus_dev *dev)
{
	u32 version, dec = 0, enc = 0;

	if (dev->ip_version_read)
		return;

	version = cedrus_read(dev, VE_VERSION);
	if (!version || version == VE_VERSION_UNUSED) {
		dec = cedrus_read(dev, VE_DEC_IP_VERSION);
		enc = cedrus_read(dev, VE_ENC_IP_VERSION);
		dev->dec_ip_version = dec & VE_IP_VERSION_MASK;
		dev->enc_ip_version = enc & VE_IP_VERSION_MASK;
	}
	dev->ip_version_read = true;

	dev_info(dev->dev,
		 "VE version %#010x, decoder IP %#x, encoder IP %#x\n",
		 version, dec, enc);
}

/* Pulse the VCU reset bits; needs the block clocked and out of reset. */
static void cedrus_a733_vcu_reset(struct cedrus_dev *dev)
{
	u32 val;

	val = cedrus_read(dev, A733_VE_TOP_RESET);
	cedrus_write(dev, A733_VE_TOP_RESET, val | A733_VE_TOP_RESET_VCU);

	val = cedrus_read(dev, A733_VE_TOP_RESET);
	cedrus_write(dev, A733_VE_TOP_RESET, val & ~A733_VE_TOP_RESET_VCU);
}

/*
 * a733-cedrus: the vendor's engine reset sets bit 10 of the mode register
 * for these three decoder/encoder IP version pairs only (libVE.so, VeReset
 * 0x7adc-0x7b2c). Meaning unknown.
 */
static bool cedrus_a733_mode_bit10(struct cedrus_dev *dev)
{
	static const struct {
		u32 dec;
		u32 enc;
	} versions[] = {
		{ 0x33310, 0x21320 },
		{ 0x33210, 0x12011 },
		{ 0x33321, 0x21321 },
	};
	unsigned int i;

	if (!(dev->quirks & CEDRUS_QUIRK_A733))
		return false;

	for (i = 0; i < ARRAY_SIZE(versions); i++)
		if (dev->dec_ip_version == versions[i].dec &&
		    dev->enc_ip_version == versions[i].enc)
			return true;

	return false;
}

int cedrus_engine_enable(struct cedrus_ctx *ctx)
{
	u32 reg = 0;

	/*
	 * FIXME: This is only valid on 32-bits DDR's, we should test
	 * it on the A13/A33.
	 */
	reg |= VE_MODE_REC_WR_MODE_2MB;
	reg |= VE_MODE_DDR_MODE_BW_128;

	switch (ctx->src_fmt.pixelformat) {
	/* MPEG-2 and JPEG both use the MPEG engine. */
	case V4L2_PIX_FMT_MPEG2_SLICE:
	case V4L2_PIX_FMT_JPEG:
		reg |= VE_MODE_DEC_MPEG;
		break;

	/* H.264 and VP8 both use the same decoding mode bit. */
	case V4L2_PIX_FMT_H264_SLICE:
	case V4L2_PIX_FMT_VP8_FRAME:
		reg |= VE_MODE_DEC_H264;
		break;

	case V4L2_PIX_FMT_HEVC_SLICE:
		reg |= VE_MODE_DEC_H265;
		break;

	/*
	 * VP9 runs in the H.265 engine: the vendor decoders of the H616 and
	 * of the A733 both select it for VP9. The H616 one also sets bits 31
	 * and 30, the A733 one doesn't.
	 */
	case V4L2_PIX_FMT_VP9_FRAME:
		reg |= VE_MODE_DEC_H265;
		if (cedrus_vp9_h616_sequence)
			reg |= VE_MODE_RAMPD | VE_MODE_H616_VP9_RESERVED;
		break;

	default:
		return -EINVAL;
	}

	if (ctx->src_fmt.width == 4096)
		reg |= VE_MODE_PIC_WIDTH_IS_4096;
	if (ctx->src_fmt.width > 2048)
		reg |= VE_MODE_PIC_WIDTH_MORE_2048;

	if (cedrus_a733_mode_bit10(ctx->dev))
		reg |= VE_MODE_A733_BIT10;

	cedrus_write(ctx->dev, VE_MODE, reg);

	return 0;
}

void cedrus_engine_disable(struct cedrus_dev *dev)
{
	cedrus_write(dev, VE_MODE, VE_MODE_DISABLED);
}

void cedrus_dst_format_set(struct cedrus_dev *dev,
			   struct v4l2_pix_format *fmt)
{
	unsigned int width = fmt->width;
	unsigned int height = fmt->height;
	u32 chroma_size;
	u32 reg;

	switch (fmt->pixelformat) {
	case V4L2_PIX_FMT_NV12:
	case V4L2_PIX_FMT_NV21:
	case V4L2_PIX_FMT_YUV420:
	case V4L2_PIX_FMT_YVU420:
		chroma_size = ALIGN(width, 16) * ALIGN(height, 16) / 2;

		switch (fmt->pixelformat) {
		case V4L2_PIX_FMT_NV12:
			reg = VE_PRIMARY_OUT_FMT_NV12;
			break;
		case V4L2_PIX_FMT_NV21:
			reg = VE_PRIMARY_OUT_FMT_NV21;
			break;
		case V4L2_PIX_FMT_YUV420:
			reg = VE_PRIMARY_OUT_FMT_YU12;
			break;
		case V4L2_PIX_FMT_YVU420:
		default:
			reg = VE_PRIMARY_OUT_FMT_YV12;
			break;
		}
		cedrus_write(dev, VE_PRIMARY_OUT_FMT, reg);

		reg = chroma_size / 2;
		cedrus_write(dev, VE_PRIMARY_CHROMA_BUF_LEN, reg);

		reg = VE_PRIMARY_FB_LINE_STRIDE_LUMA(ALIGN(width, 16)) |
		      VE_PRIMARY_FB_LINE_STRIDE_CHROMA(ALIGN(width, 16) / 2);
		cedrus_write(dev, VE_PRIMARY_FB_LINE_STRIDE, reg);

		break;
	case V4L2_PIX_FMT_NV12_32L32:
	default:
		reg = VE_PRIMARY_OUT_FMT_TILED_32_NV12;
		cedrus_write(dev, VE_PRIMARY_OUT_FMT, reg);

		reg = VE_SECONDARY_OUT_FMT_TILED_32_NV12;
		cedrus_write(dev, VE_CHROMA_BUF_LEN, reg);

		break;
	}
}

static irqreturn_t cedrus_irq(int irq, void *data)
{
	struct cedrus_dev *dev = data;
	struct cedrus_ctx *ctx;
	enum vb2_buffer_state state;
	enum cedrus_irq_status status;

	/*
	 * If cancel_delayed_work returns false it means watchdog already
	 * executed and finished the job.
	 */
	if (!cancel_delayed_work(&dev->watchdog_work))
		return IRQ_HANDLED;

	ctx = v4l2_m2m_get_curr_priv(dev->m2m_dev);
	if (!ctx) {
		v4l2_err(&dev->v4l2_dev,
			 "Instance released before the end of transaction\n");
		return IRQ_NONE;
	}

	status = ctx->current_codec->irq_status(ctx);
	if (status == CEDRUS_IRQ_NONE)
		return IRQ_NONE;

	ctx->current_codec->irq_disable(ctx);
	ctx->current_codec->irq_clear(ctx);

	if (status == CEDRUS_IRQ_ERROR)
		state = VB2_BUF_STATE_ERROR;
	else
		state = VB2_BUF_STATE_DONE;

	v4l2_m2m_buf_done_and_job_finish(ctx->dev->m2m_dev, ctx->fh.m2m_ctx,
					 state);

	return IRQ_HANDLED;
}

void cedrus_watchdog(struct work_struct *work)
{
	struct cedrus_dev *dev;
	struct cedrus_ctx *ctx;

	dev = container_of(to_delayed_work(work),
			   struct cedrus_dev, watchdog_work);

	ctx = v4l2_m2m_get_curr_priv(dev->m2m_dev);
	if (!ctx)
		return;

	v4l2_err(&dev->v4l2_dev, "frame processing timed out!\n");
	reset_control_reset(dev->rstc);
	if (dev->quirks & CEDRUS_QUIRK_A733)
		cedrus_a733_vcu_reset(dev);
	v4l2_m2m_buf_done_and_job_finish(ctx->dev->m2m_dev, ctx->fh.m2m_ctx,
					 VB2_BUF_STATE_ERROR);
}

int cedrus_hw_suspend(struct device *device)
{
	struct cedrus_dev *dev = dev_get_drvdata(device);

	clk_disable_unprepare(dev->ram_clk);
	clk_disable_unprepare(dev->mod_clk);
	clk_disable_unprepare(dev->ahb_clk);
	clk_disable_unprepare(dev->mbus_gate_clk);
	clk_disable_unprepare(dev->ahb_gate_clk);

	reset_control_assert(dev->rstc);

	return 0;
}

int cedrus_hw_resume(struct device *device)
{
	struct cedrus_dev *dev = dev_get_drvdata(device);
	int ret;

	if (dev->quirks & CEDRUS_QUIRK_A733)
		cedrus_a733_sram_claim(dev);

	ret = reset_control_reset(dev->rstc);
	if (ret) {
		dev_err(dev->dev, "Failed to apply reset\n");

		return ret;
	}

	/* NULL (no quirk, or not in the node) is a no-op for both gates. */
	ret = clk_prepare_enable(dev->ahb_gate_clk);
	if (ret) {
		dev_err(dev->dev, "Failed to enable AHB master gate\n");

		goto err_rst;
	}

	ret = clk_prepare_enable(dev->mbus_gate_clk);
	if (ret) {
		dev_err(dev->dev, "Failed to enable MBUS master gate\n");

		goto err_ahb_gate_clk;
	}

	ret = clk_prepare_enable(dev->ahb_clk);
	if (ret) {
		dev_err(dev->dev, "Failed to enable AHB clock\n");

		goto err_mbus_gate_clk;
	}

	ret = clk_prepare_enable(dev->mod_clk);
	if (ret) {
		dev_err(dev->dev, "Failed to enable MOD clock\n");

		goto err_ahb_clk;
	}

	ret = clk_prepare_enable(dev->ram_clk);
	if (ret) {
		dev_err(dev->dev, "Failed to enable RAM clock\n");

		goto err_mod_clk;
	}

	if (dev->quirks & CEDRUS_QUIRK_A733) {
		cedrus_a733_vcu_reset(dev);
		cedrus_a733_read_ip_version(dev);
	}

	return 0;

err_mod_clk:
	clk_disable_unprepare(dev->mod_clk);
err_ahb_clk:
	clk_disable_unprepare(dev->ahb_clk);
err_mbus_gate_clk:
	clk_disable_unprepare(dev->mbus_gate_clk);
err_ahb_gate_clk:
	clk_disable_unprepare(dev->ahb_gate_clk);
err_rst:
	reset_control_assert(dev->rstc);

	return ret;
}

int cedrus_hw_probe(struct cedrus_dev *dev)
{
	const struct cedrus_variant *variant;
	int irq_dec;
	int ret;

	variant = of_device_get_match_data(dev->dev);
	if (!variant)
		return -EINVAL;

	dev->capabilities = variant->capabilities;
	dev->quirks = variant->quirks;

	irq_dec = platform_get_irq(dev->pdev, 0);
	if (irq_dec <= 0)
		return irq_dec;
	ret = devm_request_irq(dev->dev, irq_dec, cedrus_irq,
			       0, dev_name(dev->dev), dev);
	if (ret) {
		dev_err(dev->dev, "Failed to request IRQ\n");

		return ret;
	}

	ret = of_reserved_mem_device_init(dev->dev);
	if (ret && ret != -ENODEV) {
		dev_err(dev->dev, "Failed to reserve memory\n");

		return ret;
	}

	if (dev->quirks & CEDRUS_QUIRK_A733) {
		struct resource *res;

		/*
		 * The decoder takes 32-bit bus addresses and there is no
		 * IOMMU driver: keep every buffer below 4 GiB.
		 */
		ret = dma_set_mask_and_coherent(dev->dev, DMA_BIT_MASK(32));
		if (ret) {
			dev_err(dev->dev, "Failed to set 32-bit DMA mask\n");

			goto err_mem;
		}

		/*
		 * System control is not requested exclusively: it is shared
		 * SoC state that a system-control driver may own later. The
		 * vendor driver also carries on without it.
		 */
		res = platform_get_resource(dev->pdev, IORESOURCE_MEM, 1);
		if (res)
			dev->syscfg = devm_ioremap(dev->dev, res->start,
						   resource_size(res));
		if (!dev->syscfg)
			dev_warn(dev->dev,
				 "No system control registers, SRAM not claimed\n");

		dev->ahb_gate_clk = devm_clk_get_optional(dev->dev, "ahb-gate");
		if (IS_ERR(dev->ahb_gate_clk)) {
			dev_err(dev->dev, "Failed to get AHB master gate\n");

			ret = PTR_ERR(dev->ahb_gate_clk);
			goto err_mem;
		}

		dev->mbus_gate_clk = devm_clk_get_optional(dev->dev,
							   "mbus-gate");
		if (IS_ERR(dev->mbus_gate_clk)) {
			dev_err(dev->dev, "Failed to get MBUS master gate\n");

			ret = PTR_ERR(dev->mbus_gate_clk);
			goto err_mem;
		}
	}

	dev->ahb_clk = devm_clk_get(dev->dev, "ahb");
	if (IS_ERR(dev->ahb_clk)) {
		dev_err(dev->dev, "Failed to get AHB clock\n");

		ret = PTR_ERR(dev->ahb_clk);
		goto err_mem;
	}

	dev->mod_clk = devm_clk_get(dev->dev, "mod");
	if (IS_ERR(dev->mod_clk)) {
		dev_err(dev->dev, "Failed to get MOD clock\n");

		ret = PTR_ERR(dev->mod_clk);
		goto err_mem;
	}

	dev->ram_clk = devm_clk_get(dev->dev, "ram");
	if (IS_ERR(dev->ram_clk)) {
		dev_err(dev->dev, "Failed to get RAM clock\n");

		ret = PTR_ERR(dev->ram_clk);
		goto err_mem;
	}

	dev->rstc = devm_reset_control_get(dev->dev, NULL);
	if (IS_ERR(dev->rstc)) {
		dev_err(dev->dev, "Failed to get reset control\n");

		ret = PTR_ERR(dev->rstc);
		goto err_mem;
	}

	dev->base = devm_platform_ioremap_resource(dev->pdev, 0);
	if (IS_ERR(dev->base)) {
		dev_err(dev->dev, "Failed to map registers\n");

		ret = PTR_ERR(dev->base);
		goto err_mem;
	}

	ret = clk_set_rate(dev->mod_clk, variant->mod_rate);
	if (ret) {
		dev_err(dev->dev, "Failed to set clock rate\n");

		goto err_mem;
	}

	pm_runtime_enable(dev->dev);
	if (!pm_runtime_enabled(dev->dev)) {
		ret = cedrus_hw_resume(dev->dev);
		if (ret)
			goto err_pm;
	}

	return 0;

err_pm:
	pm_runtime_disable(dev->dev);
err_mem:
	of_reserved_mem_device_release(dev->dev);

	return ret;
}

void cedrus_hw_remove(struct cedrus_dev *dev)
{
	pm_runtime_disable(dev->dev);
	if (!pm_runtime_status_suspended(dev->dev))
		cedrus_hw_suspend(dev->dev);

	of_reserved_mem_device_release(dev->dev);
}
