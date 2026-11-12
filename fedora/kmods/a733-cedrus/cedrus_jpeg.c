// SPDX-License-Identifier: GPL-2.0
/*
 * a733-cedrus: JPEG decoding with the MPEG engine, on a video node of its own
 *
 * The register programming follows "[PATCH 2/4] media: cedrus: Add JPEG
 * decoder", Copyright (C) 2022 Emmanuel Gil Peyrot <linkmauve@linkmauve.fr>,
 * Message-ID 20240731164422.206503-3-linkmauve@linkmauve.fr, which is not in
 * Linux 7.3.3, cross-checked against the reverse-engineered jpeg-test of
 * https://github.com/jemk/cedrus and against static inspection of the
 * vendor MJPEG library for the A733's IC generation. Where those differ the
 * vendor value is used; REGISTERS.md in fedora/kmods/a733-cedrus-jpeg lists
 * the evidence for every write. The video node around it is new.
 *
 * Nothing in this file has run on hardware.
 */

#include <linux/pm_runtime.h>
#include <linux/sizes.h>
#include <linux/slab.h>

#include <media/v4l2-device.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-jpeg.h>
#include <media/v4l2-mem2mem.h>
#include <media/videobuf2-dma-contig.h>

#include "cedrus.h"
#include "cedrus_hw.h"
#include "cedrus_jpeg_regs.h"

#define CEDRUS_JPEG_NAME		CEDRUS_NAME "-jpeg"

#define CEDRUS_JPEG_MIN_SIZE		16U
/* The limit of the patch this follows; larger pictures were never tried. */
#define CEDRUS_JPEG_MAX_SIZE		2048U
#define CEDRUS_JPEG_DEFAULT_WIDTH	640U
#define CEDRUS_JPEG_DEFAULT_HEIGHT	480U

#define CEDRUS_JPEG_MIN_SIZEIMAGE	SZ_64K
#define CEDRUS_JPEG_MAX_SIZEIMAGE	SZ_16M

/* Hardware */

static enum cedrus_irq_status cedrus_jpeg_irq_status(struct cedrus_ctx *ctx)
{
	struct cedrus_dev *dev = ctx->dev;
	u32 reg;

	reg = cedrus_read(dev, VE_DEC_MPEG_STATUS);
	reg &= VE_DEC_MPEG_STATUS_JPEG_CHECK_MASK;

	if (!reg)
		return CEDRUS_IRQ_NONE;

	if (reg & VE_DEC_MPEG_STATUS_CHECK_ERROR)
		return CEDRUS_IRQ_ERROR;

	/* Bit 3 alone is not understood; do not report it as a picture. */
	if (!(reg & VE_DEC_MPEG_STATUS_SUCCESS)) {
		dev_warn_ratelimited(dev->dev,
				     "JPEG interrupt with status %#x\n", reg);
		return CEDRUS_IRQ_ERROR;
	}

	return CEDRUS_IRQ_OK;
}

static void cedrus_jpeg_irq_clear(struct cedrus_ctx *ctx)
{
	struct cedrus_dev *dev = ctx->dev;

	cedrus_write(dev, VE_DEC_MPEG_STATUS,
		     VE_DEC_MPEG_STATUS_JPEG_CHECK_MASK);
}

static void cedrus_jpeg_irq_disable(struct cedrus_ctx *ctx)
{
	struct cedrus_dev *dev = ctx->dev;
	u32 reg = cedrus_read(dev, VE_DEC_MPEG_CTRL);

	reg &= ~VE_DEC_MPEG_CTRL_JPEG_IRQ_MASK;

	cedrus_write(dev, VE_DEC_MPEG_CTRL, reg);
}

/*
 * Put one Huffman table, given as in a DHT segment (sixteen code counts,
 * then the symbols), into slot @slot of the SRAM image. For the four
 * tables of ITU-T T.81 Annex K the result equals, word for word, the
 * default image the vendor library loads when a stream has no DHT.
 */
static int cedrus_jpeg_fill_huffman_table(u16 *image, unsigned int slot,
					  const u8 *table, size_t length)
{
	u16 *header = image + VE_DEC_MPEG_JPEG_HT_HEADER(slot);
	u16 *symbols = image + VE_DEC_MPEG_JPEG_HT_SYMBOLS(slot);
	unsigned int count = 0;
	unsigned int code = 0;
	u8 first[16];
	int i;

	if (!table || length < 16)
		return -EINVAL;

	for (i = 0; i < 16; i++) {
		first[i] = count;
		header[i] = code;
		count += table[i];
		code = (code + table[i]) << 1;
	}

	if (count > 256 || count > length - 16)
		return -EINVAL;

	for (i = 15; i >= 0 && !table[i]; i--)
		header[i] = VE_DEC_MPEG_JPEG_HT_UNUSED;

	for (i = 0; i < 8; i++)
		header[16 + i] = first[2 * i] | (first[2 * i + 1] << 8);

	table += 16;
	for (i = 0; i < count; i++)
		symbols[i / 2] |= table[i] << (8 * (i % 2));

	return 0;
}

static int cedrus_jpeg_write_huffman_tables(struct cedrus_ctx *ctx,
					    struct v4l2_jpeg_header *hdr)
{
	static const struct v4l2_jpeg_reference reference[4] = {
		{ (u8 *)v4l2_jpeg_ref_table_luma_dc_ht,
		  V4L2_JPEG_REF_HT_DC_LEN },
		{ (u8 *)v4l2_jpeg_ref_table_luma_ac_ht,
		  V4L2_JPEG_REF_HT_AC_LEN },
		{ (u8 *)v4l2_jpeg_ref_table_chroma_dc_ht,
		  V4L2_JPEG_REF_HT_DC_LEN },
		{ (u8 *)v4l2_jpeg_ref_table_chroma_ac_ht,
		  V4L2_JPEG_REF_HT_AC_LEN },
	};
	struct cedrus_dev *dev = ctx->dev;
	u16 *image = ctx->codec.jpeg.huffman_image;
	unsigned int i;
	int ret;

	memset(image, 0, VE_DEC_MPEG_JPEG_HT_WORDS * sizeof(*image));

	for (i = 0; i < 4; i++) {
		const struct v4l2_jpeg_scan_component_spec *comp;
		const struct v4l2_jpeg_reference *table;
		unsigned int selector;

		if (hdr->num_dht) {
			/* Slots 0 and 1: first component; 2 and 3: second. */
			comp = &hdr->scan->component[i / 2];
			if (i % 2)
				selector = comp->ac_entropy_coding_table_selector;
			else
				selector = comp->dc_entropy_coding_table_selector;
			if (selector > 1)
				return -EINVAL;

			/* The helper stores DC0, DC1, AC0, AC1. */
			table = &hdr->huffman_tables[2 * (i % 2) + selector];
		} else {
			/* No DHT segment, as in most MJPEG streams. */
			table = &reference[i];
		}

		ret = cedrus_jpeg_fill_huffman_table(image, i, table->start,
						     table->length);
		if (ret)
			return ret;
	}

	cedrus_write(dev, VE_DEC_MPEG_SRAM_RW_OFFSET, 0);

	for (i = 0; i < VE_DEC_MPEG_JPEG_HT_WORDS; i += 2)
		cedrus_write(dev, VE_DEC_MPEG_SRAM_RW_DATA,
			     image[i] | ((u32)image[i + 1] << 16));

	return 0;
}

static int
cedrus_jpeg_write_quantisation_table(struct cedrus_dev *dev, u32 flags,
				     const struct v4l2_jpeg_reference *table)
{
	const u8 *matrix = table->start;
	unsigned int i;
	u32 reg;

	/* 8-bit precision only, so 64 one-byte entries in zigzag order. */
	if (!matrix || table->length != V4L2_JPEG_PIXELS_IN_BLOCK)
		return -EINVAL;

	for (i = 0; i < V4L2_JPEG_PIXELS_IN_BLOCK; i++) {
		reg = VE_DEC_MPEG_IQMINPUT_WEIGHT(i, matrix[i]);
		reg |= flags;

		cedrus_write(dev, VE_DEC_MPEG_IQMINPUT, reg);
	}

	return 0;
}

/*
 * Everything this function turns down is something the sources do not
 * settle for the A733; see REGISTERS.md. It fails the decode instead of
 * programming a guess.
 */
static int cedrus_jpeg_check_header(struct cedrus_ctx *ctx,
				    const struct v4l2_jpeg_header *hdr,
				    u32 *subsampling)
{
	const struct v4l2_jpeg_frame_component_spec *comp = hdr->frame.component;
	const struct v4l2_jpeg_scan_component_spec *scan = hdr->scan->component;
	struct cedrus_dev *dev = ctx->dev;
	unsigned int i;
	u32 index;

	if (hdr->frame.width != ctx->src_fmt.width ||
	    hdr->frame.height != ctx->src_fmt.height) {
		v4l2_err(&dev->v4l2_dev,
			 "JPEG is %ux%u, the format was set to %ux%u\n",
			 hdr->frame.width, hdr->frame.height,
			 ctx->src_fmt.width, ctx->src_fmt.height);
		return -EINVAL;
	}

	if (hdr->frame.precision != 8) {
		v4l2_err(&dev->v4l2_dev, "unsupported JPEG precision %u\n",
			 hdr->frame.precision);
		return -EOPNOTSUPP;
	}

	/*
	 * Greyscale: the vendor library sets VE_DEC_MPEG_JPEG_RES_INT_GREY
	 * and format code 5, but what the hardware writes to the chroma
	 * plane of an NV12 buffer is not known.
	 */
	if (hdr->frame.num_components != 3 || hdr->scan->num_components != 3) {
		v4l2_err(&dev->v4l2_dev,
			 "unsupported JPEG with %u components, %u in the scan\n",
			 hdr->frame.num_components, hdr->scan->num_components);
		return -EOPNOTSUPP;
	}

	/* Adobe RGB: the hardware would treat it as YCbCr. */
	if (hdr->app14_tf == V4L2_JPEG_APP14_TF_CMYK_RGB) {
		v4l2_err(&dev->v4l2_dev, "unsupported RGB JPEG\n");
		return -EOPNOTSUPP;
	}

	for (i = 0; i < 3; i++) {
		if (scan[i].component_selector != comp[i].component_identifier)
			return -EOPNOTSUPP;
	}

	/* One table set for luma and one for both chroma components. */
	if (comp[2].quantization_table_selector !=
	    comp[1].quantization_table_selector ||
	    scan[2].dc_entropy_coding_table_selector !=
	    scan[1].dc_entropy_coding_table_selector ||
	    scan[2].ac_entropy_coding_table_selector !=
	    scan[1].ac_entropy_coding_table_selector) {
		v4l2_err(&dev->v4l2_dev,
			 "unsupported JPEG with separate Cb and Cr tables\n");
		return -EOPNOTSUPP;
	}

	index = comp[0].horizontal_sampling_factor << 20 |
		comp[0].vertical_sampling_factor << 16 |
		comp[1].horizontal_sampling_factor << 12 |
		comp[1].vertical_sampling_factor << 8 |
		comp[2].horizontal_sampling_factor << 4 |
		comp[2].vertical_sampling_factor;

	switch (index) {
	case 0x221111:
		*subsampling = VE_DEC_MPEG_TRIGGER_CHROMA_FMT_420;
		break;
	case 0x211111:
		*subsampling = VE_DEC_MPEG_TRIGGER_CHROMA_FMT_422;
		break;
	case 0x111111:
		*subsampling = VE_DEC_MPEG_TRIGGER_CHROMA_FMT_444;
		break;
	default:
		/*
		 * 4:2:2 with vertical subsampling (0x121111) and 4:1:1
		 * (0x411111) have format codes, but the vendor library does
		 * not set the 4:2:0 output bit for them and how it reaches
		 * NV12 for them is not known.
		 */
		v4l2_err(&dev->v4l2_dev, "unsupported JPEG sampling %06x\n",
			 index);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int cedrus_jpeg_setup(struct cedrus_ctx *ctx, struct cedrus_run *run)
{
	struct v4l2_jpeg_reference qtables[V4L2_JPEG_MAX_TABLES] = { };
	struct v4l2_jpeg_reference htables[V4L2_JPEG_MAX_TABLES] = { };
	struct v4l2_jpeg_scan_header scan = { };
	struct v4l2_jpeg_header hdr = {
		.scan = &scan,
		.quantization_tables = qtables,
		.huffman_tables = htables,
	};
	const struct v4l2_jpeg_frame_component_spec *comp = hdr.frame.component;
	struct vb2_buffer *src_buf = &run->src->vb2_buf;
	dma_addr_t src_buf_addr, dst_luma_addr, dst_chroma_addr;
	unsigned int stride = ALIGN(ctx->dst_fmt.width, 16);
	unsigned int lines = ALIGN(ctx->dst_fmt.height, 16);
	unsigned int mcu_width, mcu_height;
	struct cedrus_dev *dev = ctx->dev;
	unsigned long size;
	u32 reg, subsampling;
	void *vaddr;
	int ret;

	size = vb2_get_plane_payload(src_buf, 0);
	vaddr = vb2_plane_vaddr(src_buf, 0);
	if (!vaddr)
		return -ENOMEM;

	ret = v4l2_jpeg_parse_header(vaddr, size, &hdr);
	if (ret < 0) {
		v4l2_err(&dev->v4l2_dev, "failed to parse JPEG header: %d\n",
			 ret);
		return ret;
	}

	if (hdr.ecs_offset >= size)
		return -EINVAL;

	ret = cedrus_jpeg_check_header(ctx, &hdr, &subsampling);
	if (ret)
		return ret;

	ctx->codec.jpeg.subsampling = subsampling;

	/* Select the MPEG engine (mode 0) and JPEG within it. */
	cedrus_engine_enable(ctx);

	reg = VE_DEC_MPEG_TRIGGER_JPEG | subsampling;
	cedrus_write(dev, VE_DEC_MPEG_TRIGGER, reg);

	cedrus_write(dev, VE_DEC_MPEG_JPEG_RES_INT, hdr.restart_interval);

	/*
	 * Picture size in MCUs. check_header() admits only pictures whose
	 * first component has the largest sampling factors.
	 */
	mcu_width = DIV_ROUND_UP(hdr.frame.width,
				 8 * comp[0].horizontal_sampling_factor);
	mcu_height = DIV_ROUND_UP(hdr.frame.height,
				  8 * comp[0].vertical_sampling_factor);
	reg = VE_DEC_MPEG_JPEG_SIZE_WIDTH(mcu_width) |
	      VE_DEC_MPEG_JPEG_SIZE_HEIGHT(mcu_height);
	cedrus_write(dev, VE_DEC_MPEG_JPEG_SIZE, reg);

	/* Luma table in the intra slot, chroma table in the non-intra slot. */
	ret = cedrus_jpeg_write_quantisation_table(dev,
						   VE_DEC_MPEG_IQMINPUT_FLAG_INTRA,
						   &qtables[comp[0].quantization_table_selector]);
	if (ret)
		return ret;

	ret = cedrus_jpeg_write_quantisation_table(dev,
						   VE_DEC_MPEG_IQMINPUT_FLAG_NON_INTRA,
						   &qtables[comp[1].quantization_table_selector]);
	if (ret)
		return ret;

	ret = cedrus_jpeg_write_huffman_tables(ctx, &hdr);
	if (ret)
		return ret;

	/*
	 * JPEG decodes into the second (rotate and scale) output, set up as
	 * NV12 with the first output's format, as the vendor library does
	 * for NV12 output on this IC generation.
	 */
	reg = VE_PRIMARY_OUT_FMT_NV12 | VE_SECONDARY_OUT_FMT_EXT_NV12;
	cedrus_write(dev, VE_PRIMARY_OUT_FMT, reg);

	reg = VE_CHROMA_BUF_LEN_SDRT(stride * lines / 4) |
	      VE_CHROMA_WIDTH_ALIGN_8 | VE_SECONDARY_OUT_FMT_EXT;
	cedrus_write(dev, VE_CHROMA_BUF_LEN, reg);

	reg = VE_SECONDARY_FB_LINE_STRIDE_LUMA(stride) |
	      VE_SECONDARY_FB_LINE_STRIDE_CHROMA(stride / 2);
	cedrus_write(dev, VE_SECONDARY_FB_LINE_STRIDE, reg);

	dst_luma_addr = cedrus_dst_buf_addr(ctx, &run->dst->vb2_buf, 0);
	dst_chroma_addr = cedrus_dst_buf_addr(ctx, &run->dst->vb2_buf, 1);

	cedrus_write(dev, VE_DEC_MPEG_ROT_LUMA, dst_luma_addr);
	cedrus_write(dev, VE_DEC_MPEG_ROT_CHROMA, dst_chroma_addr);

	/* No rotation, no scaling. */
	cedrus_write(dev, VE_DEC_MPEG_SD_ROT_DBLK_CTL, 0);

	/* Entropy-coded data: offset and length in bits. */
	cedrus_write(dev, VE_DEC_MPEG_VLD_OFFSET, 8 * hdr.ecs_offset);
	cedrus_write(dev, VE_DEC_MPEG_VLD_LEN, 8 * (size - hdr.ecs_offset));

	src_buf_addr = vb2_dma_contig_plane_dma_addr(src_buf, 0);

	reg = VE_DEC_MPEG_VLD_ADDR_BASE(src_buf_addr);
	reg |= VE_DEC_MPEG_VLD_ADDR_VALID_PIC_DATA;
	reg |= VE_DEC_MPEG_VLD_ADDR_LAST_PIC_DATA;
	reg |= VE_DEC_MPEG_VLD_ADDR_FIRST_PIC_DATA;

	cedrus_write(dev, VE_DEC_MPEG_VLD_ADDR, reg);

	/* Last byte of the buffer, as the vendor library and jpeg-test do. */
	reg = src_buf_addr + vb2_plane_size(src_buf, 0) - 1;
	cedrus_write(dev, VE_DEC_MPEG_VLD_END_ADDR, reg);

	/*
	 * Interrupts, output through the second output only, and chroma
	 * reduced to 4:2:0 for the NV12 buffer where the picture has more.
	 */
	reg = VE_DEC_MPEG_CTRL_JPEG_IRQ_MASK |
	      VE_DEC_MPEG_CTRL_MC_NO_WRITEBACK |
	      VE_DEC_MPEG_CTRL_ROTATE_SCALE_OUT_EN;
	if (subsampling != VE_DEC_MPEG_TRIGGER_CHROMA_FMT_420)
		reg |= VE_DEC_MPEG_CTRL_JPEG_FORCE_420;

	cedrus_write(dev, VE_DEC_MPEG_CTRL, reg);

	return 0;
}

static void cedrus_jpeg_trigger(struct cedrus_ctx *ctx)
{
	struct cedrus_dev *dev = ctx->dev;
	u32 reg;

	reg = VE_DEC_MPEG_TRIGGER_HW_JPEG_VLD | VE_DEC_MPEG_TRIGGER_JPEG;
	reg |= ctx->codec.jpeg.subsampling;

	cedrus_write(dev, VE_DEC_MPEG_TRIGGER, reg);
}

struct cedrus_dec_ops cedrus_dec_ops_jpeg = {
	.irq_clear	= cedrus_jpeg_irq_clear,
	.irq_disable	= cedrus_jpeg_irq_disable,
	.irq_status	= cedrus_jpeg_irq_status,
	.setup		= cedrus_jpeg_setup,
	.trigger	= cedrus_jpeg_trigger,
};

/* Formats */

static void cedrus_jpeg_prepare_out_format(struct v4l2_pix_format *pix)
{
	u32 sizeimage = pix->sizeimage;

	pix->pixelformat = V4L2_PIX_FMT_JPEG;
	pix->width = clamp(pix->width, CEDRUS_JPEG_MIN_SIZE,
			   CEDRUS_JPEG_MAX_SIZE);
	pix->height = clamp(pix->height, CEDRUS_JPEG_MIN_SIZE,
			    CEDRUS_JPEG_MAX_SIZE);
	pix->field = V4L2_FIELD_NONE;
	pix->bytesperline = 0;

	if (!sizeimage)
		sizeimage = pix->width * pix->height;
	pix->sizeimage = clamp_t(u32, PAGE_ALIGN(sizeimage),
				 CEDRUS_JPEG_MIN_SIZEIMAGE,
				 CEDRUS_JPEG_MAX_SIZEIMAGE);
}

/* The capture format is the coded size of the output format, in NV12. */
static void cedrus_jpeg_prepare_cap_format(struct cedrus_ctx *ctx,
					   struct v4l2_pix_format *pix)
{
	pix->pixelformat = V4L2_PIX_FMT_NV12;
	pix->width = ctx->src_fmt.width;
	pix->height = ALIGN(ctx->src_fmt.height, 16);
	pix->field = V4L2_FIELD_NONE;
	pix->bytesperline = ALIGN(pix->width, 16);
	pix->sizeimage = pix->bytesperline * pix->height * 3 / 2;
	pix->colorspace = ctx->src_fmt.colorspace;
	pix->xfer_func = ctx->src_fmt.xfer_func;
	pix->ycbcr_enc = ctx->src_fmt.ycbcr_enc;
	pix->quantization = ctx->src_fmt.quantization;
}

static void cedrus_jpeg_reset_formats(struct cedrus_ctx *ctx)
{
	struct v4l2_pix_format *pix = &ctx->src_fmt;

	memset(pix, 0, sizeof(*pix));
	pix->width = CEDRUS_JPEG_DEFAULT_WIDTH;
	pix->height = CEDRUS_JPEG_DEFAULT_HEIGHT;
	pix->colorspace = V4L2_COLORSPACE_JPEG;
	pix->xfer_func = V4L2_XFER_FUNC_DEFAULT;
	pix->ycbcr_enc = V4L2_YCBCR_ENC_DEFAULT;
	pix->quantization = V4L2_QUANTIZATION_DEFAULT;
	cedrus_jpeg_prepare_out_format(pix);

	memset(&ctx->dst_fmt, 0, sizeof(ctx->dst_fmt));
	cedrus_jpeg_prepare_cap_format(ctx, &ctx->dst_fmt);
}

static int cedrus_jpeg_querycap(struct file *file, void *priv,
				struct v4l2_capability *cap)
{
	strscpy(cap->driver, CEDRUS_NAME, sizeof(cap->driver));
	strscpy(cap->card, CEDRUS_JPEG_NAME, sizeof(cap->card));
	snprintf(cap->bus_info, sizeof(cap->bus_info),
		 "platform:%s", CEDRUS_NAME);

	return 0;
}

static int cedrus_jpeg_enum_fmt_vid_out(struct file *file, void *priv,
					struct v4l2_fmtdesc *f)
{
	if (f->index)
		return -EINVAL;

	f->pixelformat = V4L2_PIX_FMT_JPEG;

	return 0;
}

static int cedrus_jpeg_enum_fmt_vid_cap(struct file *file, void *priv,
					struct v4l2_fmtdesc *f)
{
	if (f->index)
		return -EINVAL;

	f->pixelformat = V4L2_PIX_FMT_NV12;

	return 0;
}

static int cedrus_jpeg_enum_framesizes(struct file *file, void *priv,
				       struct v4l2_frmsizeenum *fsize)
{
	if (fsize->index)
		return -EINVAL;

	if (fsize->pixel_format != V4L2_PIX_FMT_JPEG &&
	    fsize->pixel_format != V4L2_PIX_FMT_NV12)
		return -EINVAL;

	fsize->type = V4L2_FRMSIZE_TYPE_STEPWISE;
	fsize->stepwise.min_width = CEDRUS_JPEG_MIN_SIZE;
	fsize->stepwise.max_width = CEDRUS_JPEG_MAX_SIZE;
	fsize->stepwise.step_width = 1;
	fsize->stepwise.min_height = CEDRUS_JPEG_MIN_SIZE;
	fsize->stepwise.max_height = CEDRUS_JPEG_MAX_SIZE;
	fsize->stepwise.step_height = 1;

	return 0;
}

static int cedrus_jpeg_g_fmt_vid_out(struct file *file, void *priv,
				     struct v4l2_format *f)
{
	struct cedrus_ctx *ctx = cedrus_file2ctx(file);

	f->fmt.pix = ctx->src_fmt;

	return 0;
}

static int cedrus_jpeg_g_fmt_vid_cap(struct file *file, void *priv,
				     struct v4l2_format *f)
{
	struct cedrus_ctx *ctx = cedrus_file2ctx(file);

	f->fmt.pix = ctx->dst_fmt;

	return 0;
}

static int cedrus_jpeg_try_fmt_vid_out(struct file *file, void *priv,
				       struct v4l2_format *f)
{
	cedrus_jpeg_prepare_out_format(&f->fmt.pix);

	return 0;
}

static int cedrus_jpeg_try_fmt_vid_cap(struct file *file, void *priv,
				       struct v4l2_format *f)
{
	cedrus_jpeg_prepare_cap_format(cedrus_file2ctx(file), &f->fmt.pix);

	return 0;
}

static int cedrus_jpeg_s_fmt_vid_out(struct file *file, void *priv,
				     struct v4l2_format *f)
{
	struct cedrus_ctx *ctx = cedrus_file2ctx(file);
	struct vb2_queue *vq;

	/* The capture format follows this one, so neither queue may be busy. */
	vq = v4l2_m2m_get_vq(ctx->fh.m2m_ctx, V4L2_BUF_TYPE_VIDEO_OUTPUT);
	if (vb2_is_busy(vq))
		return -EBUSY;

	vq = v4l2_m2m_get_vq(ctx->fh.m2m_ctx, V4L2_BUF_TYPE_VIDEO_CAPTURE);
	if (vb2_is_busy(vq))
		return -EBUSY;

	cedrus_jpeg_prepare_out_format(&f->fmt.pix);
	ctx->src_fmt = f->fmt.pix;
	cedrus_jpeg_prepare_cap_format(ctx, &ctx->dst_fmt);

	return 0;
}

static int cedrus_jpeg_s_fmt_vid_cap(struct file *file, void *priv,
				     struct v4l2_format *f)
{
	struct cedrus_ctx *ctx = cedrus_file2ctx(file);
	struct vb2_queue *vq;

	vq = v4l2_m2m_get_vq(ctx->fh.m2m_ctx, V4L2_BUF_TYPE_VIDEO_CAPTURE);
	if (vb2_is_busy(vq))
		return -EBUSY;

	cedrus_jpeg_prepare_cap_format(ctx, &f->fmt.pix);
	ctx->dst_fmt = f->fmt.pix;

	return 0;
}

static int cedrus_jpeg_g_selection(struct file *file, void *priv,
				   struct v4l2_selection *s)
{
	struct cedrus_ctx *ctx = cedrus_file2ctx(file);

	if (s->type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
		return -EINVAL;

	s->r.left = 0;
	s->r.top = 0;

	switch (s->target) {
	case V4L2_SEL_TGT_COMPOSE:
	case V4L2_SEL_TGT_COMPOSE_DEFAULT:
		s->r.width = ctx->src_fmt.width;
		s->r.height = ctx->src_fmt.height;
		break;
	case V4L2_SEL_TGT_COMPOSE_BOUNDS:
	case V4L2_SEL_TGT_COMPOSE_PADDED:
		s->r.width = ctx->dst_fmt.bytesperline;
		s->r.height = ctx->dst_fmt.height;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static const struct v4l2_ioctl_ops cedrus_jpeg_ioctl_ops = {
	.vidioc_querycap		= cedrus_jpeg_querycap,

	.vidioc_enum_fmt_vid_cap	= cedrus_jpeg_enum_fmt_vid_cap,
	.vidioc_g_fmt_vid_cap		= cedrus_jpeg_g_fmt_vid_cap,
	.vidioc_try_fmt_vid_cap		= cedrus_jpeg_try_fmt_vid_cap,
	.vidioc_s_fmt_vid_cap		= cedrus_jpeg_s_fmt_vid_cap,

	.vidioc_enum_fmt_vid_out	= cedrus_jpeg_enum_fmt_vid_out,
	.vidioc_g_fmt_vid_out		= cedrus_jpeg_g_fmt_vid_out,
	.vidioc_try_fmt_vid_out		= cedrus_jpeg_try_fmt_vid_out,
	.vidioc_s_fmt_vid_out		= cedrus_jpeg_s_fmt_vid_out,

	.vidioc_enum_framesizes		= cedrus_jpeg_enum_framesizes,
	.vidioc_g_selection		= cedrus_jpeg_g_selection,

	.vidioc_reqbufs			= v4l2_m2m_ioctl_reqbufs,
	.vidioc_querybuf		= v4l2_m2m_ioctl_querybuf,
	.vidioc_qbuf			= v4l2_m2m_ioctl_qbuf,
	.vidioc_dqbuf			= v4l2_m2m_ioctl_dqbuf,
	.vidioc_prepare_buf		= v4l2_m2m_ioctl_prepare_buf,
	.vidioc_create_bufs		= v4l2_m2m_ioctl_create_bufs,
	.vidioc_expbuf			= v4l2_m2m_ioctl_expbuf,

	.vidioc_streamon		= v4l2_m2m_ioctl_streamon,
	.vidioc_streamoff		= v4l2_m2m_ioctl_streamoff,
};

/* Queues */

static int cedrus_jpeg_queue_setup(struct vb2_queue *vq, unsigned int *nbufs,
				   unsigned int *nplanes, unsigned int sizes[],
				   struct device *alloc_devs[])
{
	struct cedrus_ctx *ctx = vb2_get_drv_priv(vq);
	struct v4l2_pix_format *pix_fmt;

	if (V4L2_TYPE_IS_OUTPUT(vq->type))
		pix_fmt = &ctx->src_fmt;
	else
		pix_fmt = &ctx->dst_fmt;

	if (*nplanes) {
		if (sizes[0] < pix_fmt->sizeimage)
			return -EINVAL;
	} else {
		sizes[0] = pix_fmt->sizeimage;
		*nplanes = 1;
	}

	return 0;
}

static void cedrus_jpeg_queue_cleanup(struct vb2_queue *vq, u32 state)
{
	struct cedrus_ctx *ctx = vb2_get_drv_priv(vq);
	struct vb2_v4l2_buffer *vbuf;

	for (;;) {
		if (V4L2_TYPE_IS_OUTPUT(vq->type))
			vbuf = v4l2_m2m_src_buf_remove(ctx->fh.m2m_ctx);
		else
			vbuf = v4l2_m2m_dst_buf_remove(ctx->fh.m2m_ctx);

		if (!vbuf)
			return;

		v4l2_m2m_buf_done(vbuf, state);
	}
}

static int cedrus_jpeg_buf_out_validate(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);

	vbuf->field = V4L2_FIELD_NONE;

	return 0;
}

static int cedrus_jpeg_buf_prepare(struct vb2_buffer *vb)
{
	struct vb2_queue *vq = vb->vb2_queue;
	struct cedrus_ctx *ctx = vb2_get_drv_priv(vq);

	if (V4L2_TYPE_IS_OUTPUT(vq->type)) {
		if (vb2_get_plane_payload(vb, 0) > vb2_plane_size(vb, 0))
			return -EINVAL;

		return 0;
	}

	if (vb2_plane_size(vb, 0) < ctx->dst_fmt.sizeimage)
		return -EINVAL;

	vb2_set_plane_payload(vb, 0, ctx->dst_fmt.sizeimage);

	return 0;
}

static void cedrus_jpeg_buf_queue(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	struct cedrus_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);

	v4l2_m2m_buf_queue(ctx->fh.m2m_ctx, vbuf);
}

static int cedrus_jpeg_start_streaming(struct vb2_queue *vq,
				       unsigned int count)
{
	struct cedrus_ctx *ctx = vb2_get_drv_priv(vq);
	int ret;

	if (!V4L2_TYPE_IS_OUTPUT(vq->type))
		return 0;

	ret = pm_runtime_resume_and_get(ctx->dev->dev);
	if (ret < 0)
		cedrus_jpeg_queue_cleanup(vq, VB2_BUF_STATE_QUEUED);

	return ret;
}

static void cedrus_jpeg_stop_streaming(struct vb2_queue *vq)
{
	struct cedrus_ctx *ctx = vb2_get_drv_priv(vq);

	if (V4L2_TYPE_IS_OUTPUT(vq->type))
		pm_runtime_put(ctx->dev->dev);

	cedrus_jpeg_queue_cleanup(vq, VB2_BUF_STATE_ERROR);
}

static const struct vb2_ops cedrus_jpeg_qops = {
	.queue_setup		= cedrus_jpeg_queue_setup,
	.buf_prepare		= cedrus_jpeg_buf_prepare,
	.buf_queue		= cedrus_jpeg_buf_queue,
	.buf_out_validate	= cedrus_jpeg_buf_out_validate,
	.start_streaming	= cedrus_jpeg_start_streaming,
	.stop_streaming		= cedrus_jpeg_stop_streaming,
};

static int cedrus_jpeg_queue_init(void *priv, struct vb2_queue *src_vq,
				  struct vb2_queue *dst_vq)
{
	struct cedrus_ctx *ctx = priv;
	int ret;

	/* The header is parsed in the kernel: keep the kernel mapping. */
	src_vq->type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
	src_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	src_vq->drv_priv = ctx;
	src_vq->buf_struct_size = sizeof(struct cedrus_buffer);
	src_vq->ops = &cedrus_jpeg_qops;
	src_vq->mem_ops = &vb2_dma_contig_memops;
	src_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	src_vq->lock = &ctx->dev->dev_mutex;
	src_vq->dev = ctx->dev->dev;

	ret = vb2_queue_init(src_vq);
	if (ret)
		return ret;

	dst_vq->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	dst_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	dst_vq->drv_priv = ctx;
	dst_vq->buf_struct_size = sizeof(struct cedrus_buffer);
	dst_vq->ops = &cedrus_jpeg_qops;
	dst_vq->mem_ops = &vb2_dma_contig_memops;
	dst_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	dst_vq->lock = &ctx->dev->dev_mutex;
	dst_vq->dev = ctx->dev->dev;

	return vb2_queue_init(dst_vq);
}

/* Video node */

static int cedrus_jpeg_open(struct file *file)
{
	struct cedrus_dev *dev = video_drvdata(file);
	struct cedrus_ctx *ctx;
	int ret;

	if (mutex_lock_interruptible(&dev->dev_mutex))
		return -ERESTARTSYS;

	ctx = kzalloc_obj(*ctx);
	if (!ctx) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	ctx->codec.jpeg.huffman_image = kcalloc(VE_DEC_MPEG_JPEG_HT_WORDS,
						sizeof(u16), GFP_KERNEL);
	if (!ctx->codec.jpeg.huffman_image) {
		ret = -ENOMEM;
		goto err_free;
	}

	v4l2_fh_init(&ctx->fh, video_devdata(file));
	ctx->dev = dev;
	ctx->bit_depth = 8;
	ctx->current_codec = &cedrus_dec_ops_jpeg;

	/*
	 * The stateless decoder's m2m device: its job queue is what keeps
	 * the two video nodes from using the hardware at the same time, and
	 * cedrus_device_run(), the interrupt handler and the watchdog serve
	 * both.
	 */
	ctx->fh.m2m_ctx = v4l2_m2m_ctx_init(dev->m2m_dev, ctx,
					    &cedrus_jpeg_queue_init);
	if (IS_ERR(ctx->fh.m2m_ctx)) {
		ret = PTR_ERR(ctx->fh.m2m_ctx);
		goto err_fh;
	}

	cedrus_jpeg_reset_formats(ctx);

	v4l2_fh_add(&ctx->fh, file);

	mutex_unlock(&dev->dev_mutex);

	return 0;

err_fh:
	v4l2_fh_exit(&ctx->fh);
	kfree(ctx->codec.jpeg.huffman_image);
err_free:
	kfree(ctx);
err_unlock:
	mutex_unlock(&dev->dev_mutex);

	return ret;
}

static int cedrus_jpeg_release(struct file *file)
{
	struct cedrus_dev *dev = video_drvdata(file);
	struct cedrus_ctx *ctx = cedrus_file2ctx(file);

	mutex_lock(&dev->dev_mutex);

	v4l2_fh_del(&ctx->fh, file);
	v4l2_m2m_ctx_release(ctx->fh.m2m_ctx);
	v4l2_fh_exit(&ctx->fh);

	kfree(ctx->codec.jpeg.huffman_image);
	kfree(ctx);

	mutex_unlock(&dev->dev_mutex);

	return 0;
}

static const struct v4l2_file_operations cedrus_jpeg_fops = {
	.owner		= THIS_MODULE,
	.open		= cedrus_jpeg_open,
	.release	= cedrus_jpeg_release,
	.poll		= v4l2_m2m_fop_poll,
	.unlocked_ioctl	= video_ioctl2,
	.mmap		= v4l2_m2m_fop_mmap,
};

static const struct video_device cedrus_jpeg_video_device = {
	.name		= CEDRUS_JPEG_NAME,
	.vfl_dir	= VFL_DIR_M2M,
	.fops		= &cedrus_jpeg_fops,
	.ioctl_ops	= &cedrus_jpeg_ioctl_ops,
	.minor		= -1,
	.release	= video_device_release_empty,
	.device_caps	= V4L2_CAP_VIDEO_M2M | V4L2_CAP_STREAMING,
};

int cedrus_jpeg_register(struct cedrus_dev *dev)
{
	struct video_device *vfd = &dev->vfd_jpeg;
	int ret;

	/* Only the untiled NV12 output path is written. */
	if (!(dev->capabilities & CEDRUS_CAPABILITY_JPEG_DEC) ||
	    !(dev->capabilities & CEDRUS_CAPABILITY_UNTILED))
		return 0;

	*vfd = cedrus_jpeg_video_device;
	vfd->lock = &dev->dev_mutex;
	vfd->v4l2_dev = &dev->v4l2_dev;
	video_set_drvdata(vfd, dev);

	ret = video_register_device(vfd, VFL_TYPE_VIDEO, -1);
	if (ret) {
		v4l2_err(&dev->v4l2_dev,
			 "Failed to register JPEG video device\n");
		return ret;
	}

	v4l2_info(&dev->v4l2_dev,
		  "JPEG decoder registered as /dev/video%d\n", vfd->num);

	return 0;
}

void cedrus_jpeg_unregister(struct cedrus_dev *dev)
{
	if (video_is_registered(&dev->vfd_jpeg))
		video_unregister_device(&dev->vfd_jpeg);
}
