// SPDX-License-Identifier: GPL-2.0
/*
 * Cedrus VPU driver
 *
 * Copyright (c) 2026 Jernej Skrabec <jernej.skrabec@gmail.com>
 *
 * VP9 decoder for the Allwinner Cedrus VE engine.
 *
 * This is the cedrus VP9 decoder Jernej Skrabec wrote for the H616
 * (https://github.com/jernejsk/linux-1, branch cedrus-vp9-v1, commit
 * 2388c4ec53cd "staging: media: cedrus: add VP9 decoding support"), ported
 * to this tree for the A733, which has the same decoder: VP9 is a mode of
 * the H.265 engine, with its registers in the window of that engine.
 *
 * Every register write was compared with what the A733 vendor decoder
 * programs. Where the two agree nothing is said. A write which the A733
 * vendor decoder does not make, or makes differently, has a comment.
 * cedrus_vp9_regs.h has the evidence for each register.
 *
 * Changes from the H616 decoder:
 *  - Only 8-bit frames (profile 0). The two sources disagree on the location
 *    of the plane of the two low bits of 10-bit frames.
 *  - Only the NV12 and NV21 capture formats.
 *  - The output format registers are written here, as the common code
 *    doesn't program the line stride of the capture format.
 *  - A reference whose line stride the hardware would not derive correctly
 *    fails the frame.
 *  - The mode register bits and the decode counter the H616 needs are only
 *    written when asked with the vp9_h616_sequence module parameter; the
 *    A733 vendor decoder writes neither.
 *
 * Nothing of this has run on an A733.
 */

#include <linux/dma-mapping.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <media/v4l2-vp9.h>
#include <media/videobuf2-dma-contig.h>

#include "cedrus.h"
#include "cedrus_hw.h"
#include "cedrus_regs.h"
#include "cedrus_video.h"
#include "cedrus_vp9_regs.h"

/*
 * VP9 is off unless asked for: the decoder is unproven on the A733. The
 * variant also has to have CEDRUS_CAPABILITY_VP9_DEC. a733-cedrus applies
 * it with the other codec parameters in cedrus_select_codecs().
 */
bool cedrus_vp9_enabled;
module_param_named(vp9, cedrus_vp9_enabled, bool, 0444);
MODULE_PARM_DESC(vp9, "Enable the VP9 decoder on variants that have it (unproven)");

/*
 * The H616 needs bits 31 and 30 of the mode register and the decode counter
 * of the top block for VP9. The A733 vendor decoder writes neither. For
 * comparing the two on the hardware.
 */
bool cedrus_vp9_h616_sequence;
module_param_named(vp9_h616_sequence, cedrus_vp9_h616_sequence, bool, 0444);
MODULE_PARM_DESC(vp9_h616_sequence,
		 "Program the mode register and decode counter as the H616 VP9 decoder does");

/*
 * Sizes are taken from the vendor library:
 *   prob_tbl     - probability table (input to HW) plus the entropy count
 *                  region the HW writes back at offset CEDRUS_VP9_CTX_OFFSET.
 *   neighbor_buf - per-MI neighbour state used by the HW pipeline.
 *   col_mv_buf   - collocated motion vectors written and read across frames.
 */
#define CEDRUS_VP9_PROB_TBL_SIZE	0x88000
#define CEDRUS_VP9_PROBS_OFFSET		0x4000
#define CEDRUS_VP9_PROBS_SIZE		0xafc
#define CEDRUS_VP9_CTX_OFFSET		0x4b00
#define CEDRUS_VP9_SEGMAP_OFFSET	0x8000
#define CEDRUS_VP9_NEIGHBOR_BUF_SIZE	0x1f4000

/*
 * The hardware derives the line stride of the references from their width,
 * aligned to the stride alignment of the capture format. A 64 byte alignment
 * also keeps the chroma plane, at bytesperline * height with a height
 * aligned to 16 lines, on the 1 KiB boundary the address registers need.
 */
#define CEDRUS_VP9_STRIDE_ALIGN		64

static bool cedrus_vp9_cap_format_supported(u32 pixelformat)
{
	return pixelformat == V4L2_PIX_FMT_NV12 ||
	       pixelformat == V4L2_PIX_FMT_NV21;
}

/* VP9 dequantisation tables for 8-bit frames, from the spec / libvpx. */
static const u16 vp9_dc_qlookup[256] = {
	4,    8,    8,    9,    10,   11,   12,   12,
	13,   14,   15,   16,   17,   18,   19,   19,
	20,   21,   22,   23,   24,   25,   26,   26,
	27,   28,   29,   30,   31,   32,   32,   33,
	34,   35,   36,   37,   38,   38,   39,   40,
	41,   42,   43,   43,   44,   45,   46,   47,
	48,   48,   49,   50,   51,   52,   53,   53,
	54,   55,   56,   57,   57,   58,   59,   60,
	61,   62,   62,   63,   64,   65,   66,   66,
	67,   68,   69,   70,   70,   71,   72,   73,
	74,   74,   75,   76,   77,   78,   78,   79,
	80,   81,   81,   82,   83,   84,   85,   85,
	87,   88,   90,   92,   93,   95,   96,   98,
	99,   101,  102,  104,  105,  107,  108,  110,
	111,  113,  114,  116,  117,  118,  120,  121,
	123,  125,  127,  129,  131,  134,  136,  138,
	140,  142,  144,  146,  148,  150,  152,  154,
	156,  158,  161,  164,  166,  169,  172,  174,
	177,  180,  182,  185,  187,  190,  192,  195,
	199,  202,  205,  208,  211,  214,  217,  220,
	223,  226,  230,  233,  237,  240,  243,  247,
	250,  253,  257,  261,  265,  269,  272,  276,
	280,  284,  288,  292,  296,  300,  304,  309,
	313,  317,  322,  326,  330,  335,  340,  344,
	349,  354,  359,  364,  369,  374,  379,  384,
	389,  395,  400,  406,  411,  417,  423,  429,
	435,  441,  447,  454,  461,  467,  475,  482,
	489,  497,  505,  513,  522,  530,  539,  549,
	559,  569,  579,  590,  602,  614,  626,  640,
	654,  668,  684,  700,  717,  736,  755,  775,
	796,  819,  843,  869,  896,  925,  955,  988,
	1022, 1058, 1098, 1139, 1184, 1232, 1282, 1336,
};

static const u16 vp9_ac_qlookup[256] = {
	4,    8,    9,    10,   11,   12,   13,   14,
	15,   16,   17,   18,   19,   20,   21,   22,
	23,   24,   25,   26,   27,   28,   29,   30,
	31,   32,   33,   34,   35,   36,   37,   38,
	39,   40,   41,   42,   43,   44,   45,   46,
	47,   48,   49,   50,   51,   52,   53,   54,
	55,   56,   57,   58,   59,   60,   61,   62,
	63,   64,   65,   66,   67,   68,   69,   70,
	71,   72,   73,   74,   75,   76,   77,   78,
	79,   80,   81,   82,   83,   84,   85,   86,
	87,   88,   89,   90,   91,   92,   93,   94,
	95,   96,   97,   98,   99,   100,  101,  102,
	104,  106,  108,  110,  112,  114,  116,  118,
	120,  122,  124,  126,  128,  130,  132,  134,
	136,  138,  140,  142,  144,  146,  148,  150,
	152,  155,  158,  161,  164,  167,  170,  173,
	176,  179,  182,  185,  188,  191,  194,  197,
	200,  203,  207,  211,  215,  219,  223,  227,
	231,  235,  239,  243,  247,  251,  255,  260,
	265,  270,  275,  280,  285,  290,  295,  300,
	305,  311,  317,  323,  329,  335,  341,  347,
	353,  359,  366,  373,  380,  387,  394,  401,
	408,  416,  424,  432,  440,  448,  456,  465,
	474,  483,  492,  501,  510,  520,  530,  540,
	550,  560,  571,  582,  593,  604,  615,  627,
	639,  651,  663,  676,  689,  702,  715,  729,
	743,  757,  771,  786,  801,  816,  832,  848,
	864,  881,  898,  915,  933,  951,  969,  988,
	1007, 1026, 1046, 1066, 1087, 1108, 1129, 1151,
	1173, 1196, 1219, 1243, 1267, 1292, 1317, 1343,
	1369, 1396, 1423, 1451, 1479, 1508, 1537, 1567,
	1597, 1628, 1660, 1692, 1725, 1759, 1793, 1828,
};

/*
 * Layout of the entropy count region the hardware writes into the
 * probability table at CEDRUS_VP9_CTX_OFFSET.  Field order and offsets
 * follow the vendor decoder, which reads the counts from there:
 *
 *   +0x0000 tx counts        +0x0048 eobs         +0x0948 coeffs
 *   +0x2d48 mbskip           +0x2d60 inter_mode   +0x2dd0 interp filter
 *   +0x2e00 intra_inter      +0x2e20 comp/single ref
 *   +0x2ec0 y modes          +0x2f60 uv modes     +0x30f0 partition
 *   +0x31f0 mv joints        +0x3200 mv per-component blocks
 *
 * Motion-vector counts are stored as one block per component, column
 * component first, unlike the interleaved v4l2 count arrays.
 */
struct cedrus_vp9_hw_nmv_comp {
	u32 sign[2];
	u32 class0[2];
	u32 class0_hp[2];
	u32 hp[2];
	u32 classes[11];
	u32 bits[10][2];
	u32 class0_fp[2][4];
	u32 fp[4];
};

struct cedrus_vp9_entropy_counts {
	u32 tx8x8[2][2];
	u32 tx16x16[2][3];
	u32 tx32x32[2][4];
	u32 eobs[4][2][2][6][6];
	u32 coeffs[4][2][2][6][6][4];
	u32 mbskip[3][2];
	/* One count per inter mode, NEARESTMV, NEARMV, ZEROMV and NEWMV. */
	u32 inter_mode[7][4];
	u32 switchable_interp[4][3];
	u32 intra_inter[4][2];
	u32 comp_inter[5][2];
	u32 comp_ref[5][2];
	u32 single_ref[5][2][2];
	u32 sb_ymode[4][10];
	u32 uv_mode[10][10];
	u32 partition[16][4];
	u32 joints[4];
	/* [0] = column (v4l2 component 1), [1] = row (component 0). */
	struct cedrus_vp9_hw_nmv_comp comp[2];
};

static_assert(sizeof(struct cedrus_vp9_entropy_counts) == 0x3398,
	      "cedrus_vp9_entropy_counts size mismatch");
static_assert(offsetof(struct cedrus_vp9_entropy_counts, coeffs) == 0x948,
	      "cedrus_vp9_entropy_counts coeffs offset mismatch");
static_assert(offsetof(struct cedrus_vp9_entropy_counts, joints) == 0x31f0,
	      "cedrus_vp9_entropy_counts joints offset mismatch");

/* Motion-vector counts reordered into the v4l2 array shapes. */
struct cedrus_vp9_nmv_counts {
	u32 joints[4];
	u32 sign[2][2];
	u32 classes[2][11];
	u32 class0[2][2];
	u32 bits[2][10][2];
	u32 class0_fp[2][2][4];
	u32 fp[2][4];
	u32 class0_hp[2][2];
	u32 hp[2][2];
};

struct cedrus_vp9_ctx {
	void		*prob_tbl;
	dma_addr_t	prob_tbl_dma;

	void		*neighbor_buf;
	dma_addr_t	neighbor_buf_dma;

	void		*col_mv_buf;
	dma_addr_t	col_mv_buf_dma;
	size_t		col_mv_buf_size;

	/* Per-segment dequantisation tables [seg][DC, AC]. */
	s16		y_dequant[8][2];
	s16		uv_dequant[8][2];

	/* Per-segment loop-filter levels [seg][ref][mode]. */
	u8		lf_lvl[8][4][2];

	/* VP9 frame contexts and current working probability table. */
	struct v4l2_vp9_frame_context	frame_ctx[4];
	struct v4l2_vp9_frame_context	cur_probs;
	u8				frame_ctx_idx;

	/* Symbol counts pointer table populated once at start time. */
	struct v4l2_vp9_frame_symbol_counts	symbol_counts;
	u32					tx16p_padded[2][4];
	struct cedrus_vp9_nmv_counts		nmv_counts;

	/*
	 * A frame was submitted and hasn't completed yet, and whether the
	 * last frame decoded without error, so that its counts are valid.
	 */
	bool		pending;
	bool		decode_ok;

	/* Last-frame state needed for temporal MV / use_128 decisions. */
	u32		last_flags;
	u32		last_w;
	u32		last_h;
	bool		last_valid;
};

static struct cedrus_vp9_ctx *cedrus_vp9_ctx(struct cedrus_ctx *ctx)
{
	return ctx->codec.vp9;
}

/*
 * Whether the backward adaptation is off. error_resilient_mode implies
 * frame_parallel_decoding_mode (section 7.2 of the VP9 specification),
 * whether or not userspace sets both flags.
 */
static bool cedrus_vp9_parallel(const struct v4l2_ctrl_vp9_frame *dec)
{
	return dec->flags & (V4L2_VP9_FRAME_FLAG_PARALLEL_DEC_MODE |
			     V4L2_VP9_FRAME_FLAG_ERROR_RESILIENT);
}

/* VP9 spec qindex computation for a given segment. */
static int cedrus_vp9_seg_qindex(const struct v4l2_ctrl_vp9_frame *dec,
				 unsigned int seg_id)
{
	const struct v4l2_vp9_segmentation *seg = &dec->seg;
	int q = dec->quant.base_q_idx;

	if (!(seg->flags & V4L2_VP9_SEGMENTATION_FLAG_ENABLED) ||
	    !v4l2_vp9_seg_feat_enabled(seg->feature_enabled,
				       V4L2_VP9_SEG_LVL_ALT_Q, seg_id))
		return clamp(q, 0, 255);

	if (seg->flags & V4L2_VP9_SEGMENTATION_FLAG_ABS_OR_DELTA_UPDATE)
		q = seg->feature_data[seg_id][V4L2_VP9_SEG_LVL_ALT_Q];
	else
		q += seg->feature_data[seg_id][V4L2_VP9_SEG_LVL_ALT_Q];

	return clamp(q, 0, 255);
}

static int cedrus_vp9_dc(int qindex, int delta)
{
	return vp9_dc_qlookup[clamp(qindex + delta, 0, 255)];
}

static int cedrus_vp9_ac(int qindex, int delta)
{
	return vp9_ac_qlookup[clamp(qindex + delta, 0, 255)];
}

static void cedrus_vp9_build_dequant(struct cedrus_vp9_ctx *vp9,
				     const struct v4l2_ctrl_vp9_frame *dec)
{
	unsigned int i, num_segments = 1;

	memset(vp9->y_dequant, 0, sizeof(vp9->y_dequant));
	memset(vp9->uv_dequant, 0, sizeof(vp9->uv_dequant));

	if (dec->seg.flags & V4L2_VP9_SEGMENTATION_FLAG_ENABLED)
		num_segments = 8;

	for (i = 0; i < num_segments; i++) {
		int q = cedrus_vp9_seg_qindex(dec, i);

		vp9->y_dequant[i][0] = cedrus_vp9_dc(q, dec->quant.delta_q_y_dc);
		vp9->y_dequant[i][1] = cedrus_vp9_ac(q, 0);
		vp9->uv_dequant[i][0] = cedrus_vp9_dc(q, dec->quant.delta_q_uv_dc);
		vp9->uv_dequant[i][1] = cedrus_vp9_ac(q, dec->quant.delta_q_uv_ac);
	}
}

/* Mirrors the spec 8.8.1 loop filter frame init (vp9_loop_filter_frame_init). */
static void cedrus_vp9_build_lf_lvl(struct cedrus_vp9_ctx *vp9,
				    const struct v4l2_ctrl_vp9_frame *dec)
{
	const struct v4l2_vp9_loop_filter *lf = &dec->lf;
	const struct v4l2_vp9_segmentation *seg = &dec->seg;
	bool seg_en = !!(seg->flags & V4L2_VP9_SEGMENTATION_FLAG_ENABLED);
	bool abs_upd = !!(seg->flags & V4L2_VP9_SEGMENTATION_FLAG_ABS_OR_DELTA_UPDATE);
	bool delta_en = !!(lf->flags & V4L2_VP9_LOOP_FILTER_FLAG_DELTA_ENABLED);
	int scale = 1 << (lf->level >> 5);
	unsigned int seg_id, ref, mode;

	for (seg_id = 0; seg_id < 8; seg_id++) {
		int seg_lvl = lf->level;

		if (seg_en &&
		    v4l2_vp9_seg_feat_enabled(seg->feature_enabled,
					      V4L2_VP9_SEG_LVL_ALT_L, seg_id)) {
			s16 d = seg->feature_data[seg_id][V4L2_VP9_SEG_LVL_ALT_L];

			seg_lvl = abs_upd ? d : (int)lf->level + d;
			seg_lvl = clamp(seg_lvl, 0, 63);
		}

		if (!delta_en) {
			memset(vp9->lf_lvl[seg_id], seg_lvl,
			       sizeof(vp9->lf_lvl[seg_id]));
			continue;
		}

		/* Intra blocks use the ref delta only, single mode. */
		vp9->lf_lvl[seg_id][0][0] =
			clamp(seg_lvl + lf->ref_deltas[0] * scale, 0, 63);
		vp9->lf_lvl[seg_id][0][1] = vp9->lf_lvl[seg_id][0][0];

		for (ref = 1; ref < 4; ref++)
			for (mode = 0; mode < 2; mode++)
				vp9->lf_lvl[seg_id][ref][mode] =
					clamp(seg_lvl +
					      (lf->ref_deltas[ref] +
					       lf->mode_deltas[mode]) * scale,
					      0, 63);
	}
}

/*
 * Pack the segment feature register: enables go in the lower half,
 * the per-segment ref-frame value pair in the upper half (2 bits each).
 */
static u32 cedrus_vp9_seg_feat_reg(const struct v4l2_ctrl_vp9_frame *dec)
{
	const struct v4l2_vp9_segmentation *seg = &dec->seg;
	u32 reg = 0;
	unsigned int i;

	if (!(seg->flags & V4L2_VP9_SEGMENTATION_FLAG_ENABLED))
		return 0;

	for (i = 0; i < 8; i++) {
		u8 fe = seg->feature_enabled[i];

		if (fe & V4L2_VP9_SEGMENT_FEATURE_ENABLED(V4L2_VP9_SEG_LVL_REF_FRAME)) {
			reg |= BIT(i);
			reg |= ((u32)seg->feature_data[i][V4L2_VP9_SEG_LVL_REF_FRAME] & 3)
			       << (16 + i * 2);
		}
		if (fe & V4L2_VP9_SEGMENT_FEATURE_ENABLED(V4L2_VP9_SEG_LVL_SKIP))
			reg |= BIT(8 + i);
	}
	return reg;
}

/*
 * A reference can be at most twice as large and 16 times smaller than the
 * frame that predicts from it.
 */
static bool cedrus_vp9_valid_ref_size(u32 ref_w, u32 ref_h,
				      u32 cur_w, u32 cur_h)
{
	return 2 * cur_w >= ref_w && 2 * cur_h >= ref_h &&
	       cur_w <= 16 * ref_w && cur_h <= 16 * ref_h;
}

/*
 * Compute scale-factor pair (reg0, reg1) for one reference frame:
 *   reg[ 4: 0] = step_q4 - 1
 *   reg[20: 5] = (ref_size << 14) / cur_size  (Q14 scale factor)
 */
static void cedrus_vp9_ref_scale(u32 ref_w, u32 ref_h, u32 cur_w, u32 cur_h,
				 u32 *reg0, u32 *reg1)
{
	u32 xfp, yfp, xstep, ystep;

	if (!ref_w || !ref_h || !cur_w || !cur_h) {
		*reg0 = 0;
		*reg1 = 0;
		return;
	}

	xfp = (ref_w << 14) / cur_w;
	yfp = (ref_h << 14) / cur_h;
	/* The step is derived from the Q14 factor. */
	xstep = xfp >> 10;
	ystep = yfp >> 10;

	*reg0 = VE_DEC_VP9_SCALE_STEP(xstep - 1) |
		VE_DEC_VP9_SCALE_FACTOR(xfp);
	*reg1 = VE_DEC_VP9_SCALE_STEP(ystep - 1) |
		VE_DEC_VP9_SCALE_FACTOR(yfp);
}

/*
 * Fill the SRAM port with dequant tables and loop-filter levels.  The
 * port auto-increments after each VE_DEC_VP9_SRAM_DATA write.
 */
static void cedrus_vp9_write_sram(struct cedrus_ctx *ctx)
{
	struct cedrus_dev *dev = ctx->dev;
	struct cedrus_vp9_ctx *vp9 = cedrus_vp9_ctx(ctx);
	unsigned int i;

	cedrus_write(dev, VE_DEC_VP9_SRAM_OFFSET, VE_DEC_VP9_SRAM_OFFSET_DEQUANT);

	for (i = 0; i < 8; i++) {
		u32 v = (u16)vp9->y_dequant[i][0] |
			(u32)(u16)vp9->y_dequant[i][1] << 16;
		cedrus_write(dev, VE_DEC_VP9_SRAM_DATA, v);
	}
	for (i = 0; i < 8; i++) {
		u32 v = (u16)vp9->uv_dequant[i][0] |
			(u32)(u16)vp9->uv_dequant[i][1] << 16;
		cedrus_write(dev, VE_DEC_VP9_SRAM_DATA, v);
	}

	cedrus_write(dev, VE_DEC_VP9_SRAM_OFFSET, VE_DEC_VP9_SRAM_OFFSET_LF);

	/*
	 * The loop-filter SRAM layout packs the 6-bit levels of a segment
	 * into two 32-bit words. The second level of the intra reference is
	 * not used.
	 */
	for (i = 0; i < 8; i++) {
		const u8 *l = vp9->lf_lvl[i][0];
		u32 w0 = (l[0] & 0x3f) |
			 ((u32)(l[2] & 0x3f) << 16) |
			 ((u32)(l[3] & 0x3f) << 24);
		u32 w1 = (l[4] & 0x3f) |
			 ((u32)(l[5] & 0x3f) << 8) |
			 ((u32)(l[6] & 0x3f) << 16) |
			 ((u32)(l[7] & 0x3f) << 24);

		cedrus_write(dev, VE_DEC_VP9_SRAM_DATA, w0);
		cedrus_write(dev, VE_DEC_VP9_SRAM_DATA, w1);
	}
}

static void cedrus_vp9_init_count_coeffs(struct cedrus_vp9_ctx *vp9)
{
	struct cedrus_vp9_entropy_counts *cnts =
		vp9->prob_tbl + CEDRUS_VP9_CTX_OFFSET;
	struct v4l2_vp9_frame_symbol_counts *sc = &vp9->symbol_counts;
	unsigned int i, j, k, l, m;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 2; j++) {
			for (k = 0; k < 2; k++) {
				for (l = 0; l < 6; l++) {
					for (m = 0; m < 6; m++) {
						u32 *coef = cnts->coeffs[i][j][k][l][m];

						sc->coeff[i][j][k][l][m] = (u32 (*)[3])coef;
						sc->eob[i][j][k][l][m][0] =
							&cnts->eobs[i][j][k][l][m];
						sc->eob[i][j][k][l][m][1] = &coef[3];
					}
				}
			}
		}
	}
}

/*
 * Wire vp9->symbol_counts pointers to the entropy-count region the
 * hardware will write into prob_tbl after decoding each frame.  Done
 * once per ctx because pointers stay valid for the buffer lifetime.
 */
static void cedrus_vp9_init_counts(struct cedrus_vp9_ctx *vp9)
{
	struct cedrus_vp9_entropy_counts *cnts =
		vp9->prob_tbl + CEDRUS_VP9_CTX_OFFSET;
	struct v4l2_vp9_frame_symbol_counts *sc = &vp9->symbol_counts;

	sc->partition   = &cnts->partition;
	sc->skip        = &cnts->mbskip;
	sc->intra_inter = &cnts->intra_inter;
	sc->tx32p       = &cnts->tx32x32;
	sc->tx8p        = &cnts->tx8x8;
	sc->y_mode      = &cnts->sb_ymode;
	sc->uv_mode     = &cnts->uv_mode;
	sc->comp        = &cnts->comp_inter;
	sc->comp_ref    = &cnts->comp_ref;
	sc->single_ref  = &cnts->single_ref;
	sc->mv_mode     = &cnts->inter_mode;
	sc->filter      = &cnts->switchable_interp;
	sc->mv_joint    = &vp9->nmv_counts.joints;
	sc->sign        = &vp9->nmv_counts.sign;
	sc->classes     = &vp9->nmv_counts.classes;
	sc->class0      = &vp9->nmv_counts.class0;
	sc->bits        = &vp9->nmv_counts.bits;
	sc->class0_fp   = &vp9->nmv_counts.class0_fp;
	sc->fp          = &vp9->nmv_counts.fp;
	sc->class0_hp   = &vp9->nmv_counts.class0_hp;
	sc->hp          = &vp9->nmv_counts.hp;

	cedrus_vp9_init_count_coeffs(vp9);
}

/*
 * Reorder the per-component motion-vector count blocks written by the
 * hardware into the interleaved array shapes the v4l2 VP9 library
 * expects.  Hardware stores the column component first.
 */
static void cedrus_vp9_translate_nmv_counts(struct cedrus_vp9_ctx *vp9)
{
	struct cedrus_vp9_entropy_counts *cnts =
		vp9->prob_tbl + CEDRUS_VP9_CTX_OFFSET;
	struct cedrus_vp9_nmv_counts *nmv = &vp9->nmv_counts;
	unsigned int c;

	memcpy(nmv->joints, cnts->joints, sizeof(nmv->joints));

	for (c = 0; c < 2; c++) {
		const struct cedrus_vp9_hw_nmv_comp *hw = &cnts->comp[1 - c];

		memcpy(nmv->sign[c], hw->sign, sizeof(nmv->sign[c]));
		memcpy(nmv->class0[c], hw->class0, sizeof(nmv->class0[c]));
		memcpy(nmv->class0_hp[c], hw->class0_hp,
		       sizeof(nmv->class0_hp[c]));
		memcpy(nmv->hp[c], hw->hp, sizeof(nmv->hp[c]));
		memcpy(nmv->classes[c], hw->classes, sizeof(nmv->classes[c]));
		memcpy(nmv->bits[c], hw->bits, sizeof(nmv->bits[c]));
		memcpy(nmv->class0_fp[c], hw->class0_fp,
		       sizeof(nmv->class0_fp[c]));
		memcpy(nmv->fp[c], hw->fp, sizeof(nmv->fp[c]));
	}
}

static enum cedrus_irq_status cedrus_vp9_irq_status(struct cedrus_ctx *ctx)
{
	struct cedrus_vp9_ctx *vp9 = cedrus_vp9_ctx(ctx);
	u32 reg = cedrus_read(ctx->dev, VE_DEC_VP9_STATUS) &
		  VE_DEC_VP9_STATUS_MASK;

	if (reg & (VE_DEC_VP9_STATUS_ERROR | VE_DEC_VP9_STATUS_VLD_DATA_REQ)) {
		vp9->decode_ok = false;
		return CEDRUS_IRQ_ERROR;
	}

	if (reg & VE_DEC_VP9_STATUS_FINISH) {
		vp9->decode_ok = true;
		return CEDRUS_IRQ_OK;
	}

	return CEDRUS_IRQ_NONE;
}

static void cedrus_vp9_irq_clear(struct cedrus_ctx *ctx)
{
	cedrus_write(ctx->dev, VE_DEC_VP9_STATUS, VE_DEC_VP9_STATUS_MASK);
}

static void cedrus_vp9_irq_disable(struct cedrus_ctx *ctx)
{
	struct cedrus_dev *dev = ctx->dev;
	u32 reg = cedrus_read(dev, VE_DEC_VP9_FUNC_CTRL);

	cedrus_write(dev, VE_DEC_VP9_FUNC_CTRL,
		     reg & ~VE_DEC_VP9_FUNC_CTRL_INT_MASK);
}

/*
 * The hardware reads probabilities from a packed block at
 * CEDRUS_VP9_PROBS_OFFSET in the prob_tbl buffer.  Most trees are packed
 * as one u32 per context holding up to four probability bytes.  The raw
 * v4l2_vp9_frame_context layout is NOT what the hardware consumes.
 */
static void cedrus_vp9_pack_mv_comp(u8 *buf,
				    const struct v4l2_vp9_frame_mv_context *mv,
				    unsigned int comp)
{
	buf[0x00] = mv->sign[comp];
	buf[0x01] = mv->class0_bit[comp];
	buf[0x02] = mv->class0_hp[comp];
	buf[0x03] = mv->hp[comp];
	memcpy(buf + 0x04, mv->class0_fr[comp][0], 3);
	memcpy(buf + 0x08, mv->class0_fr[comp][1], 3);
	memcpy(buf + 0x0c, mv->classes[comp], 10);
	memcpy(buf + 0x1c, mv->bits[comp], 10);
	memcpy(buf + 0x28, mv->fr[comp], 3);
}

static void cedrus_vp9_write_probs(struct cedrus_vp9_ctx *vp9,
				   const struct v4l2_ctrl_vp9_frame *dec)
{
	const struct v4l2_vp9_frame_context *p = &vp9->cur_probs;
	u8 *buf = vp9->prob_tbl + CEDRUS_VP9_PROBS_OFFSET;
	unsigned int i, j, k, l, m;
	u8 *coef;

	memset(buf, 0, CEDRUS_VP9_PROBS_SIZE);

	buf[0x000] = p->tx8[0][0];
	buf[0x001] = p->tx8[1][0];
	memcpy(buf + 0x004, p->tx16[0], 2);
	memcpy(buf + 0x008, p->tx16[1], 2);
	memcpy(buf + 0x00c, p->tx32[0], 3);
	memcpy(buf + 0x010, p->tx32[1], 3);

	/* One u32 per [tx][plane][ref][band][ctx], three probs each. */
	coef = buf + 0x014;
	for (i = 0; i < 4; i++)
		for (j = 0; j < 2; j++)
			for (k = 0; k < 2; k++)
				for (l = 0; l < 6; l++)
					for (m = 0; m < 6; m++) {
						memcpy(coef, p->coef[i][j][k][l][m], 3);
						coef += 4;
					}

	memcpy(buf + 0x914, p->skip, 3);
	for (i = 0; i < 7; i++)
		memcpy(buf + 0x918 + i * 4, p->inter_mode[i], 3);
	for (i = 0; i < 4; i++)
		memcpy(buf + 0x934 + i * 4, p->interp_filter[i], 2);
	memcpy(buf + 0x944, p->is_inter, 4);
	memcpy(buf + 0x948, p->comp_mode, 4);
	buf[0x94c] = p->comp_mode[4];
	memcpy(buf + 0x950, p->comp_ref, 4);
	buf[0x954] = p->comp_ref[4];
	for (i = 0; i < 4; i++)
		memcpy(buf + 0x958 + i * 4, p->single_ref[i], 2);
	memcpy(buf + 0x968, p->single_ref[4], 2);
	for (i = 0; i < 4; i++)
		memcpy(buf + 0x970 + i * 0x10, p->y_mode[i], 9);
	for (i = 0; i < 10; i++)
		memcpy(buf + 0x9b0 + i * 0x10, p->uv_mode[i], 9);
	for (i = 0; i < 16; i++)
		memcpy(buf + 0xa50 + i * 4, p->partition[i], 3);

	memcpy(buf + 0xa90, p->mv.joint, 3);
	cedrus_vp9_pack_mv_comp(buf + 0xa94, &p->mv, 1);
	cedrus_vp9_pack_mv_comp(buf + 0xac4, &p->mv, 0);

	if (dec->seg.flags & V4L2_VP9_SEGMENTATION_FLAG_ENABLED) {
		memcpy(buf + 0xaf0, dec->seg.tree_probs, 7);
		memcpy(buf + 0xaf8, dec->seg.pred_probs, 3);
	}
}

/* First 8x8 block of a tile (get_tile_offset() of the VP9 specification). */
static u32 cedrus_vp9_tile_offset(u32 tile_no, u32 mis, u32 log2_tile_count)
{
	u32 sb64s = (mis + 7) >> 3;

	return min(((sb64s * tile_no) >> log2_tile_count) << 3, mis);
}

/*
 * Entry list for tiles beyond the first one, at the start of the
 * prob_tbl buffer.  The first tile's rectangle is given through the
 * TILE_START/TILE_END registers; the others as { 0, packed rect } u64
 * pairs using the same encoding as those registers.
 */
static void cedrus_vp9_write_tile_list(struct cedrus_vp9_ctx *vp9,
				       const struct v4l2_ctrl_vp9_frame *dec,
				       u32 mi_cols, u32 mi_rows)
{
	u32 rows = 1 << dec->tile_rows_log2;
	u32 cols = 1 << dec->tile_cols_log2;
	__le64 *entry = vp9->prob_tbl;
	u32 r, c, n = 0;

	memset(vp9->prob_tbl, 0, CEDRUS_VP9_PROBS_OFFSET);

	if (rows * cols <= 1)
		return;

	for (r = 0; r < rows; r++) {
		u32 rs = cedrus_vp9_tile_offset(r, mi_rows, dec->tile_rows_log2);
		u32 re = cedrus_vp9_tile_offset(r + 1, mi_rows, dec->tile_rows_log2);

		for (c = 0; c < cols; c++) {
			u32 cs = cedrus_vp9_tile_offset(c, mi_cols, dec->tile_cols_log2);
			u32 ce = cedrus_vp9_tile_offset(c + 1, mi_cols, dec->tile_cols_log2);
			u64 rect;

			if (n++ == 0)
				continue;

			rect = (cs == ce || rs == re) ? BIT_ULL(31) : 0;
			rect |= (cs >> 3) & 0x1ff;
			rect |= ((u64)((rs >> 3) & 0x1ff)) << 16;
			rect |= ((u64)(((ce - 1) >> 3) & 0x1ff)) << 32;
			rect |= ((u64)(((re - 1) >> 3) & 0x1ff)) << 48;

			*entry++ = 0;
			*entry++ = cpu_to_le64(rect);
		}
	}
}

/*
 * Collocated MVs are stored per 8x8 block, 16 bytes each. The A733 vendor
 * decoder sizes the buffer differently, 640 bytes per 64x64 block of a frame
 * with one more block column and row, plus 16 KiB, which is larger for small
 * frames. Use the larger of the two.
 */
static size_t cedrus_vp9_col_mv_size(u32 width, u32 height)
{
	size_t size = (size_t)(ALIGN(width, 64) / 8) * (ALIGN(height, 64) / 8) * 16;
	size_t vendor = (size_t)((DIV_ROUND_UP(width, 8) + 15) / 8) *
			((DIV_ROUND_UP(height, 8) + 15) / 8) * 640;

	return max(size, ALIGN(vendor, SZ_1K) + SZ_16K);
}

/*
 * In-stream resolution changes can outgrow the collocated MV buffer sized
 * from the initial coded dimensions. Growing it is safe: temporal MVs are
 * never used across a resolution change, so its contents are dead.
 */
static int cedrus_vp9_grow_col_mv_buf(struct cedrus_ctx *ctx,
				      u32 width, u32 height)
{
	struct cedrus_vp9_ctx *vp9 = cedrus_vp9_ctx(ctx);
	size_t size = cedrus_vp9_col_mv_size(width, height);
	struct cedrus_dev *dev = ctx->dev;
	dma_addr_t buf_dma;
	void *buf;

	if (size <= vp9->col_mv_buf_size)
		return 0;

	buf = dma_alloc_coherent(dev->dev, size, &buf_dma, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	dma_free_coherent(dev->dev, vp9->col_mv_buf_size, vp9->col_mv_buf,
			  vp9->col_mv_buf_dma);
	vp9->col_mv_buf = buf;
	vp9->col_mv_buf_dma = buf_dma;
	vp9->col_mv_buf_size = size;

	return 0;
}

/*
 * The first tile goes to the TILE_START/TILE_END registers, the others to
 * the list written by cedrus_vp9_write_tile_list().
 */
static void cedrus_vp9_write_first_tile(struct cedrus_dev *dev,
					const struct v4l2_ctrl_vp9_frame *dec,
					u32 mi_cols, u32 mi_rows)
{
	u32 col_end = cedrus_vp9_tile_offset(1, mi_cols, dec->tile_cols_log2);
	u32 row_end = cedrus_vp9_tile_offset(1, mi_rows, dec->tile_rows_log2);
	u32 reg = 0;

	if (!col_end || !row_end)
		reg = VE_DEC_VP9_TILE_START_INVALID;

	cedrus_write(dev, VE_DEC_VP9_TILE_START, reg);
	cedrus_write(dev, VE_DEC_VP9_TILE_END,
		     VE_DEC_VP9_TILE_X((col_end - 1) >> 3) |
		     VE_DEC_VP9_TILE_Y((row_end - 1) >> 3));
}

/*
 * The output format registers of the top block, with the line stride of the
 * capture format and the chroma plane of the frame being decoded. The A733
 * vendor decoder writes the same three registers before every frame.
 */
static void cedrus_vp9_dst_format_set(struct cedrus_dev *dev,
				      const struct v4l2_pix_format *fmt,
				      unsigned int height)
{
	u32 reg;

	if (fmt->pixelformat == V4L2_PIX_FMT_NV21)
		reg = VE_PRIMARY_OUT_FMT_NV21;
	else
		reg = VE_PRIMARY_OUT_FMT_NV12;
	cedrus_write(dev, VE_PRIMARY_OUT_FMT, reg);

	cedrus_write(dev, VE_PRIMARY_CHROMA_BUF_LEN,
		     fmt->bytesperline * height / 4);

	reg = VE_PRIMARY_FB_LINE_STRIDE_LUMA(fmt->bytesperline) |
	      VE_PRIMARY_FB_LINE_STRIDE_CHROMA(fmt->bytesperline / 2);
	cedrus_write(dev, VE_PRIMARY_FB_LINE_STRIDE, reg);
}

static bool cedrus_vp9_ref_stride_ok(const struct v4l2_pix_format *fmt,
				     u32 ref_width)
{
	return ALIGN(ref_width, CEDRUS_VP9_STRIDE_ALIGN) == fmt->bytesperline;
}

static int cedrus_vp9_setup(struct cedrus_ctx *ctx, struct cedrus_run *run)
{
	const struct v4l2_ctrl_vp9_frame *dec = run->vp9.frame_params;
	const struct v4l2_ctrl_vp9_compressed_hdr *prob = run->vp9.prob_updates;
	struct cedrus_vp9_ctx *vp9 = cedrus_vp9_ctx(ctx);
	struct cedrus_buffer *dst_cb = vb2_to_cedrus_buffer(&run->dst->vb2_buf);
	struct cedrus_dev *dev = ctx->dev;
	struct vb2_queue *cap_q = &ctx->fh.m2m_ctx->cap_q_ctx.q;
	struct vb2_buffer *src_buf = &run->src->vb2_buf;
	struct v4l2_pix_format *recon = &ctx->dst_fmt;
	dma_addr_t src_dma, src_end, luma, chroma;
	u32 src_len, hdr_off, cur_w, cur_h, mi_cols, mi_rows;
	u32 hdr_syn, fc, reg, stride_align;
	bool intra_only, resolution_change, use_temporal_mv;
	int ret;

	if (!dec || !prob)
		return -EINVAL;

	/* The previous frame didn't complete (watchdog timeout). */
	if (vp9->pending)
		vp9->last_valid = false;

	cur_w = dec->frame_width_minus_1 + 1;
	cur_h = dec->frame_height_minus_1 + 1;

	/*
	 * Not supported: 10-bit frames. The H616 decoder and the A733 vendor
	 * decoder disagree on where the plane of the two low bits is (see
	 * VE_DEC_VP9_FIRST_OUT_OFFSET in REGISTERS.md), so fail the frame
	 * instead of programming one of the two.
	 */
	if (dec->bit_depth != 8)
		return -EINVAL;

	/* See cedrus_vp9_adjust_cap_format(). */
	if (!cedrus_vp9_cap_format_supported(recon->pixelformat) ||
	    recon->bytesperline % CEDRUS_VP9_STRIDE_ALIGN ||
	    recon->height % 16)
		return -EINVAL;

	/*
	 * The frame has to fit the capture buffers; the hardware writes whole
	 * 16x16 blocks.
	 */
	if (ALIGN(cur_w, 16) > ALIGN(recon->width, 16) ||
	    ALIGN(cur_h, 16) > recon->height)
		return -EINVAL;

	/* The whole frame is in a single buffer. */
	src_dma = vb2_dma_contig_plane_dma_addr(src_buf, 0);
	src_len = vb2_get_plane_payload(src_buf, 0);
	hdr_off = dec->uncompressed_header_size + dec->compressed_header_size;
	if (hdr_off >= src_len)
		return -EINVAL;

	/* The bitstream end address has a 1 KiB granularity. */
	src_end = ALIGN_DOWN(src_dma + vb2_plane_size(src_buf, 0), SZ_1K);
	if (src_dma + src_len > src_end)
		return -EINVAL;

	mi_cols = DIV_ROUND_UP(cur_w, 8);
	mi_rows = DIV_ROUND_UP(cur_h, 8);

	intra_only = !!(dec->flags & (V4L2_VP9_FRAME_FLAG_KEY_FRAME |
				      V4L2_VP9_FRAME_FLAG_INTRA_ONLY));

	resolution_change = vp9->last_valid &&
			    (vp9->last_w != cur_w || vp9->last_h != cur_h);

	use_temporal_mv = vp9->last_valid && !intra_only &&
			  !(dec->flags & V4L2_VP9_FRAME_FLAG_ERROR_RESILIENT) &&
			  !(vp9->last_flags & V4L2_VP9_FRAME_FLAG_KEY_FRAME) &&
			  (vp9->last_flags & V4L2_VP9_FRAME_FLAG_SHOW_FRAME) &&
			  !resolution_change;

	/*
	 * The HW predicts segment IDs from the map left in prob_tbl by
	 * earlier frames. Like libvpx (vp9_setup_past_independence()), clear
	 * it on key frames, intra-only and error-resilient frames, whether or
	 * not they use segmentation, and when the frame size changes.
	 */
	if (intra_only || resolution_change || !vp9->last_valid ||
	    (dec->flags & V4L2_VP9_FRAME_FLAG_ERROR_RESILIENT))
		memset(vp9->prob_tbl + CEDRUS_VP9_SEGMAP_OFFSET, 0,
		       CEDRUS_VP9_PROB_TBL_SIZE - CEDRUS_VP9_SEGMAP_OFFSET);

	/* Record per-buffer dimensions so future frames can use them as refs. */
	dst_cb->codec.vp9.width = cur_w;
	dst_cb->codec.vp9.height = cur_h;

	/* Forward probability update from the compressed header. */
	vp9->frame_ctx_idx = v4l2_vp9_reset_frame_ctx(dec, vp9->frame_ctx);
	vp9->cur_probs = vp9->frame_ctx[vp9->frame_ctx_idx];
	v4l2_vp9_fw_update_probs(&vp9->cur_probs, prob, dec);

	cedrus_vp9_build_dequant(vp9, dec);
	cedrus_vp9_build_lf_lvl(vp9, dec);

	ret = cedrus_vp9_grow_col_mv_buf(ctx, cur_w, cur_h);
	if (ret)
		return ret;

	ret = cedrus_engine_enable(ctx);
	if (ret)
		return ret;

	/*
	 * The picture width class is the one of the frame, not of the format.
	 * The A733 vendor library sets the same two bits with the same width
	 * thresholds when it resets the engine.
	 */
	reg = cedrus_read(dev, VE_MODE);
	reg &= ~(VE_MODE_PIC_WIDTH_IS_4096 | VE_MODE_PIC_WIDTH_MORE_2048);
	if (cur_w == 4096)
		reg |= VE_MODE_PIC_WIDTH_IS_4096;
	if (cur_w > 2048)
		reg |= VE_MODE_PIC_WIDTH_MORE_2048;
	cedrus_write(dev, VE_MODE, reg);

	cedrus_vp9_dst_format_set(dev, recon, ALIGN(cur_h, 16));

	/* Probability table input is the cur_probs we just updated. */
	cedrus_vp9_write_probs(vp9, dec);
	cedrus_vp9_write_tile_list(vp9, dec, mi_cols, mi_rows);

	/* Entropy counts are accumulated by the HW; start from zero. */
	if (!cedrus_vp9_parallel(dec))
		memset(vp9->prob_tbl + CEDRUS_VP9_CTX_OFFSET, 0,
		       sizeof(struct cedrus_vp9_entropy_counts));

	/* Header syntax register. */
	hdr_syn = VE_DEC_VP9_HDR_SYN_DEC_EN | VE_DEC_VP9_HDR_SYN_HW_EN2;

	if (dec->tile_cols_log2 || dec->tile_rows_log2)
		hdr_syn |= VE_DEC_VP9_HDR_SYN_TILES_EN;

	if (!intra_only)
		hdr_syn |= VE_DEC_VP9_HDR_SYN_INTER_FRAME;

	hdr_syn |= VE_DEC_VP9_HDR_SYN_DEPTH(dec->bit_depth - 8);

	if (dec->ref_frame_sign_bias & V4L2_VP9_SIGN_BIAS_LAST)
		hdr_syn |= VE_DEC_VP9_HDR_SYN_BIAS_LAST;
	if (dec->ref_frame_sign_bias & V4L2_VP9_SIGN_BIAS_GOLDEN)
		hdr_syn |= VE_DEC_VP9_HDR_SYN_BIAS_GOLDEN;
	if (dec->ref_frame_sign_bias & V4L2_VP9_SIGN_BIAS_ALT)
		hdr_syn |= VE_DEC_VP9_HDR_SYN_BIAS_ALT;

	if (dec->flags & V4L2_VP9_FRAME_FLAG_ALLOW_HIGH_PREC_MV)
		hdr_syn |= VE_DEC_VP9_HDR_SYN_HP_MV;

	if (!(dec->flags & V4L2_VP9_FRAME_FLAG_KEY_FRAME))
		hdr_syn |= VE_DEC_VP9_HDR_SYN_INTERP(dec->interpolation_filter);

	/*
	 * The A733 vendor decoder only sets the enable when the loop filter
	 * deltas are enabled too. The levels in the SRAM already include the
	 * deltas, so this follows the H616 decoder, which is right for either
	 * meaning of the bit.
	 */
	if (dec->lf.level) {
		hdr_syn |= VE_DEC_VP9_HDR_SYN_LF_EN;
		hdr_syn |= VE_DEC_VP9_HDR_SYN_LF_SHARP(dec->lf.sharpness);
	}

	if (!dec->quant.base_q_idx && !dec->quant.delta_q_y_dc &&
	    !dec->quant.delta_q_uv_dc && !dec->quant.delta_q_uv_ac)
		hdr_syn |= VE_DEC_VP9_HDR_SYN_LOSSLESS;

	if (dec->seg.flags & V4L2_VP9_SEGMENTATION_FLAG_ENABLED) {
		hdr_syn |= VE_DEC_VP9_HDR_SYN_SEG_EN;
		if (dec->seg.flags & V4L2_VP9_SEGMENTATION_FLAG_UPDATE_MAP)
			hdr_syn |= VE_DEC_VP9_HDR_SYN_SEG_UPD_MAP;
		if (dec->seg.flags & V4L2_VP9_SEGMENTATION_FLAG_TEMPORAL_UPDATE)
			hdr_syn |= VE_DEC_VP9_HDR_SYN_SEG_TEMP_UPD;
	}

	hdr_syn |= VE_DEC_VP9_HDR_SYN_TX_MODE(prob->tx_mode);
	hdr_syn |= VE_DEC_VP9_HDR_SYN_REF_MODE(dec->reference_mode);

	if (use_temporal_mv)
		hdr_syn |= VE_DEC_VP9_HDR_SYN_USE_PREV_MV;

	if (!cedrus_vp9_parallel(dec))
		hdr_syn |= VE_DEC_VP9_HDR_SYN_CNT_EN;

	cedrus_write(dev, VE_DEC_VP9_HDR_SYN, hdr_syn);

	cedrus_write(dev, VE_DEC_VP9_BITS_OFFSET, hdr_off * 8);
	cedrus_write(dev, VE_DEC_VP9_BITS_END,
		     VE_DEC_VP9_BITS_END_BASE(src_end));
	cedrus_write(dev, VE_DEC_VP9_BITS_LEN, (src_len - hdr_off) * 8);
	cedrus_write(dev, VE_DEC_VP9_BITS_ADDR,
		     VE_DEC_VP9_BITS_ADDR_BASE(src_dma) |
		     VE_DEC_VP9_BITS_ADDR_FIRST |
		     VE_DEC_VP9_BITS_ADDR_VALID |
		     VE_DEC_VP9_BITS_ADDR_LAST);

	/* Picture size and reference frame sizes / scale factors. */
	cedrus_write(dev, VE_DEC_VP9_PIC_SIZE,
		     VE_DEC_VP9_PIC_WIDTH(cur_w) |
		     VE_DEC_VP9_PIC_HEIGHT(cur_h));

	stride_align =
		VE_DEC_VP9_SCALE1_STRIDE_ALIGN(ilog2(CEDRUS_VP9_STRIDE_ALIGN / 8));

	if (intra_only) {
		cedrus_write(dev, VE_DEC_VP9_LAST_SCALE1, stride_align);
	} else {
		struct vb2_buffer *last_buf, *gold_buf, *alt_buf;
		struct cedrus_buffer *last_cb, *gold_cb, *alt_cb;
		u32 last_w, last_h, gold_w, gold_h, alt_w, alt_h;
		u32 s0, s1;

		last_buf = vb2_find_buffer(cap_q, dec->last_frame_ts);
		gold_buf = vb2_find_buffer(cap_q, dec->golden_frame_ts);
		alt_buf  = vb2_find_buffer(cap_q, dec->alt_frame_ts);

		/*
		 * A missing reference would be programmed as address 0 and the
		 * VE would fault reading it (seen when userspace reallocates
		 * the CAPTURE queue on a resolution change).
		 */
		if (!last_buf || !gold_buf || !alt_buf) {
			dev_warn_ratelimited(dev->dev,
					     "VP9 reference frame not found\n");
			return -EINVAL;
		}

		/*
		 * Pick each reference's recorded dimensions so the hardware
		 * scale factors compensate when the reference resolution
		 * differs from the current frame (VP9 scaled references).
		 */
		last_cb = vb2_to_cedrus_buffer(last_buf);
		gold_cb = vb2_to_cedrus_buffer(gold_buf);
		alt_cb = vb2_to_cedrus_buffer(alt_buf);

		last_w = last_cb->codec.vp9.width ?: cur_w;
		last_h = last_cb->codec.vp9.height ?: cur_h;
		gold_w = gold_cb->codec.vp9.width ?: cur_w;
		gold_h = gold_cb->codec.vp9.height ?: cur_h;
		alt_w = alt_cb->codec.vp9.width ?: cur_w;
		alt_h = alt_cb->codec.vp9.height ?: cur_h;

		/*
		 * The hardware reads a reference with the line stride it
		 * derives from the width of that reference, which has to be
		 * the one the reference was written with.
		 */
		if (!cedrus_vp9_ref_stride_ok(recon, last_w) ||
		    !cedrus_vp9_ref_stride_ok(recon, gold_w) ||
		    !cedrus_vp9_ref_stride_ok(recon, alt_w)) {
			dev_warn_ratelimited(dev->dev,
					     "VP9 reference with another line stride\n");
			return -EINVAL;
		}

		/*
		 * The scale factors only fit the registers within the scaling
		 * limits of the specification. Like libvpx, fail the frame
		 * when none of the references is within them.
		 */
		if (!cedrus_vp9_valid_ref_size(last_w, last_h, cur_w, cur_h) &&
		    !cedrus_vp9_valid_ref_size(gold_w, gold_h, cur_w, cur_h) &&
		    !cedrus_vp9_valid_ref_size(alt_w, alt_h, cur_w, cur_h))
			return -EINVAL;

		cedrus_write(dev, VE_DEC_VP9_LAST_PIC_SIZE,
			     VE_DEC_VP9_PIC_WIDTH(last_w) |
			     VE_DEC_VP9_PIC_HEIGHT(last_h));
		cedrus_write(dev, VE_DEC_VP9_GOLDEN_PIC_SIZE,
			     VE_DEC_VP9_PIC_WIDTH(gold_w) |
			     VE_DEC_VP9_PIC_HEIGHT(gold_h));
		cedrus_write(dev, VE_DEC_VP9_ALTREF_PIC_SIZE,
			     VE_DEC_VP9_PIC_WIDTH(alt_w) |
			     VE_DEC_VP9_PIC_HEIGHT(alt_h));

		cedrus_vp9_ref_scale(last_w, last_h, cur_w, cur_h, &s0, &s1);
		cedrus_write(dev, VE_DEC_VP9_LAST_SCALE0, s0);
		cedrus_write(dev, VE_DEC_VP9_LAST_SCALE1, s1 | stride_align);

		cedrus_vp9_ref_scale(gold_w, gold_h, cur_w, cur_h, &s0, &s1);
		cedrus_write(dev, VE_DEC_VP9_GOLDEN_SCALE0, s0);
		/*
		 * Unlike the other scale registers, GOLDEN_SCALE1 keeps
		 * the vertical scale factor in bits [31:16].
		 */
		cedrus_write(dev, VE_DEC_VP9_GOLDEN_SCALE1,
			     VE_DEC_VP9_GOLDEN_SCALE1_FACTOR(s1 >> 5) |
			     (s1 & GENMASK(4, 0)));

		cedrus_vp9_ref_scale(alt_w, alt_h, cur_w, cur_h, &s0, &s1);
		cedrus_write(dev, VE_DEC_VP9_ALTREF_SCALE0, s0);
		cedrus_write(dev, VE_DEC_VP9_ALTREF_SCALE1, s1);

		cedrus_write(dev, VE_DEC_VP9_LAST_LUMA_ADDR,
			     VE_DEC_VP9_BUF_ADDR(cedrus_dst_buf_addr(ctx, last_buf, 0)));
		cedrus_write(dev, VE_DEC_VP9_LAST_CHROMA_ADDR,
			     VE_DEC_VP9_BUF_ADDR(cedrus_dst_buf_addr(ctx, last_buf, 1)));
		cedrus_write(dev, VE_DEC_VP9_GOLDEN_LUMA_ADDR,
			     VE_DEC_VP9_BUF_ADDR(cedrus_dst_buf_addr(ctx, gold_buf, 0)));
		cedrus_write(dev, VE_DEC_VP9_GOLDEN_CHROMA_ADDR,
			     VE_DEC_VP9_BUF_ADDR(cedrus_dst_buf_addr(ctx, gold_buf, 1)));

		/* Altref chroma sits at an unusual register slot. */
		cedrus_write(dev, VE_DEC_VP9_ALTREF_LUMA_ADDR,
			     VE_DEC_VP9_BUF_ADDR(cedrus_dst_buf_addr(ctx, alt_buf, 0)));
		cedrus_write(dev, VE_DEC_VP9_ALTREF_CHROMA_ADDR,
			     VE_DEC_VP9_BUF_ADDR(cedrus_dst_buf_addr(ctx, alt_buf, 1)));
	}

	/* Current frame reconstruction targets. */
	luma = cedrus_dst_buf_addr(ctx, &run->dst->vb2_buf, 0);
	chroma = cedrus_dst_buf_addr(ctx, &run->dst->vb2_buf, 1);
	cedrus_write(dev, VE_DEC_VP9_CUR_LUMA_ADDR, VE_DEC_VP9_BUF_ADDR(luma));
	cedrus_write(dev, VE_DEC_VP9_CUR_CHROMA_ADDR, VE_DEC_VP9_BUF_ADDR(chroma));

	/*
	 * No second output. Inferred for the A733: zero is taken to be the
	 * reset value. The H616 decoder clears these; the A733 vendor decoder
	 * doesn't write them when it has no second output, but it resets the
	 * engine before every frame, which this driver doesn't.
	 */
	cedrus_write(dev, VE_DEC_VP9_SDRT_CTRL, 0);
	cedrus_write(dev, VE_DEC_VP9_SDRT_LUMA_ADDR, 0);
	cedrus_write(dev, VE_DEC_VP9_SDRT_CHROMA_ADDR, 0);

	/*
	 * Only 8-bit frames get here. Clear the 10-bit output registers, so
	 * nothing is left from an H.265 job of another context. Inferred for
	 * the A733, as above: its vendor decoder doesn't write them for
	 * 8-bit frames.
	 */
	cedrus_write(dev, VE_DEC_VP9_FIRST_OUT_OFFSET, 0);
	cedrus_write(dev, VE_DEC_VP9_10BIT_CFG, 0);

	/* Side buffers and segment feature register. */
	cedrus_write(dev, VE_DEC_VP9_NEIGHBOR_INFO_ADDR,
		     VE_DEC_VP9_BUF_ADDR(vp9->neighbor_buf_dma));
	cedrus_write(dev, VE_DEC_VP9_ENTRY_POINT_ADDR,
		     VE_DEC_VP9_BUF_ADDR(vp9->prob_tbl_dma));
	cedrus_write(dev, VE_DEC_VP9_COL_MV_ADDR,
		     VE_DEC_VP9_BUF_ADDR(vp9->col_mv_buf_dma));
	cedrus_write(dev, VE_DEC_VP9_SEG_FEAT,
		     cedrus_vp9_seg_feat_reg(dec));

	cedrus_vp9_write_first_tile(dev, dec, mi_cols, mi_rows);

	cedrus_vp9_write_sram(ctx);

	/* Functional control: the interrupt enables. */
	fc = VE_DEC_VP9_FUNC_CTRL_FINISH_INT |
	     VE_DEC_VP9_FUNC_CTRL_ERR_INT |
	     VE_DEC_VP9_FUNC_CTRL_DATA_REQ_INT;
	/*
	 * Both sources set this bit for frames 129 to 192 pixels wide and
	 * more than 64 pixels high; what it does is not known.
	 */
	if (ALIGN(cur_w, 16) > 128 && ALIGN(cur_w, 16) <= 192 &&
	    ALIGN(cur_h, 16) > 64)
		fc |= VE_DEC_VP9_FUNC_CTRL_DDR_CONS;
	cedrus_write(dev, VE_DEC_VP9_FUNC_CTRL, fc);

	vp9->pending = true;

	return 0;
}

/*
 * The A733 vendor decoder resets the engine, programs the registers and
 * writes the two triggers. This driver doesn't reset the engine for every
 * frame, so what the reset would clear is cleared here.
 */
static void cedrus_vp9_trigger(struct cedrus_ctx *ctx)
{
	struct cedrus_dev *dev = ctx->dev;

	/*
	 * Inferred: the interrupt flags are cleared by writing them, as the
	 * vendor interrupt handling writes back what it read.
	 */
	cedrus_write(dev, VE_DEC_VP9_STATUS, VE_DEC_VP9_STATUS_MASK);
	cedrus_write(dev, VE_DEC_VP9_TRIGGER, VE_DEC_VP9_TRIGGER_INIT_SWDEC);

	/*
	 * From the H616 decoder: the A733 vendor decoder has a name for this
	 * register but never writes it.
	 */
	cedrus_write(dev, VE_DEC_VP9_DEC_CTB_NUM, 0);

	/* Not written by the A733 vendor decoder; only when asked for. */
	if (cedrus_vp9_h616_sequence) {
		cedrus_write(dev, VE_DEC_COUNTER, 0);
		cedrus_write(dev, VE_DEC_COUNTER, VE_DEC_COUNTER_EN);
	}

	cedrus_write(dev, VE_DEC_VP9_TRIGGER, VE_DEC_VP9_TRIGGER_DEC_FRAME);
}

/*
 * Probability adaptation runs once the frame is done.  Called from the
 * irq_clear hook after we observe FINISH so the counts are stable.
 *
 * Mirrors the spec 6.1.2 refresh_probs() flow as implemented in the
 * verisilicon hantro_g2_vp9 driver: the forward-updated probabilities
 * used by the hardware to decode are discarded before adaptation, and
 * the saved frame context is reloaded as the adapt() input.  Adapted
 * probabilities are then written back to that frame context slot.
 *
 * The exception is intra-only frames, which carry forward updates to
 * tx and skip probabilities only.  Those are preserved across the
 * reload so adapt_coef_probs() sees them.
 */
struct cedrus_vp9_tx_skip {
	u8 tx8[2][1];
	u8 tx16[2][2];
	u8 tx32[2][3];
	u8 skip[3];
};

static void cedrus_vp9_save_tx_skip(struct cedrus_vp9_tx_skip *out,
				    const struct v4l2_vp9_frame_context *probs)
{
	memcpy(out->tx8, probs->tx8, sizeof(out->tx8));
	memcpy(out->tx16, probs->tx16, sizeof(out->tx16));
	memcpy(out->tx32, probs->tx32, sizeof(out->tx32));
	memcpy(out->skip, probs->skip, sizeof(out->skip));
}

static void cedrus_vp9_restore_tx_skip(struct v4l2_vp9_frame_context *probs,
				       const struct cedrus_vp9_tx_skip *src)
{
	memcpy(probs->tx8, src->tx8, sizeof(src->tx8));
	memcpy(probs->tx16, src->tx16, sizeof(src->tx16));
	memcpy(probs->tx32, src->tx32, sizeof(src->tx32));
	memcpy(probs->skip, src->skip, sizeof(src->skip));
}

static void cedrus_vp9_adapt_probs(struct cedrus_ctx *ctx)
{
	struct cedrus_vp9_ctx *vp9 = cedrus_vp9_ctx(ctx);
	const struct v4l2_ctrl_vp9_frame *dec;
	const struct v4l2_ctrl_vp9_compressed_hdr *prob;
	struct cedrus_vp9_entropy_counts *cnts;
	struct cedrus_vp9_tx_skip tx_skip;
	bool intra_only, refresh, parallel;
	unsigned int i;

	vp9->pending = false;

	dec = cedrus_find_control_data(ctx, V4L2_CID_STATELESS_VP9_FRAME);
	if (!dec)
		return;

	/*
	 * The counts of a frame which failed to decode are garbage: keep the
	 * frame contexts, and don't predict from the motion vectors and the
	 * segment map of that frame.
	 */
	if (!vp9->decode_ok) {
		vp9->last_valid = false;
		return;
	}

	refresh = dec->flags & V4L2_VP9_FRAME_FLAG_REFRESH_FRAME_CTX;
	parallel = cedrus_vp9_parallel(dec);
	intra_only = !!(dec->flags & (V4L2_VP9_FRAME_FLAG_KEY_FRAME |
				      V4L2_VP9_FRAME_FLAG_INTRA_ONLY));

	if (refresh && !parallel) {
		cnts = vp9->prob_tbl + CEDRUS_VP9_CTX_OFFSET;

		/*
		 * For intra-only frames the only probabilities updated by
		 * the compressed header are tx and skip.  Snapshot them
		 * before the frame-context reload so we can restore them.
		 */
		if (intra_only)
			cedrus_vp9_save_tx_skip(&tx_skip, &vp9->cur_probs);

		vp9->cur_probs = vp9->frame_ctx[vp9->frame_ctx_idx];

		if (intra_only)
			cedrus_vp9_restore_tx_skip(&vp9->cur_probs, &tx_skip);

		/* Pad tx16x16 from [2][3] to the [2][4] expected by v4l2. */
		for (i = 0; i < 2; i++) {
			vp9->tx16p_padded[i][0] = cnts->tx16x16[i][0];
			vp9->tx16p_padded[i][1] = cnts->tx16x16[i][1];
			vp9->tx16p_padded[i][2] = cnts->tx16x16[i][2];
			vp9->tx16p_padded[i][3] = 0;
		}
		vp9->symbol_counts.tx16p = &vp9->tx16p_padded;

		v4l2_vp9_adapt_coef_probs(&vp9->cur_probs,
					  &vp9->symbol_counts,
					  !vp9->last_valid ||
					  (vp9->last_flags &
					   V4L2_VP9_FRAME_FLAG_KEY_FRAME),
					  intra_only);

		if (!intra_only) {
			prob = cedrus_find_control_data(ctx,
							V4L2_CID_STATELESS_VP9_COMPRESSED_HDR);
			cedrus_vp9_translate_nmv_counts(vp9);
			v4l2_vp9_adapt_noncoef_probs(&vp9->cur_probs,
						     &vp9->symbol_counts,
						     dec->reference_mode,
						     dec->interpolation_filter,
						     prob ? prob->tx_mode : 0,
						     dec->flags);
		}
	}

	if (refresh)
		vp9->frame_ctx[vp9->frame_ctx_idx] = vp9->cur_probs;

	vp9->last_flags = dec->flags;
	vp9->last_w = dec->frame_width_minus_1 + 1;
	vp9->last_h = dec->frame_height_minus_1 + 1;
	vp9->last_valid = true;
}

static int cedrus_vp9_start(struct cedrus_ctx *ctx)
{
	struct cedrus_dev *dev = ctx->dev;
	struct cedrus_vp9_ctx *vp9;
	int i;

	vp9 = kzalloc_obj(*vp9);
	if (!vp9)
		return -ENOMEM;

	vp9->prob_tbl = dma_alloc_coherent(dev->dev, CEDRUS_VP9_PROB_TBL_SIZE,
					   &vp9->prob_tbl_dma, GFP_KERNEL);
	if (!vp9->prob_tbl)
		goto err_free_ctx;

	vp9->neighbor_buf = dma_alloc_coherent(dev->dev,
					       CEDRUS_VP9_NEIGHBOR_BUF_SIZE,
					       &vp9->neighbor_buf_dma,
					       GFP_KERNEL);
	if (!vp9->neighbor_buf)
		goto err_free_prob;

	/* Sized for the coded size of the format, grown by setup if needed. */
	vp9->col_mv_buf_size = cedrus_vp9_col_mv_size(ctx->src_fmt.width,
						      ctx->src_fmt.height);
	vp9->col_mv_buf = dma_alloc_coherent(dev->dev, vp9->col_mv_buf_size,
					     &vp9->col_mv_buf_dma, GFP_KERNEL);
	if (!vp9->col_mv_buf)
		goto err_free_neighbor;

	for (i = 0; i < 4; i++)
		vp9->frame_ctx[i] = v4l2_vp9_default_probs;
	vp9->cur_probs = v4l2_vp9_default_probs;

	cedrus_vp9_init_counts(vp9);

	ctx->codec.vp9 = vp9;
	return 0;

err_free_neighbor:
	dma_free_coherent(dev->dev, CEDRUS_VP9_NEIGHBOR_BUF_SIZE,
			  vp9->neighbor_buf, vp9->neighbor_buf_dma);
err_free_prob:
	dma_free_coherent(dev->dev, CEDRUS_VP9_PROB_TBL_SIZE,
			  vp9->prob_tbl, vp9->prob_tbl_dma);
err_free_ctx:
	kfree(vp9);
	return -ENOMEM;
}

static void cedrus_vp9_stop(struct cedrus_ctx *ctx)
{
	struct cedrus_dev *dev = ctx->dev;
	struct cedrus_vp9_ctx *vp9 = cedrus_vp9_ctx(ctx);

	dma_free_coherent(dev->dev, vp9->col_mv_buf_size,
			  vp9->col_mv_buf, vp9->col_mv_buf_dma);
	dma_free_coherent(dev->dev, CEDRUS_VP9_NEIGHBOR_BUF_SIZE,
			  vp9->neighbor_buf, vp9->neighbor_buf_dma);
	dma_free_coherent(dev->dev, CEDRUS_VP9_PROB_TBL_SIZE,
			  vp9->prob_tbl, vp9->prob_tbl_dma);
	kfree(vp9);
	ctx->codec.vp9 = NULL;
}

/*
 * Wrap irq_clear so probability adaptation runs after the IRQ status
 * has been observed but before the next job is dispatched.
 */
static void cedrus_vp9_irq_clear_and_adapt(struct cedrus_ctx *ctx)
{
	cedrus_vp9_adapt_probs(ctx);
	cedrus_vp9_irq_clear(ctx);
}

/*
 * The capture format of VP9: NV12 or NV21 with a line stride aligned to
 * CEDRUS_VP9_STRIDE_ALIGN. The height is already aligned to 16 lines.
 */
void cedrus_vp9_adjust_cap_format(struct v4l2_pix_format *pix_fmt)
{
	if (!cedrus_vp9_cap_format_supported(pix_fmt->pixelformat))
		pix_fmt->pixelformat = V4L2_PIX_FMT_NV12;

	pix_fmt->height = ALIGN(pix_fmt->height, 16);
	pix_fmt->bytesperline = ALIGN(pix_fmt->width, CEDRUS_VP9_STRIDE_ALIGN);
	pix_fmt->sizeimage = pix_fmt->bytesperline * pix_fmt->height * 3 / 2;
}

struct cedrus_dec_ops cedrus_dec_ops_vp9 = {
	.irq_clear	= cedrus_vp9_irq_clear_and_adapt,
	.irq_disable	= cedrus_vp9_irq_disable,
	.irq_status	= cedrus_vp9_irq_status,
	.setup		= cedrus_vp9_setup,
	.start		= cedrus_vp9_start,
	.stop		= cedrus_vp9_stop,
	.trigger	= cedrus_vp9_trigger,
};
