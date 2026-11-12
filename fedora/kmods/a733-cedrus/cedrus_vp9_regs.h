/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Cedrus VPU driver
 *
 * Copyright (c) 2026 Jernej Skrabec <jernej.skrabec@gmail.com>
 *
 * VP9 registers of the Allwinner video engine. The VP9 decoder is a mode of
 * the H.265 engine: same register window (VE_ENGINE_DEC_H265), same mode
 * select value, different meaning of most registers.
 *
 * The definitions come from the cedrus VP9 decoder for the H616 (see
 * cedrus_vp9.c for the reference), where they were part of cedrus_regs.h.
 * Each one was compared with what the A733 vendor library programs, by
 * static inspection only; the evidence for every register is in the comment
 * in front of it, with the grades of REGISTERS.md:
 *
 *   A+B  defined by the open H616 driver (A), and the A733 vendor library
 *        programs the register in the same way (B)
 *   A    defined by the open H616 driver, not programmed by the A733 vendor
 *        library
 *   B    only known from the A733 vendor library
 *
 * Nothing here has run on an A733.
 */

#ifndef _CEDRUS_VP9_REGS_H_
#define _CEDRUS_VP9_REGS_H_

#include "cedrus_regs.h"

/* A+B */
#define VE_DEC_VP9_HDR_SYN		(VE_ENGINE_DEC_H265 + 0x04)
#define VE_DEC_VP9_HDR_SYN_TILES_EN		BIT(0)
#define VE_DEC_VP9_HDR_SYN_INTER_FRAME		BIT(1)
#define VE_DEC_VP9_HDR_SYN_DEPTH(d)		SHIFT_AND_MASK_BITS(d, 4, 2)
#define VE_DEC_VP9_HDR_SYN_BIAS_LAST		BIT(5)
#define VE_DEC_VP9_HDR_SYN_BIAS_GOLDEN		BIT(6)
#define VE_DEC_VP9_HDR_SYN_BIAS_ALT		BIT(7)
#define VE_DEC_VP9_HDR_SYN_HP_MV		BIT(8)
#define VE_DEC_VP9_HDR_SYN_INTERP(v)		SHIFT_AND_MASK_BITS(v, 11, 9)
/*
 * The H616 driver sets this bit when the filter level is not zero. The A733
 * vendor decoder sets it when the level is not zero and the loop filter
 * deltas are enabled.
 */
#define VE_DEC_VP9_HDR_SYN_LF_EN		BIT(12)
#define VE_DEC_VP9_HDR_SYN_LF_SHARP(v)		SHIFT_AND_MASK_BITS(v, 15, 13)
#define VE_DEC_VP9_HDR_SYN_LOSSLESS		BIT(16)
#define VE_DEC_VP9_HDR_SYN_SEG_EN		BIT(17)
#define VE_DEC_VP9_HDR_SYN_SEG_UPD_MAP		BIT(18)
#define VE_DEC_VP9_HDR_SYN_SEG_TEMP_UPD		BIT(19)
#define VE_DEC_VP9_HDR_SYN_TX_MODE(v)		SHIFT_AND_MASK_BITS(v, 22, 20)
#define VE_DEC_VP9_HDR_SYN_REF_MODE(v)		SHIFT_AND_MASK_BITS(v, 24, 23)
#define VE_DEC_VP9_HDR_SYN_USE_PREV_MV		BIT(25)
/* Always set by both; the function of bits 26 and 31 is not known. */
#define VE_DEC_VP9_HDR_SYN_HW_EN2		BIT(26)
/* Set when the frame is not in frame parallel decoding mode. */
#define VE_DEC_VP9_HDR_SYN_CNT_EN		BIT(27)
#define VE_DEC_VP9_HDR_SYN_DEC_EN		BIT(31)

/* A+B */
#define VE_DEC_VP9_PIC_SIZE		(VE_ENGINE_DEC_H265 + 0x08)
#define VE_DEC_VP9_PIC_WIDTH(w)			SHIFT_AND_MASK_BITS(w, 13, 0)
#define VE_DEC_VP9_PIC_HEIGHT(h)		SHIFT_AND_MASK_BITS(h, 29, 16)

/* A+B: same fields as VE_DEC_VP9_PIC_SIZE, for the three references. */
#define VE_DEC_VP9_LAST_PIC_SIZE	(VE_ENGINE_DEC_H265 + 0x0c)
#define VE_DEC_VP9_GOLDEN_PIC_SIZE	(VE_ENGINE_DEC_H265 + 0x10)
#define VE_DEC_VP9_ALTREF_PIC_SIZE	(VE_ENGINE_DEC_H265 + 0x14)

/*
 * A+B: SCALE0 is the horizontal and SCALE1 the vertical scale of a reference.
 * VE_DEC_VP9_GOLDEN_SCALE1 has the factor in bits 31:16 instead; both the
 * H616 driver and the A733 vendor decoder write it there.
 */
#define VE_DEC_VP9_LAST_SCALE0		(VE_ENGINE_DEC_H265 + 0x18)
#define VE_DEC_VP9_LAST_SCALE1		(VE_ENGINE_DEC_H265 + 0x1c)
#define VE_DEC_VP9_GOLDEN_SCALE0	(VE_ENGINE_DEC_H265 + 0x20)
#define VE_DEC_VP9_GOLDEN_SCALE1	(VE_ENGINE_DEC_H265 + 0x24)
#define VE_DEC_VP9_ALTREF_SCALE0	(VE_ENGINE_DEC_H265 + 0x28)
#define VE_DEC_VP9_ALTREF_SCALE1	(VE_ENGINE_DEC_H265 + 0x2c)
#define VE_DEC_VP9_SCALE_STEP(v)		SHIFT_AND_MASK_BITS(v, 4, 0)
#define VE_DEC_VP9_SCALE_FACTOR(v)		SHIFT_AND_MASK_BITS(v, 20, 5)
#define VE_DEC_VP9_GOLDEN_SCALE1_FACTOR(v)	SHIFT_AND_MASK_BITS(v, 31, 16)
/* In VE_DEC_VP9_LAST_SCALE1 only: log2(line stride alignment / 8). */
#define VE_DEC_VP9_SCALE1_STRIDE_ALIGN(v)	SHIFT_AND_MASK_BITS(v, 30, 28)

/* A+B, except where noted */
#define VE_DEC_VP9_FUNC_CTRL		(VE_ENGINE_DEC_H265 + 0x30)
#define VE_DEC_VP9_FUNC_CTRL_FINISH_INT		BIT(0)
#define VE_DEC_VP9_FUNC_CTRL_ERR_INT		BIT(1)
#define VE_DEC_VP9_FUNC_CTRL_DATA_REQ_INT	BIT(2)
/* B: set by the A733 vendor decoder when the second output is in use. */
#define VE_DEC_VP9_FUNC_CTRL_SECOND_OUT		BIT(9)
/* A: named by the H616 driver, written by neither. */
#define VE_DEC_VP9_FUNC_CTRL_MCRI_CACHE		BIT(10)
/*
 * Set by both for frames 129 to 192 pixels wide and more than 64 pixels
 * high. The H616 driver calls it DDR consistency; what it does is not known.
 */
#define VE_DEC_VP9_FUNC_CTRL_DDR_CONS		BIT(31)
#define VE_DEC_VP9_FUNC_CTRL_INT_MASK \
	(VE_DEC_VP9_FUNC_CTRL_FINISH_INT | \
	 VE_DEC_VP9_FUNC_CTRL_ERR_INT | \
	 VE_DEC_VP9_FUNC_CTRL_DATA_REQ_INT)

/* A+B */
#define VE_DEC_VP9_TRIGGER		(VE_ENGINE_DEC_H265 + 0x34)
#define VE_DEC_VP9_TRIGGER_INIT_SWDEC		0x7
#define VE_DEC_VP9_TRIGGER_DEC_FRAME		0x8

/* A+B */
#define VE_DEC_VP9_STATUS		(VE_ENGINE_DEC_H265 + 0x38)
#define VE_DEC_VP9_STATUS_FINISH		BIT(0)
#define VE_DEC_VP9_STATUS_ERROR			BIT(1)
#define VE_DEC_VP9_STATUS_VLD_DATA_REQ		BIT(2)
#define VE_DEC_VP9_STATUS_BS_DMA_BUSY		BIT(19)
#define VE_DEC_VP9_STATUS_MASK \
	(VE_DEC_VP9_STATUS_FINISH | \
	 VE_DEC_VP9_STATUS_ERROR | \
	 VE_DEC_VP9_STATUS_VLD_DATA_REQ)

/* A: the A733 vendor library only has a name for it. */
#define VE_DEC_VP9_DEC_CTB_NUM		(VE_ENGINE_DEC_H265 + 0x3c)

/* A+B */
#define VE_DEC_VP9_BITS_ADDR		(VE_ENGINE_DEC_H265 + 0x40)
#define VE_DEC_VP9_BITS_ADDR_FIRST		BIT(30)
#define VE_DEC_VP9_BITS_ADDR_LAST		BIT(29)
#define VE_DEC_VP9_BITS_ADDR_VALID		BIT(28)
#define VE_DEC_VP9_BITS_ADDR_BASE(a)		(((a) >> 8) & GENMASK(27, 0))

/* A+B: offset and length are in bits, the end has a 1 KiB granularity. */
#define VE_DEC_VP9_BITS_OFFSET		(VE_ENGINE_DEC_H265 + 0x44)
#define VE_DEC_VP9_BITS_LEN		(VE_ENGINE_DEC_H265 + 0x48)
#define VE_DEC_VP9_BITS_END		(VE_ENGINE_DEC_H265 + 0x4c)
#define VE_DEC_VP9_BITS_END_BASE(a)		((a) >> 8)

/*
 * A+B, fields unknown: second (scaled) output. The H616 driver clears the
 * three registers; the A733 vendor library only writes them when it uses
 * the second output (scaler coefficients then also go to the VE Top1 block,
 * see REGISTERS.md), and their fields are not decoded.
 */
#define VE_DEC_VP9_SDRT_CTRL		(VE_ENGINE_DEC_H265 + 0x50)
#define VE_DEC_VP9_SDRT_LUMA_ADDR	(VE_ENGINE_DEC_H265 + 0x54)
#define VE_DEC_VP9_SDRT_CHROMA_ADDR	(VE_ENGINE_DEC_H265 + 0x58)

/*
 * A+B: bits 7:0 reference feature enable of segments 0 to 7, bits 15:8 skip
 * feature enable, bits 31:16 the reference of each segment, two bits each.
 */
#define VE_DEC_VP9_SEG_FEAT		(VE_ENGINE_DEC_H265 + 0x5c)

/* A+B: all buffer addresses are in units of 256 bytes, 1 KiB aligned. */
#define VE_DEC_VP9_NEIGHBOR_INFO_ADDR	(VE_ENGINE_DEC_H265 + 0x60)
#define VE_DEC_VP9_ENTRY_POINT_ADDR	(VE_ENGINE_DEC_H265 + 0x64)
#define VE_DEC_VP9_BUF_ADDR(a)			((a) >> 8)

/* A+B: rectangle of the first tile, in 64x64 blocks. */
#define VE_DEC_VP9_TILE_START		(VE_ENGINE_DEC_H265 + 0x68)
#define VE_DEC_VP9_TILE_START_INVALID		BIT(31)
#define VE_DEC_VP9_TILE_X(x)			SHIFT_AND_MASK_BITS(x, 8, 0)
#define VE_DEC_VP9_TILE_Y(y)			SHIFT_AND_MASK_BITS(y, 24, 16)
#define VE_DEC_VP9_TILE_END		(VE_ENGINE_DEC_H265 + 0x6c)

/* A+B */
#define VE_DEC_VP9_COL_MV_ADDR		(VE_ENGINE_DEC_H265 + 0x78)
#define VE_DEC_VP9_ALTREF_CHROMA_ADDR	(VE_ENGINE_DEC_H265 + 0x7c)

/*
 * A+B, but the two disagree on the value for 10-bit frames, see REGISTERS.md.
 * Not written by this driver, which rejects 10-bit frames.
 */
#define VE_DEC_VP9_FIRST_OUT_OFFSET	(VE_ENGINE_DEC_H265 + 0x84)
#define VE_DEC_VP9_10BIT_CFG		(VE_ENGINE_DEC_H265 + 0x8c)
#define VE_DEC_VP9_10BIT_CFG_STRIDE(s)		SHIFT_AND_MASK_BITS(s, 11, 0)

/* A+B */
#define VE_DEC_VP9_CUR_LUMA_ADDR	(VE_ENGINE_DEC_H265 + 0x90)
#define VE_DEC_VP9_CUR_CHROMA_ADDR	(VE_ENGINE_DEC_H265 + 0x94)
#define VE_DEC_VP9_LAST_LUMA_ADDR	(VE_ENGINE_DEC_H265 + 0x98)
#define VE_DEC_VP9_LAST_CHROMA_ADDR	(VE_ENGINE_DEC_H265 + 0x9c)
#define VE_DEC_VP9_GOLDEN_LUMA_ADDR	(VE_ENGINE_DEC_H265 + 0xa0)
#define VE_DEC_VP9_GOLDEN_CHROMA_ADDR	(VE_ENGINE_DEC_H265 + 0xa4)
#define VE_DEC_VP9_ALTREF_LUMA_ADDR	(VE_ENGINE_DEC_H265 + 0xa8)

/*
 * B: second SRAM port, which the A733 vendor decoder only writes when it
 * lets the hardware parse the compressed header. It never does: the switch
 * is cleared when the decoder is created. Not used by this driver.
 */
#define VE_DEC_VP9_SRAM1_OFFSET		(VE_ENGINE_DEC_H265 + 0xc0)
#define VE_DEC_VP9_SRAM1_DATA		(VE_ENGINE_DEC_H265 + 0xc4)

/* A+B: the data port increments the offset. */
#define VE_DEC_VP9_SRAM_OFFSET		(VE_ENGINE_DEC_H265 + 0xe0)
#define VE_DEC_VP9_SRAM_OFFSET_DEQUANT		0x000
#define VE_DEC_VP9_SRAM_OFFSET_LF		0x100
#define VE_DEC_VP9_SRAM_DATA		(VE_ENGINE_DEC_H265 + 0xe4)

#endif
