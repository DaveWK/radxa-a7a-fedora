/* SPDX-License-Identifier: GPL-2.0 */
/*
 * a733-cedrus: registers used for JPEG decoding
 *
 * The grades of the register notes (not included here) are given in
 * brackets.
 *
 * 1. JPEG mode of the MPEG engine (VE base + 0x100), the path cedrus_jpeg.c
 *    programs. Names follow "[PATCH 0/4] media: cedrus: Add a JPEG decoder",
 *    Emmanuel Gil Peyrot and Jernej Skrabec, 2024-07-31, Message-ID
 *    20240731164422.206503-1-linkmauve@linkmauve.fr (GPL-2.0, not in Linux
 *    7.3.3). The vendor MJPEG library the A733 is set up to use drives the
 *    same registers with the same values.
 *
 * 2. The stand-alone JPEG decoder block (VE base + 0xe00). Only the enable
 *    bit and the interrupt registers are defined, for documentation; nothing
 *    in this module writes them. On the A733 the vendor kernel driver does
 *    not service its interrupt and the vendor library selection does not
 *    choose it.
 */

#ifndef _CEDRUS_JPEG_REGS_H_
#define _CEDRUS_JPEG_REGS_H_

#include "cedrus_regs.h"

/* VE top level: second ("rotate/scale") output, which JPEG decodes into. */

#define VE_SECONDARY_FB_LINE_STRIDE		0xcc

#define VE_SECONDARY_FB_LINE_STRIDE_CHROMA(s)	SHIFT_AND_MASK_BITS(s, 31, 16)
#define VE_SECONDARY_FB_LINE_STRIDE_LUMA(s)	SHIFT_AND_MASK_BITS(s, 15, 0)

/* Further fields of VE_CHROMA_BUF_LEN (0xe8). */
#define VE_CHROMA_WIDTH_ALIGN_16		(0x00 << 29)
#define VE_CHROMA_WIDTH_ALIGN_8			(0x01 << 29)
#define VE_LUMA_WIDTH_ALIGN_16			(0x00 << 28)
#define VE_LUMA_WIDTH_ALIGN_32			(0x01 << 28)

/* MPEG engine, JPEG mode. */

/*
 * Interrupt enables for the MPEG engine as the vendor kernel driver checks
 * and clears them for sun60iw2 (mask 0x7c), and as the vendor library and
 * the reverse-engineered jpeg-test set them for JPEG [A, B]. Bits 3 to 6
 * are cedrus' FINISH, ERROR, VLD_DATA_REQ and ROTATE enables; bit 2 has no
 * known name [U].
 */
#define VE_DEC_MPEG_CTRL_JPEG_IRQ_MASK		GENMASK(6, 2)
/* Chroma of 4:2:2 and 4:4:4 pictures reduced to 4:2:0 on output [A, B]. */
#define VE_DEC_MPEG_CTRL_JPEG_FORCE_420		BIT(18)

/*
 * Status bits the vendor kernel driver treats as "interrupt pending" and
 * the vendor library clears after a JPEG decode [A, B]. Bits 0 to 2 are
 * cedrus' SUCCESS, ERROR and VLD_DATA_REQ; bit 3 has no known name [U].
 */
#define VE_DEC_MPEG_STATUS_JPEG_CHECK_MASK	GENMASK(3, 0)

#define VE_DEC_MPEG_TRIGGER_CHROMA_FMT_400	(0x05 << 27)

#define VE_DEC_MPEG_JPEG_SIZE			(VE_ENGINE_DEC_MPEG + 0xb8)

/* Both in MCUs. */
#define VE_DEC_MPEG_JPEG_SIZE_WIDTH(w) \
	SHIFT_AND_MASK_BITS((w) - 1, 10, 0)
#define VE_DEC_MPEG_JPEG_SIZE_HEIGHT(h) \
	SHIFT_AND_MASK_BITS((h) - 1, 26, 16)

#define VE_DEC_MPEG_JPEG_MCU			(VE_ENGINE_DEC_MPEG + 0xbc)
#define VE_DEC_MPEG_JPEG_RES_INT		(VE_ENGINE_DEC_MPEG + 0xc0)
/* Set by the vendor library for single-component pictures [B]. */
#define VE_DEC_MPEG_JPEG_RES_INT_GREY		BIT(31)
#define VE_DEC_MPEG_SD_ROT_DBLK_CTL		(VE_ENGINE_DEC_MPEG + 0xd4)
#define VE_DEC_MPEG_JPEG_MCU_START		(VE_ENGINE_DEC_MPEG + 0xd8)
#define VE_DEC_MPEG_JPEG_MCU_END		(VE_ENGINE_DEC_MPEG + 0xdc)
#define VE_DEC_MPEG_SRAM_RW_OFFSET		(VE_ENGINE_DEC_MPEG + 0xe0)
#define VE_DEC_MPEG_SRAM_RW_DATA		(VE_ENGINE_DEC_MPEG + 0xe4)

/*
 * Huffman table SRAM image, in 16-bit words. Table n (0: first component
 * DC, 1: first component AC, 2: second component DC, 3: second component
 * AC) has a 32-word header at 32 * n: sixteen first codes by code length
 * (0xffff above the longest used length), eight words of 8-bit indexes of
 * the first symbol by code length, eight zero words. Its symbols are packed
 * two per word from word 512 + 128 * n. The image is loaded as 512 32-bit
 * writes after setting the SRAM offset to 0 [A, B].
 */
#define VE_DEC_MPEG_JPEG_HT_WORDS		1024
#define VE_DEC_MPEG_JPEG_HT_HEADER(n)		(32 * (n))
#define VE_DEC_MPEG_JPEG_HT_SYMBOLS(n)		(512 + 128 * (n))
#define VE_DEC_MPEG_JPEG_HT_UNUSED		0xffff

/*
 * Stand-alone JPEG decoder block. Not written by this module.
 *
 * Selected by VE_MODE bit 5, next to the mode field [A for older SoCs, B].
 * Interrupt control and status at the same offsets as in the MPEG engine
 * [A for sun55iw6 and sun300iw1].
 */
#define VE_ENGINE_DEC_JPEG			0xe00

#define VE_MODE_JPEG_DEC_EN			BIT(5)

#define VE_DEC_JPEG_INT_CTRL			(VE_ENGINE_DEC_JPEG + 0x14)
#define VE_DEC_JPEG_INT_STATUS			(VE_ENGINE_DEC_JPEG + 0x1c)

#endif
