/* SPDX-License-Identifier: GPL-2.0-only */
/* Kernel API the 6.6-era VIPLite sources use and current kernels dropped. */
#ifndef A733_VIPCORE_MAINLINE_COMPAT_H
#define A733_VIPCORE_MAINLINE_COMPAT_H
#include <linux/mm.h>
#ifndef nth_page
#define nth_page(page, n) ((page) + (n))
#endif
#endif
