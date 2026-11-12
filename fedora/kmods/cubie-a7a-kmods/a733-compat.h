/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * cubie-a7a-kmods: register several platform drivers from one module.
 *
 * import.py rewrites each copied driver's module_platform_driver(drv) or
 * builtin_platform_driver(drv) line to A733_SUBDRIVER(drv); the module's
 * main.c then calls a733_register_<drv>() from its init, in order.
 */
#ifndef CUBIE_A7A_COMPAT_H
#define CUBIE_A7A_COMPAT_H

#include <linux/platform_device.h>

#define A733_DECLARE(drv)						\
	int a733_register_##drv(void);					\
	void a733_unregister_##drv(void)

#define A733_SUBDRIVER(drv)						\
	A733_DECLARE(drv);						\
	int a733_register_##drv(void)					\
	{								\
		return platform_driver_register(&(drv));		\
	}								\
	void a733_unregister_##drv(void)				\
	{								\
		platform_driver_unregister(&(drv));			\
	}

#endif
