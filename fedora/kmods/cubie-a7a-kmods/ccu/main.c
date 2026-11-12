// SPDX-License-Identifier: GPL-2.0-only
/*
 * sun60i-a733-ccu: the Allwinner A733 main and PRCM clock controllers, with a
 * private copy of the sunxi-ng CCU core (Fedora builds its own copy into
 * vmlinux, CONFIG_SUNXI_CCU=y, without the A733 changes).
 */
#include <linux/module.h>

#include "../a733-compat.h"

A733_DECLARE(sun60i_a733_r_ccu_driver);
A733_DECLARE(sun60i_a733_ccu_driver);

static int __init sun60i_a733_ccu_init(void)
{
	int ret;

	ret = a733_register_sun60i_a733_r_ccu_driver();
	if (ret)
		return ret;
	ret = a733_register_sun60i_a733_ccu_driver();
	if (ret)
		a733_unregister_sun60i_a733_r_ccu_driver();
	return ret;
}
module_init(sun60i_a733_ccu_init);

static void __exit sun60i_a733_ccu_exit(void)
{
	a733_unregister_sun60i_a733_ccu_driver();
	a733_unregister_sun60i_a733_r_ccu_driver();
}
module_exit(sun60i_a733_ccu_exit);

MODULE_DESCRIPTION("Allwinner A733 CCU and PRCM CCU (cubie-a7a-kmods)");
MODULE_LICENSE("GPL");
