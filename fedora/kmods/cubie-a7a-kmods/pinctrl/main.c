// SPDX-License-Identifier: GPL-2.0-only
/*
 * pinctrl-sun60i-a733: the Allwinner A733 main and R pin controllers, with a
 * private copy of the pinctrl-sunxi core (Fedora builds its own copy into
 * vmlinux, CONFIG_PINCTRL_SUNXI=y, without the A733 register layout).
 */
#include <linux/module.h>

#include "../a733-compat.h"

A733_DECLARE(a523_r_pinctrl_driver);
A733_DECLARE(a733_pinctrl_driver);

static int __init sun60i_a733_pinctrl_init(void)
{
	int ret;

	ret = a733_register_a523_r_pinctrl_driver();
	if (ret)
		return ret;
	ret = a733_register_a733_pinctrl_driver();
	if (ret)
		a733_unregister_a523_r_pinctrl_driver();
	return ret;
}
module_init(sun60i_a733_pinctrl_init);

static void __exit sun60i_a733_pinctrl_exit(void)
{
	a733_unregister_a733_pinctrl_driver();
	a733_unregister_a523_r_pinctrl_driver();
}
module_exit(sun60i_a733_pinctrl_exit);

MODULE_DESCRIPTION("Allwinner A733 pin controllers (cubie-a7a-kmods)");
MODULE_LICENSE("GPL");
