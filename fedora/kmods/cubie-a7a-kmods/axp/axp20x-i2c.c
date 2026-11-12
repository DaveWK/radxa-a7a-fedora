// SPDX-License-Identifier: GPL-2.0-only
/*
 * I2C driver for the X-Powers' Power Management ICs
 *
 * AXP20x typically comprises an adaptive USB-Compatible PWM charger, BUCK DC-DC
 * converters, LDOs, multiple 12-bit ADCs of voltage, current and temperature
 * as well as configurable GPIOs.
 *
 * This driver supports the I2C variants.
 *
 * Copyright (C) 2014 Carlo Caione
 *
 * Author: Carlo Caione <carlo@caione.org>
 */

#include <linux/acpi.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/mfd/axp20x-cubie.h>
#include <linux/of.h>
#include <linux/regmap.h>
#include <linux/slab.h>

static int axp20x_i2c_probe(struct i2c_client *i2c)
{
	struct axp20x_dev *axp20x;
	int ret;

	axp20x = devm_kzalloc(&i2c->dev, sizeof(*axp20x), GFP_KERNEL);
	if (!axp20x)
		return -ENOMEM;

	axp20x->dev = &i2c->dev;
	axp20x->irq = i2c->irq;
	dev_set_drvdata(axp20x->dev, axp20x);

	axp20x->variant = (kernel_ulong_t)i2c_get_match_data(i2c);
	ret = axp20x_match_device(axp20x);
	if (ret)
		return ret;

	axp20x->regmap = devm_regmap_init_i2c(i2c, axp20x->regmap_cfg);
	if (IS_ERR(axp20x->regmap)) {
		ret = PTR_ERR(axp20x->regmap);
		dev_err(&i2c->dev, "regmap init failed: %d\n", ret);
		return ret;
	}

	return axp20x_device_probe(axp20x);
}

static void axp20x_i2c_remove(struct i2c_client *i2c)
{
	struct axp20x_dev *axp20x = i2c_get_clientdata(i2c);

	axp20x_device_remove(axp20x);
}

#ifdef CONFIG_OF
static const struct of_device_id axp20x_i2c_of_match[] = {
	{ .compatible = "x-powers,axp318w", .data = (void *)AXP318_ID },
	{ },
};
MODULE_DEVICE_TABLE(of, axp20x_i2c_of_match);
#endif

static const struct i2c_device_id axp20x_i2c_id[] = {
	{ .name = "axp318w",	.driver_data = AXP318_ID },
	{ }
};
MODULE_DEVICE_TABLE(i2c, axp20x_i2c_id);

#ifdef CONFIG_ACPI
#endif

static struct i2c_driver axp20x_i2c_driver = {
	.driver = {
		.name	= "axp318w-i2c",
		.of_match_table	= of_match_ptr(axp20x_i2c_of_match),
	},
	.probe		= axp20x_i2c_probe,
	.remove		= axp20x_i2c_remove,
	.id_table	= axp20x_i2c_id,
};

module_i2c_driver(axp20x_i2c_driver);

MODULE_DESCRIPTION("PMIC MFD I2C driver for AXP20X");
MODULE_AUTHOR("Carlo Caione <carlo@caione.org>");
MODULE_LICENSE("GPL");
