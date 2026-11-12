# SPDX-License-Identifier: GPL-2.0-only
#
# cubie-a7a-kmods: Allwinner A733 / Radxa Cubie A7A drivers built out of tree
# against a stock Fedora kernel (see PROVENANCE and import.py).
#
#   make KERNELRELEASE=... -C /lib/modules/$(uname -r)/build M=$PWD modules

ifneq ($(KERNELRELEASE),)

ccflags-y += -I$(src)/include

obj-m += sun60i-a733-ccu.o
sun60i-a733-ccu-y := ccu/main.o ccu/ccu-sun60i-a733.o ccu/ccu-sun60i-a733-r.o \
	ccu/ccu_common.o ccu/ccu_mmc_timing.o ccu/ccu_reset.o ccu/ccu_div.o \
	ccu/ccu_frac.o ccu/ccu_gate.o ccu/ccu_mux.o ccu/ccu_mult.o ccu/ccu_phase.o \
	ccu/ccu_sdm.o ccu/ccu_nk.o ccu/ccu_nkm.o ccu/ccu_nkmp.o ccu/ccu_nm.o ccu/ccu_mp.o

obj-m += pinctrl-sun60i-a733.o
pinctrl-sun60i-a733-y := pinctrl/main.o pinctrl/pinctrl-sun60i-a733.o \
	pinctrl/pinctrl-sun60i-a733-r.o pinctrl/pinctrl-sunxi.o \
	pinctrl/pinctrl-sunxi-dt.o

obj-m += axp318w.o
axp318w-y := axp/axp20x-i2c.o axp/axp20x.o

obj-m += regulator/axp318-regulator.o

# Overrides of stock modules (the board package's depmod.d override makes
# depmod prefer these extra/ copies). They include
# kernel-internal headers copied from Fedora's 7.2 tree, so they are built
# only for 7.2 kernels (dkms.conf passes CUBIE_OVERRIDES=y then).
ifeq ($(CUBIE_OVERRIDES),y)
obj-m += dma/sun6i-dma.o
obj-m += stmmac/dwmac-sun55i.o
obj-m += sun60i-a733-serdes.o
sun60i-a733-serdes-y := serdes/phy-sun60i-a733.o
obj-m += sun60i-a733-pcie.o
sun60i-a733-pcie-y := pcie/pcie-sun60i-a733.o
obj-m += ppu/sun55i-pck600.o
# Thermal sensors (5, H6 layout, own calibration and curve) and the SID
# window the calibration comes from: stock drivers plus the A733 entries.
obj-m += sun8i_thermal.o
sun8i_thermal-y := thermal/sun8i_thermal.o
obj-m += nvmem_sunxi_sid.o
nvmem_sunxi_sid-y := nvmem/sunxi_sid.o
endif

else

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) CUBIE_OVERRIDES=$(CUBIE_OVERRIDES) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

mrproper: clean

help:
	@echo "modules   build against KDIR=$(KDIR)"
	@echo "clean     remove the build outputs"
	@echo "mrproper  same as clean"

.PHONY: modules clean mrproper help

endif
