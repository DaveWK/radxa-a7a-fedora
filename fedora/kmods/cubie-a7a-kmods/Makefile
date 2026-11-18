# SPDX-License-Identifier: GPL-2.0-only
#
# cubie-a7a-kmods: Allwinner A733 / Radxa Cubie A7A drivers built out of tree
# against a stock Fedora kernel (see PROVENANCE and import.py).
#
#   make KERNELRELEASE=... -C /lib/modules/$(uname -r)/build M=$PWD modules

ifneq ($(KERNELRELEASE),)

ccflags-y += -I$(src)/include

# What this kernel needs (dkms.conf passes both; a hand build may):
#   CUBIE_SERIES   the kernel series whose internal headers the override
#                  modules are built with: 7.3 (7.2 and 7.3 kernels), 7.4,
#                  or empty (no override modules)
#   CUBIE_PINCTRL  y: build the A733 pin controller module. Default: y unless
#                  the kernel has the driver built in
#                  (CONFIG_PINCTRL_SUN60I_A733=y, mainline since v7.4-rc1),
#                  where a module for the same compatibles would never bind
CUBIE_OVERRIDES ?= n
ifeq ($(CUBIE_OVERRIDES),y)
CUBIE_SERIES ?= 7.3
endif
CUBIE_PINCTRL ?= $(if $(filter y,$(CONFIG_PINCTRL_SUN60I_A733)),n,y)

obj-m += sun60i-a733-ccu.o
sun60i-a733-ccu-y := ccu/main.o ccu/ccu-sun60i-a733.o ccu/ccu-sun60i-a733-r.o \
	ccu/ccu_common.o ccu/ccu_mmc_timing.o ccu/ccu_reset.o ccu/ccu_div.o \
	ccu/ccu_frac.o ccu/ccu_gate.o ccu/ccu_mux.o ccu/ccu_mult.o ccu/ccu_phase.o \
	ccu/ccu_sdm.o ccu/ccu_nk.o ccu/ccu_nkm.o ccu/ccu_nkmp.o ccu/ccu_nm.o ccu/ccu_mp.o

ifeq ($(CUBIE_PINCTRL),y)
obj-m += pinctrl-sun60i-a733.o
pinctrl-sun60i-a733-y := pinctrl/main.o pinctrl/pinctrl-sun60i-a733.o \
	pinctrl/pinctrl-sun60i-a733-r.o pinctrl/pinctrl-sunxi.o \
	pinctrl/pinctrl-sunxi-dt.o
endif

obj-m += axp318w.o
axp318w-y := axp/axp20x-i2c.o axp/axp20x.o

obj-m += regulator/axp318-regulator.o

# Overrides of stock modules (the board package's depmod.d override makes
# depmod prefer these extra/ copies) and the staged SerDes/PCIe drivers.
# dwmac-sun55i and the PCIe glue include kernel-internal headers (stmmac.h,
# pcie-designware.h, pci.h), which carry struct layouts: one set per kernel
# series, from Fedora's kernel source, in stmmac/k<series>/ and
# pcie/k<series>/. A series without a set gets no override modules.
ifneq ($(CUBIE_SERIES),)
ifeq ($(wildcard $(src)/stmmac/k$(CUBIE_SERIES)/stmmac.h),)
$(error cubie-a7a-kmods: no internal header set for kernel series $(CUBIE_SERIES))
endif
# sun6i-dma: the A733 support is in the stock module from v7.4-rc1 on.
ifeq ($(CUBIE_SERIES),7.3)
obj-m += dma/sun6i-dma.o
endif
obj-m += stmmac/dwmac-sun55i.o
CFLAGS_stmmac/dwmac-sun55i.o := -I$(src)/stmmac/k$(CUBIE_SERIES)
obj-m += sun60i-a733-serdes.o
sun60i-a733-serdes-y := serdes/phy-sun60i-a733.o
obj-m += sun60i-a733-pcie.o
sun60i-a733-pcie-y := pcie/pcie-sun60i-a733.o
CFLAGS_pcie/pcie-sun60i-a733.o := -I$(src)/pcie/k$(CUBIE_SERIES)
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
	$(MAKE) -C $(KDIR) M=$(CURDIR) CUBIE_SERIES=$(CUBIE_SERIES) $(if $(CUBIE_PINCTRL),CUBIE_PINCTRL=$(CUBIE_PINCTRL)) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

mrproper: clean

help:
	@echo "modules   build against KDIR=$(KDIR)"
	@echo "clean     remove the build outputs"
	@echo "mrproper  same as clean"

.PHONY: modules clean mrproper help

endif
