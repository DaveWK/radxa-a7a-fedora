# SPDX-License-Identifier: GPL-2.0-only
# Rockchip pcie-rkep (host side of an RK182x coprocessor on PCIe) as an
# out-of-tree module for a stock kernel. The DMA test helper is compiled into
# the module, as the vendor tree does for a modular build.
ifneq ($(KERNELRELEASE),)
obj-m += pcie-rkep.o
ccflags-y += -I$(src)/include -DCONFIG_PCIE_DW_DMATEST_MODULE=1
else
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
mrproper: clean
help:
	@echo "modules KDIR=...  build pcie-rkep.ko"
	@echo "clean             remove build outputs; mrproper: the same"
.PHONY: modules clean mrproper help
endif
