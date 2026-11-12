# SPDX-License-Identifier: GPL-2.0-only
# VeriSilicon VIPLite 2.0 kernel driver (vipcore) for the Allwinner A733's
# VIP9000 NPU, as an out-of-tree module for a stock kernel. The object list
# and the defines are the vendor Kbuild's for a platform device without the
# vendor IOMMU; the SoC glue is os/linux/platform/allwinner/platform_a733.c.
ifneq ($(KERNELRELEASE),)
obj-m += vipcore.o
ccflags-y += -I$(src) -I$(src)/inc -I$(src)/memory -I$(src)/os/linux \
	-I$(src)/os/linux/allocator -I$(src)/os/linux/platform/allwinner -I$(src)/task \
	-include $(src)/mainline-compat.h -DLINUX -DDRIVER -DDBG=0 -DNPU_USER_IOMMU=0 -DUSE_LINUX_PLATFORM_DEVICE \
	-DvpmdAUTO_CORRECT_CONFLICTS=1 -Wno-unused-function
vipcore-y := vip_drv_interface.o vip_drv_hardware.o vip_drv_device.o \
	vip_drv_context.o vip_drv_debug.o vip_drv_util.o vip_drv_pm.o \
	memory/vip_drv_mem_heap.o memory/vip_drv_mmu.o \
	memory/vip_drv_video_memory.o memory/vip_drv_mem_allocator.o \
	task/vip_drv_task_descriptor.o task/vip_drv_task_schedule.o \
	task/vip_drv_task_parallel_async.o task/vip_drv_task_serial_sync.o \
	task/vip_drv_task_parallel_sync.o task/vip_drv_task_single.o \
	task/vip_drv_task_common.o task/vip_drv_task_debug.o \
	os/linux/vip_drv_device_driver.o os/linux/vip_drv_os.o \
	os/linux/vip_drv_os_debug.o \
	os/linux/allocator/vip_drv_mem_allocator_common.o \
	os/linux/allocator/vip_drv_mem_allocator_heap_reserved.o \
	os/linux/allocator/vip_drv_mem_allocator_heap_exclusive.o \
	os/linux/allocator/vip_drv_mem_allocator_continue.o \
	os/linux/allocator/vip_drv_mem_allocator_segment_continue.o \
	os/linux/allocator/vip_drv_mem_allocator_gfp.o \
	os/linux/allocator/vip_drv_mem_allocator_cma.o \
	os/linux/allocator/vip_drv_mem_allocator_ion.o \
	os/linux/allocator/vip_drv_mem_allocator_wrap_user_physical.o \
	os/linux/allocator/vip_drv_mem_allocator_wrap_user_memory.o \
	os/linux/allocator/vip_drv_mem_allocator_wrap_dma_buf.o \
	os/linux/platform/allwinner/platform_a733.o
else
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
mrproper: clean
help:
	@echo "modules KDIR=...  build vipcore.ko"
	@echo "clean             remove build outputs; mrproper: the same"
.PHONY: modules clean mrproper help
endif
