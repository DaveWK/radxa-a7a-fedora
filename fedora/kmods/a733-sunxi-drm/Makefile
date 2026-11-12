# SPDX-License-Identifier: GPL-2.0-only
# Allwinner sunxi-drm display driver for the A733 (sun60iw2), HDMI path only,
# as an out-of-tree module for a stock kernel. The object list is the vendor
# Makefile's with DSI, LVDS, RGB, eDP, panels, the DSI combo PHY, HDCP and the
# vendor fbdev left out; a733-config.h carries the Kconfig-style defines.
ifneq ($(KERNELRELEASE),)
obj-m += sunxidrm.o

hw := sunxi_device/hardware
de := $(hw)/lowlevel_de
hdmi := $(hw)/lowlevel_hdmi20

ccflags-y += -I$(src) -I$(src)/compat -I$(src)/bsp-include \
	-I$(src)/$(hw) -I$(src)/$(hw)/lowlevel_lcd -I$(src)/$(hw)/lowlevel_tcon \
	-I$(src)/$(hdmi) -I$(src)/$(de) \
	$(foreach d,csc cdc snr sharp dci dlc fcm bld ovl scaler afbd tfbd wb gamma dither crc smbl deband fmt,-I$(src)/$(de)/$(d)) \
	-include $(src)/a733-config.h -include $(src)/compat/mainline-compat.h \
	-Wno-unused-function -Wno-unused-variable
CFLAGS_sunxi_drm_trace.o := -I$(src)

# base
sunxidrm-y := sunxi_drm_drv.o sunxi_drm_crtc.o sunxi_drm_intf.o \
	sunxi_drm_notify.o sunxi_drm_gem.o sunxi_drm_debug.o sunxi_drm_trace.o

# display engine (v352 on sun60iw2)
sunxidrm-y += $(de)/de_backend.o $(de)/de_channel.o $(de)/sunxi_de.o \
	$(de)/de_top.o $(de)/de_frontend.o $(de)/wb/de_wb.o \
	$(de)/afbd/de_fbd_atw.o $(de)/tfbd/de_tfbd.o \
	$(de)/csc/de_csc.o $(de)/csc/de_csc_table.o $(de)/csc/de_csc_platform.o \
	$(de)/cdc/de_cdc.o $(de)/cdc/de_cdc_table.o $(de)/cdc/de_cdc_platform.o \
	$(de)/snr/de_snr.o $(de)/snr/de_snr_platform.o \
	$(de)/sharp/de_sharp.o $(de)/sharp/de_sharp_platform.o \
	$(de)/dci/de_dci.o $(de)/dci/de_dci_platform.o \
	$(de)/dlc/de_dlc.o $(de)/dlc/de_dlc_platform.o \
	$(de)/fcm/de_fcm.o $(de)/fcm/de_fcm_platform.o \
	$(de)/bld/de_bld.o $(de)/bld/de_bld_platform.o \
	$(de)/ovl/de_ovl.o $(de)/ovl/de_ovl_platform.o \
	$(de)/scaler/de_scaler.o $(de)/scaler/de_scaler_table.o \
	$(de)/scaler/de_scaler_platform.o \
	$(de)/gamma/de_gamma.o $(de)/gamma/de_gamma_platform.o \
	$(de)/dither/de_dither.o $(de)/dither/de_dither_platform.o \
	$(de)/crc/de_crc.o $(de)/crc/de_crc_platform.o \
	$(de)/smbl/de_smbl.o $(de)/smbl/de_smbl_platform.o \
	$(de)/deband/de_deband.o $(de)/deband/de_deband_platform.o \
	$(de)/fmt/de_fmt.o $(de)/fmt/de_fmt_platform.o

# tcon (the tcon core shares one file between tcon-lcd and tcon-tv, so the
# tcon-lcd register layer stays even though no LCD output is built)
sunxidrm-y += sunxi_device/sunxi_tcon.o sunxi_device/sunxi_tcon_top.o \
	$(hw)/lowlevel_tcon/tcon_tv_reg.o $(hw)/lowlevel_tcon/tcon_top.o \
	$(hw)/lowlevel_lcd/tcon_lcd.o

# HDMI 2.0 TX
sunxidrm-y += sunxi_drm_hdmi.o sunxi_device/sunxi_hdmi.o \
	$(hdmi)/dw_dev.o $(hdmi)/dw_avp.o $(hdmi)/dw_edid.o $(hdmi)/dw_fc.o \
	$(hdmi)/dw_i2cm.o $(hdmi)/dw_mc.o $(hdmi)/dw_phy.o \
	$(hdmi)/phy_top.o $(hdmi)/phy_aw.o $(hdmi)/phy_snps.o $(hdmi)/phy_inno.o \
	$(hdmi)/dw_cec.o $(hdmi)/dw_hdcp.o compat/bsp_stubs.o
else
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
mrproper: clean
help:
	@echo "modules KDIR=...  build sunxidrm.ko"
	@echo "clean             remove build outputs; mrproper: the same"
.PHONY: modules clean mrproper help
endif
