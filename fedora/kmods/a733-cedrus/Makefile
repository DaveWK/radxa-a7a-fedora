# SPDX-License-Identifier: GPL-2.0
# a733-cedrus: Fedora's cedrus (drivers/staging/media/sunxi/cedrus, kernel
# 7.3.3) under another module name with one variant, the Allwinner A733
# decoder block. The object list is the in-tree Makefile's.
#
# Every codec is built in by default (cubie-a7a-vdec, DKMS) and offered or
# hidden when the module loads: module parameters mpeg2, h264, hevc, vp8
# (default on), hevc10, vp9, jpeg (default off); see `modinfo a733-cedrus`,
# PROVENANCE and TESTING.md. A build switch set to 0 leaves a codec out of
# the module altogether:
#   A733_CEDRUS_HEVC      H.265, 8 bit
#   A733_CEDRUS_HEVC10    H.265, 10 bit (follows A733_CEDRUS_HEVC; 1 implies it)
#   A733_CEDRUS_VP8       VP8
#   A733_CEDRUS_EXPERIMENTAL  default of the three above
#   A733_CEDRUS_VP9       VP9 (../a733-cedrus-vp9)
#   A733_CEDRUS_JPEG      a second video node that decodes baseline JPEG
#                         with the MPEG engine (../a733-cedrus-jpeg); needs
#                         v4l2-jpeg.ko (CONFIG_V4L2_JPEG_HELPER=m,
#                         kernel-modules)
# MPEG-2 and H.264 are always built in.
A733_CEDRUS_EXPERIMENTAL ?= 1
A733_CEDRUS_HEVC ?= $(A733_CEDRUS_EXPERIMENTAL)
A733_CEDRUS_HEVC10 ?= $(A733_CEDRUS_HEVC)
A733_CEDRUS_VP8 ?= $(A733_CEDRUS_EXPERIMENTAL)
A733_CEDRUS_VP9 ?= 1
A733_CEDRUS_JPEG ?= 1

ifneq ($(KERNELRELEASE),)
obj-m += a733-cedrus.o
a733-cedrus-y := cedrus.o cedrus_video.o cedrus_hw.o cedrus_dec.o \
		 cedrus_mpeg2.o cedrus_h264.o cedrus_h265.o \
		 cedrus_vp8.o cedrus_vp9.o
ifneq ($(filter 1,$(A733_CEDRUS_HEVC) $(A733_CEDRUS_HEVC10)),)
ccflags-y += -DA733_CEDRUS_CODEC_H265
endif
ifeq ($(A733_CEDRUS_HEVC10),1)
ccflags-y += -DA733_CEDRUS_CODEC_H265_10
endif
ifeq ($(A733_CEDRUS_VP8),1)
ccflags-y += -DA733_CEDRUS_CODEC_VP8
endif
ifeq ($(A733_CEDRUS_VP9),1)
ccflags-y += -DA733_CEDRUS_CODEC_VP9
endif
ifeq ($(A733_CEDRUS_JPEG),1)
a733-cedrus-y += cedrus_jpeg.o
ccflags-y += -DA733_CEDRUS_JPEG
endif
else
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) \
		A733_CEDRUS_EXPERIMENTAL=$(A733_CEDRUS_EXPERIMENTAL) \
		A733_CEDRUS_HEVC=$(A733_CEDRUS_HEVC) \
		A733_CEDRUS_HEVC10=$(A733_CEDRUS_HEVC10) \
		A733_CEDRUS_VP8=$(A733_CEDRUS_VP8) \
		A733_CEDRUS_VP9=$(A733_CEDRUS_VP9) \
		A733_CEDRUS_JPEG=$(A733_CEDRUS_JPEG) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
mrproper: clean
help:
	@echo "modules KDIR=...                build a733-cedrus.ko with every codec"
	@echo "                                (offered per module parameter, modinfo)"
	@echo "modules A733_CEDRUS_HEVC=0      without H.265 8 bit (and 10 bit)"
	@echo "modules A733_CEDRUS_HEVC10=0    without H.265 10 bit"
	@echo "modules A733_CEDRUS_VP8=0       without VP8"
	@echo "modules A733_CEDRUS_EXPERIMENTAL=0  without all three"
	@echo "modules A733_CEDRUS_VP9=0       without VP9"
	@echo "modules A733_CEDRUS_JPEG=0      without the JPEG node (no v4l2-jpeg dependency)"
	@echo "clean                           remove build outputs; mrproper: the same"
.PHONY: modules clean mrproper help
endif
