# SPDX-License-Identifier: GPL-2.0-only
#
# Build the Cubie A7A DTB.
#   make                        -> sun60i-a733-cubie-a7a.dtb (origin "firmware")
#   make DTB_ORIGIN=rpm OUT=... -> the copy cubie-a7a-dtb packages
#
# DTB_VERSION is the binding stamp: bump it whenever a change here needs a
# newer DTB than the one in already-flashed firmware (cubie-a7a-dtb then
# installs its copy on the ESP until the firmware catches up).

DTB_VERSION ?= $(shell cat $(CURDIR)/DTB_VERSION)
DTB_ORIGIN  ?= firmware
OUT         ?= sun60i-a733-cubie-a7a.dtb
CPP         ?= cpp
DTC         ?= dtc

all: $(OUT)

$(OUT): $(wildcard *.dts *.dtsi series/* include/dt-bindings/*/*.h) DTB_VERSION
	$(CPP) -nostdinc -undef -D__DTS__ -x assembler-with-cpp -P \
		-I $(CURDIR) -I $(CURDIR)/include \
		-DDTB_VERSION=$(DTB_VERSION) -DDTB_ORIGIN='"$(DTB_ORIGIN)"' \
		sun60i-a733-cubie-a7a.dts > $(OUT).pre.dts
	$(DTC) -q -I dts -O dtb -@ -o $@ $(OUT).pre.dts
	rm -f $(OUT).pre.dts

# Test DTB with the open display nodes (a733-display-open) in place of the
# vendor sunxidrm ones; not part of "all".
OPEN_OUT ?= sun60i-a733-cubie-a7a-open-display.dtb
open-display: $(OPEN_OUT)

$(OPEN_OUT): $(wildcard *.dts *.dtsi series/* include/dt-bindings/*/*.h) DTB_VERSION
	$(CPP) -nostdinc -undef -D__DTS__ -x assembler-with-cpp -P \
		-I $(CURDIR) -I $(CURDIR)/include \
		-DDTB_VERSION=$(DTB_VERSION) -DDTB_ORIGIN='"$(DTB_ORIGIN)"' \
		sun60i-a733-cubie-a7a-open-display.dts > $(OPEN_OUT).pre.dts
	$(DTC) -q -I dts -O dtb -@ -o $@ $(OPEN_OUT).pre.dts
	rm -f $(OPEN_OUT).pre.dts

clean:
	rm -f *.dtb *.pre.dts

mrproper: clean

help:
	@echo "all       $(OUT) (DTB_ORIGIN=$(DTB_ORIGIN), DTB_VERSION=$(DTB_VERSION))"
	@echo "open-display  $(OPEN_OUT) (test DTB for a733-display-open)"
	@echo "clean     remove built DTBs"
	@echo "mrproper  same as clean"

.PHONY: all open-display help clean mrproper
