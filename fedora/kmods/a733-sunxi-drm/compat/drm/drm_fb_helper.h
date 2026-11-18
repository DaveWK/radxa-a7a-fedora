/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Linux 7.4 moved <drm/drm_fb_helper.h> to <drm/clients/drm_fbdev_helper.h>
 * (the fbdev emulation is a DRM client). The module's compat/ directory
 * comes after the kernel's own include directories, so this file is found
 * only where the kernel no longer has the old name.
 */
#ifndef A733_SUNXI_DRM_COMPAT_DRM_FB_HELPER_H
#define A733_SUNXI_DRM_COMPAT_DRM_FB_HELPER_H

#include <drm/clients/drm_fbdev_helper.h>

#endif
