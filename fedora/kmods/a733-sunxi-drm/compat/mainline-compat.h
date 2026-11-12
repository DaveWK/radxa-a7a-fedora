/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Kernel API drift between the vendor driver's base and the stock kernel,
 * where a rename covers it. Everything else is changed in place in the
 * vendor files and listed in PROVENANCE.
 */
#ifndef A733_SUNXI_DRM_MAINLINE_COMPAT_H
#define A733_SUNXI_DRM_MAINLINE_COMPAT_H

#ifndef __ASSEMBLY__
#include <linux/version.h>
#include <drm/drm_atomic.h>

/* struct drm_atomic_state and its helpers were renamed to drm_atomic_commit */
#define drm_atomic_state		drm_atomic_commit
#define drm_atomic_state_alloc		drm_atomic_commit_alloc
#define drm_atomic_state_clear		drm_atomic_commit_clear
#define drm_atomic_state_get		drm_atomic_commit_get
#define drm_atomic_state_put		drm_atomic_commit_put
#endif

#endif
