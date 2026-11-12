/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Command-stream capture for vipcore (build with VIPCORE_CAPTURE=1).
 * See CAPTURE.md. Nothing here is compiled into the default module.
 */
#ifndef _VIP_DRV_CAPTURE_H_
#define _VIP_DRV_CAPTURE_H_

#ifndef VIPDRV_NPU_CAPTURE
#define VIPDRV_NPU_CAPTURE 0
#endif

#if VIPDRV_NPU_CAPTURE
#include <vip_drv_type.h>
#include <vip_lite_common.h>

/* command buffer kinds, in the CMD record's flags */
#define VIPDRV_CAPTURE_CMD_SUBTASK  0
#define VIPDRV_CAPTURE_CMD_INIT     1
#define VIPDRV_CAPTURE_CMD_PRELOAD  2

int vipdrv_capture_init(void);
void vipdrv_capture_exit(void);

/* vip_true_e when this task is captured; the caller then reports its command
   buffers and calls vipdrv_capture_task_submitted() before the trigger */
vip_bool_e vipdrv_capture_task_begin(
    vipdrv_task_t *task,
    vip_uint32_t pid,
    vip_uint32_t trigger_physical
    );

void vipdrv_capture_cmd(
    vipdrv_task_t *task,
    vip_uint32_t kind,
    vip_uint32_t index,
    vip_uint32_t mem_id,
    vip_uint32_t physical,
    const vip_uint8_t *logical,
    vip_uint32_t size
    );

void vipdrv_capture_task_submitted(
    vipdrv_task_t *task,
    vip_uint32_t pid
    );

void vipdrv_capture_task_done(
    vipdrv_task_t *task,
    vip_status_e status
    );
#endif

#endif
