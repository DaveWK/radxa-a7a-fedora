// SPDX-License-Identifier: GPL-2.0-only
/*
 * Command-stream capture for vipcore, the VIPLite kernel driver of the
 * A733 NPU. Built only with VIPCORE_CAPTURE=1 (see CAPTURE.md).
 *
 * While armed through debugfs, each task submitted through this driver is
 * recorded into one vmalloc buffer:
 *   - a TASK record (task id, pid, trigger address),
 *   - its command buffers (init, preload, subtasks) as handed to the NPU,
 *   - optionally a snapshot of every video memory block the submitting
 *     process owns, taken just before the trigger (command buffers, NN/TP
 *     instructions, coefficients, inputs), each block once per arming,
 *   - optionally, after the task completed, the NPU-writable blocks again
 *     (outputs and intermediates),
 *   - a DONE record with the completion status.
 * Nothing is decoded here: this is a data capture of what userspace gave
 * this driver. Reading /sys/kernel/debug/vipcore_capture/data returns the
 * stream; the format is in vip_drv_capture_format below and in
 * capture/npu-capture-split.py.
 */
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <vip_drv_capture.h>
#include <vip_drv_task_common.h>
#include <vip_drv_video_memory.h>

#define NPUCAP_VERSION        1
#define NPUCAP_REC_MAGIC      0x31434552u /* "REC1" */
#define NPUCAP_MAX_PENDING    16
#define NPUCAP_MAX_SEEN       2048

enum npucap_type {
    NPUCAP_TASK     = 1,  /* vip_address = trigger address */
    NPUCAP_CMD      = 2,  /* flags = VIPDRV_CAPTURE_CMD_*, sub = index */
    NPUCAP_MEM_PRE  = 3,  /* a video memory block before the trigger */
    NPUCAP_MEM_POST = 4,  /* an NPU-writable block after completion */
    NPUCAP_DONE     = 5,  /* status = the task's completion status */
};

/* rec.flags for MEM records */
#define NPUCAP_F_UNMAPPED     0x0100 /* no kernel mapping: metadata only */
#define NPUCAP_F_TRUNCATED    0x0200 /* buffer full: payload left out */

/* mode bits written to control */
#define NPUCAP_MODE_PRE       0x1
#define NPUCAP_MODE_POST      0x2
#define NPUCAP_MODE_PRE_EVERY 0x4 /* PRE snapshot on every task, not once */

struct npucap_file_header {
    char     magic[8];      /* "A7NPUCAP" */
    u32      version;
    u32      header_size;   /* sizeof(struct npucap_file_header) */
    u32      record_size;   /* sizeof(struct npucap_rec) */
    u32      mode;
    u32      max_tasks;
    u32      reserved;
    u64      arm_time_ns;   /* CLOCK_MONOTONIC */
};

struct npucap_rec {
    u32      magic;
    u16      type;
    u16      flags;
    u32      seq;
    u32      task_id;
    u64      time_ns;       /* CLOCK_MONOTONIC */
    u32      pid;
    u32      sub;           /* CMD: subtask index; MEM: index in the walk */
    u32      subtask_index;
    u32      subtask_count;
    u32      core_index;
    u32      core_cnt;
    u32      mem_id;
    u32      mem_flag;
    u32      allocator_type;
    u32      physical_num;
    s32      status;
    u32      reserved;
    u64      vip_address;   /* NPU virtual address (or physical with NO_MMU_PAGE) */
    u64      physical0;     /* first physical segment */
    u64      size;          /* bytes the record describes */
    u64      payload_size;  /* bytes that follow, padded to 8 in the stream */
    char     name[16];      /* allocator name */
};

static unsigned int capture_buf_mb = 64;
module_param(capture_buf_mb, uint, 0644);
MODULE_PARM_DESC(capture_buf_mb, "capture buffer size in MiB, allocated when armed (VIPCORE_CAPTURE builds)");

static struct {
    struct mutex lock;
    struct dentry *dir;
    u8 *buf;
    size_t size;
    size_t used;
    u32 mode;
    u32 max_tasks;
    u32 tasks;
    u32 seq;
    u32 dropped;
    bool armed;
    struct { u32 task_id; u32 pid; } pending[NPUCAP_MAX_PENDING];
    u32 seen[NPUCAP_MAX_SEEN];
    u32 seen_count;
} npucap;

static void npucap_fill(struct npucap_rec *rec, u16 type, vipdrv_task_t *task, u32 pid)
{
    memset(rec, 0, sizeof(*rec));
    rec->magic = NPUCAP_REC_MAGIC;
    rec->type = type;
    rec->seq = npucap.seq++;
    rec->time_ns = ktime_get_ns();
    rec->pid = pid;
    if (task) {
        rec->task_id = task->task_id;
        rec->subtask_index = task->subtask_index;
        rec->subtask_count = task->subtask_count;
        rec->core_index = task->core_index;
        rec->core_cnt = task->core_cnt;
    }
}

/* Appends a record; src is copied with memcpy_fromio() since some
   allocators map video memory with ioremap(). Caller holds the lock. */
static void npucap_emit(struct npucap_rec *rec, const void *src, u64 payload)
{
    size_t need = sizeof(*rec) + ALIGN(payload, 8);

    if (!npucap.buf)
        return;
    if (npucap.used + need > npucap.size) {
        npucap.dropped++;
        if (npucap.used + sizeof(*rec) > npucap.size)
            return;
        rec->flags |= NPUCAP_F_TRUNCATED;
        payload = 0;
        need = sizeof(*rec);
    }
    rec->payload_size = payload;
    memcpy(npucap.buf + npucap.used, rec, sizeof(*rec));
    if (payload) {
        u8 *dst = npucap.buf + npucap.used + sizeof(*rec);

        memcpy_fromio(dst, (const void __iomem __force *)src, payload);
        memset(dst + payload, 0, ALIGN(payload, 8) - payload);
    }
    npucap.used += need;
}

static int npucap_pending_find(u32 task_id)
{
    int i;

    for (i = 0; i < NPUCAP_MAX_PENDING; i++)
        if (npucap.pending[i].task_id == task_id)
            return i;
    return -1;
}

vip_bool_e vipdrv_capture_task_begin(
    vipdrv_task_t *task,
    vip_uint32_t pid,
    vip_uint32_t trigger_physical
    )
{
    struct npucap_rec rec;
    int slot;

    mutex_lock(&npucap.lock);
    if (!npucap.armed || npucap.tasks >= npucap.max_tasks) {
        mutex_unlock(&npucap.lock);
        return vip_false_e;
    }
    npucap.tasks++;
    slot = npucap_pending_find(0);
    if (slot >= 0) {
        npucap.pending[slot].task_id = task->task_id;
        npucap.pending[slot].pid = pid;
    }
    npucap_fill(&rec, NPUCAP_TASK, task, pid);
    rec.vip_address = trigger_physical;
    npucap_emit(&rec, NULL, 0);
    mutex_unlock(&npucap.lock);

    return vip_true_e;
}

void vipdrv_capture_cmd(
    vipdrv_task_t *task,
    vip_uint32_t kind,
    vip_uint32_t index,
    vip_uint32_t mem_id,
    vip_uint32_t physical,
    const vip_uint8_t *logical,
    vip_uint32_t size
    )
{
    struct npucap_rec rec;

    mutex_lock(&npucap.lock);
    npucap_fill(&rec, NPUCAP_CMD, task, 0);
    rec.flags = kind;
    rec.sub = index;
    rec.mem_id = mem_id;
    rec.vip_address = physical;
    rec.size = size;
    if (!logical)
        rec.flags |= NPUCAP_F_UNMAPPED;
    npucap_emit(&rec, logical, logical ? size : 0);
    mutex_unlock(&npucap.lock);
}

struct npucap_walk {
    vipdrv_task_t *task;
    u32 pid;
    u16 type;
    u32 index;
};

static bool npucap_seen(u32 mem_id)
{
    u32 i;

    for (i = 0; i < npucap.seen_count; i++)
        if (npucap.seen[i] == mem_id)
            return true;
    if (npucap.seen_count < NPUCAP_MAX_SEEN)
        npucap.seen[npucap.seen_count++] = mem_id;
    return false;
}

static void npucap_mem_cb(
    void *arg,
    const vipdrv_mem_capture_info_t *info,
    const vip_uint8_t *logical
    )
{
    struct npucap_walk *walk = arg;
    struct npucap_rec rec;

    if (walk->type == NPUCAP_MEM_PRE && !(npucap.mode & NPUCAP_MODE_PRE_EVERY) &&
        npucap_seen(info->mem_id))
        return;

    npucap_fill(&rec, walk->type, walk->task, walk->pid);
    rec.sub = walk->index++;
    rec.mem_id = info->mem_id;
    rec.mem_flag = info->mem_flag;
    rec.allocator_type = info->allocator_type;
    rec.physical_num = info->physical_num;
    rec.vip_address = info->vip_address;
    rec.physical0 = info->physical0;
    rec.size = info->size;
    if (info->allocator_name)
        strscpy(rec.name, info->allocator_name, sizeof(rec.name));
    if (!logical)
        rec.flags |= NPUCAP_F_UNMAPPED;
    npucap_emit(&rec, logical, logical ? info->size : 0);
}

void vipdrv_capture_task_submitted(
    vipdrv_task_t *task,
    vip_uint32_t pid
    )
{
    struct npucap_walk walk = { .task = task, .pid = pid, .type = NPUCAP_MEM_PRE };

    mutex_lock(&npucap.lock);
    if (npucap.mode & NPUCAP_MODE_PRE)
        vipdrv_mem_capture_walk(pid, 0, VIPDRV_CACHE_CLEAN, npucap_mem_cb, &walk);
    mutex_unlock(&npucap.lock);
}

void vipdrv_capture_task_done(
    vipdrv_task_t *task,
    vip_status_e status
    )
{
    struct npucap_walk walk = { .task = task, .type = NPUCAP_MEM_POST };
    struct npucap_rec rec;
    int slot;

    mutex_lock(&npucap.lock);
    slot = npucap_pending_find(task->task_id);
    if (task->task_id == 0 || slot < 0) {
        mutex_unlock(&npucap.lock);
        return;
    }
    walk.pid = npucap.pending[slot].pid;
    npucap.pending[slot].task_id = 0;
    if ((npucap.mode & NPUCAP_MODE_POST) && status == VIP_SUCCESS)
        vipdrv_mem_capture_walk(walk.pid, VIPDRV_MEM_FLAG_MMU_PAGE_WRITEABLE,
                                VIPDRV_CACHE_INVALID, npucap_mem_cb, &walk);
    npucap_fill(&rec, NPUCAP_DONE, task, walk.pid);
    rec.status = status;
    npucap_emit(&rec, NULL, 0);
    mutex_unlock(&npucap.lock);
}

/* control: "arm [mode [max_tasks]]", "disarm", "free"; read for the state */
static int npucap_arm(u32 mode, u32 max_tasks)
{
    struct npucap_file_header *hdr;
    size_t size = (size_t)capture_buf_mb << 20;

    if (size < sizeof(*hdr) + sizeof(struct npucap_rec))
        return -EINVAL;
    if (npucap.buf && npucap.size != size) {
        vfree(npucap.buf);
        npucap.buf = NULL;
    }
    if (!npucap.buf) {
        npucap.buf = vmalloc(size);
        if (!npucap.buf)
            return -ENOMEM;
        npucap.size = size;
    }
    memset(npucap.pending, 0, sizeof(npucap.pending));
    npucap.seen_count = 0;
    npucap.seq = 0;
    npucap.tasks = 0;
    npucap.dropped = 0;
    npucap.mode = mode;
    npucap.max_tasks = max_tasks;

    hdr = (struct npucap_file_header *)npucap.buf;
    memset(hdr, 0, sizeof(*hdr));
    memcpy(hdr->magic, "A7NPUCAP", 8);
    hdr->version = NPUCAP_VERSION;
    hdr->header_size = sizeof(*hdr);
    hdr->record_size = sizeof(struct npucap_rec);
    hdr->mode = mode;
    hdr->max_tasks = max_tasks;
    hdr->arm_time_ns = ktime_get_ns();
    npucap.used = sizeof(*hdr);
    npucap.armed = true;

    return 0;
}

static ssize_t npucap_control_write(struct file *file, const char __user *ubuf,
                                    size_t count, loff_t *ppos)
{
    char buf[64];
    u32 mode = NPUCAP_MODE_PRE | NPUCAP_MODE_POST, max_tasks = 4;
    int ret = 0;

    if (count >= sizeof(buf))
        return -EINVAL;
    if (copy_from_user(buf, ubuf, count))
        return -EFAULT;
    buf[count] = '\0';
    strim(buf);

    mutex_lock(&npucap.lock);
    if (!strncmp(buf, "arm", 3)) {
        if (buf[3] && sscanf(buf + 3, "%i %u", &mode, &max_tasks) < 1)
            ret = -EINVAL;
        else
            ret = npucap_arm(mode, max_tasks);
    } else if (!strcmp(buf, "disarm")) {
        npucap.armed = false;
    } else if (!strcmp(buf, "free")) {
        npucap.armed = false;
        vfree(npucap.buf);
        npucap.buf = NULL;
        npucap.size = 0;
        npucap.used = 0;
    } else {
        ret = -EINVAL;
    }
    mutex_unlock(&npucap.lock);

    return ret ? ret : count;
}

static ssize_t npucap_control_read(struct file *file, char __user *ubuf,
                                   size_t count, loff_t *ppos)
{
    char buf[256];
    int len;

    mutex_lock(&npucap.lock);
    len = scnprintf(buf, sizeof(buf),
                    "armed %d\nmode 0x%x\nmax_tasks %u\ntasks %u\nrecords %u\n"
                    "used %zu\nsize %zu\ndropped %u\n",
                    npucap.armed, npucap.mode, npucap.max_tasks, npucap.tasks,
                    npucap.seq, npucap.used, npucap.size, npucap.dropped);
    mutex_unlock(&npucap.lock);

    return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static ssize_t npucap_data_read(struct file *file, char __user *ubuf,
                                size_t count, loff_t *ppos)
{
    ssize_t ret;

    mutex_lock(&npucap.lock);
    ret = npucap.buf ? simple_read_from_buffer(ubuf, count, ppos, npucap.buf, npucap.used) : 0;
    mutex_unlock(&npucap.lock);

    return ret;
}

static const struct file_operations npucap_control_fops = {
    .owner = THIS_MODULE,
    .read = npucap_control_read,
    .write = npucap_control_write,
    .llseek = default_llseek,
};

static const struct file_operations npucap_data_fops = {
    .owner = THIS_MODULE,
    .read = npucap_data_read,
    .llseek = default_llseek,
};

int vipdrv_capture_init(void)
{
    BUILD_BUG_ON(sizeof(struct npucap_file_header) != 40);
    BUILD_BUG_ON(sizeof(struct npucap_rec) != 120);

    mutex_init(&npucap.lock);
    npucap.dir = debugfs_create_dir("vipcore_capture", NULL);
    if (IS_ERR(npucap.dir))
        return PTR_ERR(npucap.dir);
    debugfs_create_file("control", 0600, npucap.dir, NULL, &npucap_control_fops);
    debugfs_create_file("data", 0400, npucap.dir, NULL, &npucap_data_fops);
    pr_warn("vipcore: command-stream capture build (VIPCORE_CAPTURE=1), "
            "debugfs vipcore_capture/, disarmed\n");

    return 0;
}

void vipdrv_capture_exit(void)
{
    debugfs_remove_recursive(npucap.dir);
    npucap.dir = NULL;
    mutex_lock(&npucap.lock);
    npucap.armed = false;
    vfree(npucap.buf);
    npucap.buf = NULL;
    mutex_unlock(&npucap.lock);
}
