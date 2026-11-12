/****************************************************************************
*
*    The MIT License (MIT)
*
*    Copyright (c) 2017 - 2024 Vivante Corporation
*
*    Permission is hereby granted, free of charge, to any person obtaining a
*    copy of this software and associated documentation files (the "Software"),
*    to deal in the Software without restriction, including without limitation
*    the rights to use, copy, modify, merge, publish, distribute, sublicense,
*    and/or sell copies of the Software, and to permit persons to whom the
*    Software is furnished to do so, subject to the following conditions:
*
*    The above copyright notice and this permission notice shall be included in
*    all copies or substantial portions of the Software.
*
*    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
*    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
*    DEALINGS IN THE SOFTWARE.
*
*****************************************************************************
*
*    The GPL License (GPL)
*
*    Copyright (C) 2017 - 2024 Vivante Corporation
*
*    This program is free software; you can redistribute it and/or
*    modify it under the terms of the GNU General Public License
*    as published by the Free Software Foundation; either version 2
*    of the License, or (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program; if not, write to the Free Software Foundation,
*    Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*
*****************************************************************************
*
*    Note: This software is released under dual MIT and GPL licenses. A
*    recipient may use this file under the terms of either the MIT license or
*    GPL License. If you wish to use only one license not the other, you can
*    indicate your decision by deleting one of the above license notices in your
*    version of this file.
*
*****************************************************************************/

#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/mman.h>
#include <asm/atomic.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/interrupt.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/idr.h>
#include <vip_drv_mem_allocator.h>
#include "vip_drv_mem_allocator_common.h"
#include "vip_drv_device_driver.h"
#include <vip_drv_video_memory.h>
#if defined (USE_LINUX_PCIE_DEVICE)
#include <linux/pci.h>
#endif

#undef VIPDRV_LOG_ZONE
#define VIPDRV_LOG_ZONE  VIPDRV_LOG_ZONE_VIDEO_MEMORY


#if (LINUX_VERSION_CODE > KERNEL_VERSION (4,20,17) && !defined(CONFIG_ARCH_NO_SG_CHAIN)) ||   \
    (LINUX_VERSION_CODE >= KERNEL_VERSION (3,6,0)       \
    && (defined(ARCH_HAS_SG_CHAIN) || defined(CONFIG_ARCH_HAS_SG_CHAIN)))
#define gcdUSE_Linux_SG_TABLE_API   1
#else
#define gcdUSE_Linux_SG_TABLE_API   0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
MODULE_IMPORT_NS("DMA_BUF");
#endif

extern vipdrv_driver_t *kdriver;

#if FLUSH_CACHE_HOOK
#if !gcdUSE_Linux_SG_TABLE_API
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
struct sg_table
{
    struct scatterlist *sgl;
    unsigned int nents;
    unsigned int orig_nents;
};

static inline void sg_set_page(
    struct scatterlist *sg,
    struct page *page,
    unsigned int len,
    unsigned int offset
    )
{
    sg->page = page;
    sg->offset = offset;
    sg->length = len;
}

static inline void sg_mark_end(
    struct scatterlist *sg
    )
{
    (void)sg;
}
#endif

static vip_int32_t vipdrv_sg_alloc_table_from_pages(
    struct scatterlist **sgl,
    struct page **pages,
    unsigned int  n_pages,
    unsigned long offset,
    unsigned long size,
    unsigned int  *nents
    )
{
    unsigned int chunks = 0;
    unsigned int i = 0;
    unsigned int cur_page = 0;
    struct scatterlist *s = VIP_NULL;

    chunks = 1;
    PRINTK_D("start do vsi sg alloc table from pages.\n");

    for (i = 1; i < n_pages; ++i) {
        if (page_to_pfn(pages[i]) != page_to_pfn(pages[i - 1]) + 1) {
            ++chunks;
        }
    }

    vipdrv_os_allocate_memory(sizeof(struct scatterlist) * chunks, (void**)&s);
    if (unlikely(!s)) {
        PRINTK_E("fail to allocate memory in table_from_pages\n");
        return -ENOMEM;
    }
    vipdrv_os_zero_memory(s, sizeof(struct scatterlist) * chunks);

    *sgl = s;
    *nents = chunks;
    cur_page = 0;

    for (i = 0; i < chunks; i++, s++) {
        unsigned long chunk_size = 0;
        unsigned int j = 0;

        for (j = cur_page + 1; j < n_pages; j++) {
            if (page_to_pfn(pages[j]) != page_to_pfn(pages[j - 1]) + 1) {
                break;
            }
        }

        chunk_size = ((j - cur_page) << PAGE_SHIFT) - offset;
        sg_set_page(s, pages[cur_page], min(size, chunk_size), offset);
        size -= chunk_size;
        offset = 0;
        cur_page = j;
    }

    sg_mark_end(s - 1);

    return 0;
}
#endif
#endif

#if FLUSH_CACHE_HOOK
/*
 * The page-list flush handle. sgt stays the first member: the handle is
 * still a struct sg_table * to code that only frees it.
 */
typedef struct _vipdrv_flush_pages {
    struct sg_table sgt;
    /*
     * DMA_TO_DEVICE when the NPU only reads the pages: they may be page
     * cache the process may not write, so the CPU cache is never
     * invalidated (that would discard other writers' dirty lines).
     */
    enum dma_data_direction dir;
} vipdrv_flush_pages_t;

static void vipdrv_free_flush_pages(
    vipdrv_flush_pages_t *flush
    )
{
#if gcdUSE_Linux_SG_TABLE_API
    sg_free_table(&flush->sgt);
#else
    if (VIP_NULL != flush->sgt.sgl) {
        vipdrv_os_free_memory((void*)flush->sgt.sgl);
    }
#endif
    vipdrv_os_free_memory((void*)flush);
}
#endif

vip_status_e flush_cache_init_pages(
    void **flush_handle,
    struct page **pages,
    vip_uint32_t page_count,
    vip_uint32_t offset,
    vip_size_t size
    )
{
    return flush_cache_init_pages_access(flush_handle, pages, page_count, offset, size,
                                         vip_true_e);
}

vip_status_e flush_cache_init_pages_access(
    void **flush_handle,
    struct page **pages,
    vip_uint32_t page_count,
    vip_uint32_t offset,
    vip_size_t size,
    vip_bool_e npu_writable
    )
{
    vip_status_e status = VIP_SUCCESS;
#if FLUSH_CACHE_HOOK
    vipdrv_flush_pages_t *flush = VIP_NULL;
    struct sg_table *sgt = VIP_NULL;
    vip_int32_t result = 0;
    vip_uint32_t flush_size = VIP_ALIGN(size, cache_line_size());

    *flush_handle = VIP_NULL;
    PRINTK_D("flush cache init, size=0x%x, offset=0x%x, device=0x%"PRPx"\n",
             size, offset, kdriver->device);
    if (size & (cache_line_size() - 1)) {
        PRINTK_W("flush cache warning memory size 0x%x not align to cache line size 0x%x\n",
                   size, cache_line_size());
    }

    if (VIP_NULL == kdriver->device) {
        PRINTK_E("fail to flush cache init, device is NULL\n");
        return VIP_ERROR_FAILURE;
    }

    vipdrv_os_allocate_memory(sizeof(vipdrv_flush_pages_t), (void**)&flush);
    if (!flush) {
        PRINTK_E("%s[%d], fail to alloca memory for flush cache handle\n",
                 __FUNCTION__, __LINE__);
        vipGoOnError(VIP_ERROR_IO);
    }
    vipdrv_os_zero_memory(flush, sizeof(vipdrv_flush_pages_t));
    flush->dir = npu_writable ? DMA_BIDIRECTIONAL : DMA_TO_DEVICE;
    sgt = &flush->sgt;

#if gcdUSE_Linux_SG_TABLE_API
    result = sg_alloc_table_from_pages(sgt, pages, page_count, offset,
                                       flush_size, GFP_KERNEL | __GFP_NOWARN);
#else
    result = vipdrv_sg_alloc_table_from_pages(&sgt->sgl, pages, page_count, offset,
                                             flush_size, &sgt->nents);
    sgt->orig_nents = sgt->nents;
#endif
    if (unlikely(result < 0)) {
        PRINTK_E("%s[%d], sg alloc table from pages failed\n", __FUNCTION__, __LINE__);
        /* sg_alloc_table_from_pages() frees what it allocated on failure */
        vipdrv_os_free_memory((void*)flush);
        vipGoOnError(VIP_ERROR_IO);
    }

    result = dma_map_sg(kdriver->device, sgt->sgl, sgt->nents, flush->dir);
    if (unlikely(result != sgt->nents)) {
        PRINTK_E("%s[%d], dma_map_sg failed, result=%d, exp=%d\n",
                  __FUNCTION__, __LINE__, result, sgt->nents);
        vipdrv_free_flush_pages(flush);
        dump_stack();
        vipGoOnError(VIP_ERROR_IO);
    }
    *flush_handle = flush;
    dma_sync_sg_for_device(kdriver->device, sgt->sgl, sgt->nents, DMA_TO_DEVICE);
    if (DMA_TO_DEVICE != flush->dir) {
        dma_sync_sg_for_cpu(kdriver->device, sgt->sgl, sgt->nents, DMA_FROM_DEVICE);
    }

onError:
#endif
    return status;
}

vip_status_e flush_cache_destroy_pages(
    void *flush_handle
    )
{
#if FLUSH_CACHE_HOOK
    vipdrv_flush_pages_t *flush = (vipdrv_flush_pages_t *)flush_handle;

#if DEBUG_ALLOCATOR
    PRINTK_D("flush cache destroy pages..\n");
#endif
    if (flush != VIP_NULL) {
        vipdrv_driver_t *kdriver = vipdrv_get_kdriver();
        struct sg_table *sgt = &flush->sgt;
        dma_sync_sg_for_device(kdriver->device, sgt->sgl, sgt->nents, DMA_TO_DEVICE);
        if (DMA_TO_DEVICE != flush->dir) {
            dma_sync_sg_for_cpu(kdriver->device, sgt->sgl, sgt->nents, DMA_FROM_DEVICE);
        }
        /* the direction it was mapped with (the vendor unmapped FROM_DEVICE) */
        dma_unmap_sg(kdriver->device, sgt->sgl, sgt->nents, flush->dir);

        vipdrv_free_flush_pages(flush);
    }
#endif

    return VIP_SUCCESS;
}

vip_status_e flush_cache_pages(
    void* flush_handle,
    vip_uint8_t type
    )
{
    vip_status_e status = VIP_SUCCESS;
#if FLUSH_CACHE_HOOK
    vipdrv_driver_t *kdriver = vipdrv_get_kdriver();
    vipdrv_flush_pages_t *flush = (vipdrv_flush_pages_t *)flush_handle;
    struct sg_table *sgt = VIP_NULL;
    vip_bool_e invalidate = vip_false_e;
    if (VIP_NULL == flush_handle) {
        PRINTK_E("flush cache continue: handle is null\n");
        return status;
    }
    sgt = &flush->sgt;
    /* the NPU cannot have written a read-only buffer: nothing to invalidate */
    invalidate = (DMA_TO_DEVICE != flush->dir) ? vip_true_e : vip_false_e;

    switch (type) {
        case VIPDRV_CACHE_CLEAN:
            {
                dma_sync_sg_for_device(kdriver->device, sgt->sgl, sgt->nents, DMA_TO_DEVICE);
            }
            break;

        case VIPDRV_CACHE_FLUSH:
            {
                dma_sync_sg_for_device(kdriver->device, sgt->sgl, sgt->nents, DMA_TO_DEVICE);
                if (invalidate) {
                    dma_sync_sg_for_cpu(kdriver->device, sgt->sgl, sgt->nents, DMA_FROM_DEVICE);
                }
            }
            break;

        case VIPDRV_CACHE_INVALID:
            {
                if (invalidate) {
                    dma_sync_sg_for_cpu(kdriver->device, sgt->sgl, sgt->nents, DMA_FROM_DEVICE);
                }
            }
            break;

        default:
            PRINTK_E("not support this flush cache type=%d\n", type);
            break;
    }
#endif
    return status;
}

vip_status_e flush_cache_init_continue(
    void **flush_handle,
    struct page *contiguous_pages,
    vip_uint32_t page_count,
    vip_uint32_t offset
    )
{
    vip_status_e status = VIP_SUCCESS;
#if FLUSH_CACHE_HOOK
    int ret = 0;
    dma_addr_t *dma_addr = VIP_NULL;
    vipdrv_driver_t *kdriver = vipdrv_get_kdriver();

    vipdrv_os_allocate_memory(sizeof(dma_addr_t), (void**)&dma_addr);
    if (VIP_NULL == dma_addr) {
        PRINTK_E("fail to flush cache for video memory.\n");
        vipGoOnError(VIP_ERROR_FAILURE);
    }

    *flush_handle = (void*)dma_addr;

    *dma_addr = dma_map_page(kdriver->device, contiguous_pages, offset,
                             page_count * PAGE_SIZE, DMA_BIDIRECTIONAL);
    ret = dma_mapping_error(kdriver->device, *dma_addr);
    if (ret != 0) {
        PRINTK_E("dma map page failed.\n");
        vipGoOnError(VIP_ERROR_FAILURE);
    }

    flush_cache_continue(dma_addr, page_count * PAGE_SIZE, VIPDRV_CACHE_FLUSH);

onError:
#endif
    return status;
}

vip_status_e flush_cache_destroy_continue(
    void* flush_handle,
    vip_uint32_t page_count
    )
{
#if FLUSH_CACHE_HOOK
    if (VIP_NULL != flush_handle) {
        dma_addr_t *dma_addr = (dma_addr_t*)flush_handle;
        vipdrv_driver_t *kdriver = vipdrv_get_kdriver();
        dma_unmap_page(kdriver->device, *dma_addr, page_count * PAGE_SIZE, DMA_BIDIRECTIONAL);
        vipdrv_os_free_memory((void*)flush_handle);
    }
#endif
    return VIP_SUCCESS;
}

vip_status_e flush_cache_continue(
    void* flush_handle,
    vip_size_t size,
    vip_uint8_t type
    )
{
    vip_status_e status = VIP_SUCCESS;
#if FLUSH_CACHE_HOOK
    dma_addr_t *dma_addr = (dma_addr_t*)flush_handle;
    vipdrv_driver_t *kdriver = vipdrv_get_kdriver();
    if (VIP_NULL == flush_handle) {
        PRINTK_E("flush cache continue: handle is null\n");
        return status;
    }

    switch (type) {
        case VIPDRV_CACHE_CLEAN:
            {
                dma_sync_single_for_device(kdriver->device, *dma_addr, size, DMA_TO_DEVICE);
            }
            break;
        case VIPDRV_CACHE_FLUSH:
            {
                dma_sync_single_for_device(kdriver->device, *dma_addr, size, DMA_TO_DEVICE);
                dma_sync_single_for_cpu(kdriver->device, *dma_addr, size, DMA_FROM_DEVICE);
            }
            break;
        case VIPDRV_CACHE_INVALID:
            {
                dma_sync_single_for_cpu(kdriver->device, *dma_addr, size, DMA_FROM_DEVICE);
            }
            break;
        default:
            PRINTK_E("not support this flush cache type=%d\n", type);
            break;
    }
#endif
    return status;
}

/*
 * The PFN behind one page of a VM_PFNMAP/VM_IO mapping. The caller holds
 * mmap_lock for read and has checked that addr lies in vma. Returns 0 or a
 * negative errno; *pfn is only written with a value read from the page
 * table.
 */
static int vipdrv_follow_user_pfn(
    struct vm_area_struct *vma,
    unsigned long addr,
    vip_bool_e write,
    unsigned long *pfn
    )
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    /*
     * 6.12 replaced follow_pte()/follow_pfn() with follow_pfnmap_start()/
     * follow_pfnmap_end() (mmap_lock held for read until end()), which also
     * return PMD/PUD-sized PFN mappings. A PTE that is not populated yet
     * (exporters that insert PFNs from their fault handler) or not yet
     * writable is faulted in once, as vfio does; without
     * FAULT_FLAG_ALLOW_RETRY fixup_user_fault() keeps mmap_lock held, so
     * vma stays valid.
     */
    struct follow_pfnmap_args args = { .vma = vma, .address = addr };
    int ret = follow_pfnmap_start(&args);

    if (0 == ret && write && !args.writable) {
        follow_pfnmap_end(&args);
        ret = -EFAULT;
    }
    if (0 != ret) {
        ret = fixup_user_fault(vma->vm_mm, addr, write ? FAULT_FLAG_WRITE : 0, VIP_NULL);
        if (0 != ret) {
            return ret;
        }
        args.vma = vma;
        args.address = addr;
        ret = follow_pfnmap_start(&args);
        if (0 != ret) {
            return ret;
        }
    }

    if (write && !args.writable) {
        ret = -EFAULT;
    }
    else {
        *pfn = args.pfn + ((addr & ~args.addr_mask) >> PAGE_SHIFT);
    }
    follow_pfnmap_end(&args);

    return ret;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
    /* the vendor walk; pte_offset_map_lock() is a module API before 6.5 */
    struct mm_struct *mm = vma->vm_mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    spinlock_t *ptl;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        return -EFAULT;
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION (4,11,0))
    pud = pud_offset((p4d_t*)pgd, addr);
#else
    pud = pud_offset(pgd, addr);
#endif
    if (pud_none(*pud) || pud_bad(*pud)) {
        return -EFAULT;
    }

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        return -EFAULT;
    }

    pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
    if (!pte) {
        return -EFAULT;
    }

    if (!pte_present(*pte)) {
        pte_unmap_unlock(pte, ptl);
        return -EFAULT;
    }

    *pfn = pte_pfn(*pte);
    pte_unmap_unlock(pte, ptl);

    return 0;
#else
    /*
     * 6.6 - 6.11: pte_offset_map_lock() goes through the unexported
     * __pte_offset_map_lock() since 6.5 and follow_pte() is not wired up
     * here. Refuse rather than hand the NPU an unresolved address.
     */
    return -EOPNOTSUPP;
#endif
}

/*
 * Wrap a VM_PFNMAP user mapping (a dma-buf, CMA or device buffer another
 * driver mapped). No page reference is taken: userspace must keep the
 * mapping, and the exporter the memory, until the buffer is unwrapped.
 * npu_writable: every VMA must be VM_WRITE and every PTE writable (faulted
 * in for write if need be), else the wrap fails.
 */
vip_status_e vipdrv_import_pfn_map(
    vipdrv_video_mem_handle_t *handle,
    unsigned long long memory,
    vip_uint32_t page_count,
    vip_size_t size,
    vip_uint32_t offset,
    vip_bool_e npu_writable
    )
{
    vip_status_e status = VIP_SUCCESS;
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma = VIP_NULL;
    unsigned long addr = (unsigned long)memory & PAGE_MASK;
    unsigned long *pfns = VIP_NULL;
    vip_uint32_t i = 0;
    struct page **pages = VIP_NULL;
    vip_bool_e physical_contiguous = vip_true_e;
    vipdrv_allocator_t* allocator = handle->allocator;
    int ret = 0;

    PRINTK_D("map pfn memory address=0x%"PRIx64", size=0x%x, num page=%d\n",
              memory, size, page_count);
    if ((memory & (cache_line_size() - 1)) || (size & (cache_line_size() - 1))) {
        PRINTK_W("warning, memory base address or size not align to cache line size,"
                 "address=0x%"PRIx64", size=0x%x\n", memory, size);
    }

    vipOnError(vipdrv_os_allocate_memory(page_count * sizeof(struct page *), (void**)&pages));
    vipOnError(vipdrv_os_allocate_memory(page_count * sizeof(unsigned long), (void**)&pfns));

    /* resolve every page under one mmap_lock hold, re-checking the VMAs */
    down_read(&current_mm_mmap_sem);
    for (i = 0; i < page_count; i++, addr += PAGE_SIZE) {
        if (VIP_NULL == vma || addr >= vma->vm_end) {
            vma = find_vma(mm, addr);
            if (VIP_NULL == vma || vma->vm_start > addr ||
                !(vma->vm_flags & (VM_IO | VM_PFNMAP))) {
                PRINTK_E("pfn map: no PFN mapping at user address 0x%lx\n", addr);
                status = VIP_ERROR_IO;
                break;
            }
            if (npu_writable && !(vma->vm_flags & VM_WRITE)) {
                PRINTK_E("pfn map: NPU-writable wrap of read-only mapping at 0x%lx\n", addr);
                status = VIP_ERROR_INVALID_ARGUMENTS;
                break;
            }
        }

        ret = vipdrv_follow_user_pfn(vma, addr, npu_writable, &pfns[i]);
        if (0 != ret) {
            PRINTK_E("pfn map: fail to resolve user address 0x%lx, ret=%d\n", addr, ret);
            status = (-EOPNOTSUPP == ret) ? VIP_ERROR_NOT_SUPPORTED : VIP_ERROR_IO;
            break;
        }

        /* the cache maintenance (dma_map_sg) needs a struct page */
        if (!pfn_valid(pfns[i])) {
            PRINTK_E("pfn map: PFN 0x%lx at 0x%lx has no struct page, not supported\n",
                     pfns[i], addr);
            status = VIP_ERROR_NOT_SUPPORTED;
            break;
        }
        pages[i] = pfn_to_page(pfns[i]);
    }
    up_read(&current_mm_mmap_sem);
    if (VIP_SUCCESS != status) {
        goto onError;
    }

    for (i = 1; i < page_count; i++) {
        if (pfns[i] != pfns[i - 1] + 1) {
            physical_contiguous = vip_false_e;
            break;
        }
    }

    if (physical_contiguous) {
        vip_physical_t cpu_physical = page_to_phys(pages[0]) + (vip_physical_t)offset;
        /* all physical memory is contiguous */
        handle->physical_table[0] = allocator->callback.phy_cpu2vip(cpu_physical);
        handle->size_table[0] = page_count * PAGE_SIZE - offset;
        handle->physical_num = 1;
    }
    else {
        for (i = 0; i < page_count; i++) {
            handle->physical_table[i] = allocator->callback.phy_cpu2vip(page_to_phys(pages[i]));
            handle->size_table[i] = PAGE_SIZE;
        }
        handle->physical_table[0] += offset;
        handle->size_table[0] -= offset;
        handle->physical_num = page_count;
    }

    /* flush cache */
    vipOnError(flush_cache_init_pages_access(&handle->flush_handle, pages, page_count, offset, size,
                                             npu_writable));

    handle->alloc_handle = (void*)(pages);

    if (pfns != VIP_NULL) {
        vipdrv_os_free_memory((void*)pfns);
    }

    return status;

onError:
    handle->physical_num = 0;
    if (pfns != VIP_NULL) {
        vipdrv_os_free_memory((void*)pfns);
    }
    if (pages != VIP_NULL) {
        vipdrv_os_free_memory((void*)pages);
        pages = VIP_NULL;
    }

    return status;
}

/* Drop the pins vipdrv_import_page_map() took. */
static void vipdrv_release_user_pages(
    struct page **pages,
    vip_uint32_t count
    )
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 6, 0)
    unpin_user_pages(pages, count);
#else
    vip_uint32_t i = 0;

    for (i = 0; i < count; i++) {
        put_page(pages[i]);
    }
#endif
}

/*
 * Pin a wrapped range of normal user memory. flags carries VM_WRITE when
 * every VMA in the range was writable; the pages are then pinned with
 * FOLL_WRITE (breaking COW now, as the vendor did, so a later CPU write
 * cannot move the page under the NPU). An NPU-writable wrap needs that
 * write pin, which GUP refuses for a VMA that is not VM_WRITE: the NPU
 * is never handed write access the process does not have.
 */
vip_status_e vipdrv_import_page_map(
    vipdrv_video_mem_handle_t *handle,
    unsigned long long memory,
    vip_uint32_t page_count,
    vip_size_t size,
    vip_uint32_t offset,
    unsigned long flags,
    vip_bool_e npu_writable
    )
{
    vip_status_e status = VIP_SUCCESS;
    vipdrv_allocator_t* allocator = handle->allocator;
    struct page **pages = VIP_NULL;
    vip_uint32_t i = 0;
    vip_int32_t result = 0;
    vip_bool_e physical_contiguous = vip_true_e;

    PRINTK_D("map page memory logical=0x%"PRIx64", size=0x%x, num page=%d\n",
              memory, size, page_count);

    if ((memory & (cache_line_size() - 1)) || (size & (cache_line_size() - 1))) {
        PRINTK_W("warning, memory base address or size not align to cache line size, "
                 "address=0x%"PRIx64",size=0x%x, cache line size=%d\n",
                 memory, size, cache_line_size());
    }

    if (npu_writable && !(flags & VM_WRITE)) {
        PRINTK_E("fail to wrap memory, NPU-writable wrap of read-only memory 0x%"PRIx64"\n",
                 memory);
        return VIP_ERROR_INVALID_ARGUMENTS;
    }

    vipOnError(vipdrv_os_allocate_memory(page_count * sizeof(struct page *), (void**)&pages));

    down_read(&current_mm_mmap_sem);

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 6, 0)
    /* the NPU keeps DMAing to the pages until unwrap: FOLL_LONGTERM */
    result = pin_user_pages(memory & PAGE_MASK, page_count, FOLL_LONGTERM |
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
    result = get_user_pages(current, current->mm, memory & PAGE_MASK, page_count,
#else
    result = get_user_pages(memory & PAGE_MASK, page_count,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0) || defined(CONFIG_PPC)
                            ((flags & VM_WRITE) ? FOLL_WRITE : 0),
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 1)
                            (flags & VM_WRITE) ? 1 : 0, 0,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 168)
                            (flags & VM_WRITE) ? FOLL_WRITE : 0,
#else
                            (flags & VM_WRITE) ? 1 : 0, 0,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
                            pages);
#else
                            pages, NULL);
#endif

    up_read(&current_mm_mmap_sem);

    if (result < (vip_int32_t)page_count) {
        /* result may be a negative errno: compare as signed */
        if (result > 0) {
            vipdrv_release_user_pages(pages, (vip_uint32_t)result);
        }
        PRINTK_E("fail to allocator wrap memory.. get page: %d < %d\n",
                  result, page_count);
        vipGoOnError(VIP_ERROR_IO);
    }

    for (i = 1; i < page_count; i++) {
        if (page_to_pfn(pages[i]) != page_to_pfn(pages[i - 1]) + 1) {
            physical_contiguous = vip_false_e;
            break;
        }
    }

    if (physical_contiguous) {
        /* all physical memory is contiguous */
        handle->physical_table[0] = allocator->callback.phy_cpu2vip(page_to_phys(pages[0]) + offset);
        handle->size_table[0] = page_count * PAGE_SIZE - offset;
        handle->physical_num = 1;
    }
    else {
        for (i = 0; i < page_count; i++) {
            handle->physical_table[i] = allocator->callback.phy_cpu2vip(page_to_phys(pages[i]));
            handle->size_table[i] = PAGE_SIZE;
        }
        handle->physical_table[0] += offset;
        handle->size_table[0] -= offset;
        handle->physical_num = page_count;
    }

    /* flush cache */
    status = flush_cache_init_pages_access(&handle->flush_handle, pages, page_count, offset, size,
                                           npu_writable);
    if (VIP_SUCCESS != status) {
        vipdrv_release_user_pages(pages, page_count);
        goto onError;
    }

    handle->alloc_handle = (void*)(pages);

    return status;

onError:
    handle->physical_num = 0;
    if (pages != VIP_NULL) {
        vipdrv_os_free_memory((void*)pages);
        pages = VIP_NULL;
    }

    return status;
}

vip_status_e vipdrv_map_kernel_page(
    size_t page_count,
    struct page **pages,
    void **logical,
    vip_bool_e no_cache
    )
{
    vip_status_e status = VIP_SUCCESS;
    pgprot_t pgprot;
    void *addr = VIP_NULL;
    if (vip_true_e == no_cache) {
        #if USE_MEM_WRITE_COMOBINE
        pgprot = pgprot_writecombine(PAGE_KERNEL);
        #else
        pgprot = pgprot_noncached(PAGE_KERNEL);
        #endif
    }
    else {
        pgprot = PAGE_KERNEL;
    }

    addr = vmap(pages, page_count, 0, pgprot);
    if (addr == NULL) {
        PRINTK_E("fail to vmap physical to kernel space\n");
        vipGoOnError(VIP_ERROR_IO);
    }

    *logical = addr;
onError:
    return status;
}

vip_status_e vipdrv_unmap_kernel_page(
    void *logical
    )
{
    vip_status_e status = VIP_SUCCESS;

    vunmap(logical);

    return status;
}

/*
 * The VMA vm_mmap() returned at user_logical, if it still covers the whole
 * range (another thread may have unmapped it before we took mmap_lock).
 * Caller holds the mmap lock.
 */
static struct vm_area_struct *vipdrv_find_mapped_vma(
    void *user_logical,
    size_t page_count
    )
{
    unsigned long addr = (unsigned long)user_logical;
    struct vm_area_struct *vma = find_vma(current->mm, addr);

    if (VIP_NULL == vma || vma->vm_start > addr ||
        vma->vm_end < addr + page_count * PAGE_SIZE) {
        return VIP_NULL;
    }

    return vma;
}

/* Undo vm_mmap() when setting up the mapping failed; no mmap lock held. */
static void vipdrv_unmap_user_on_error(
    void *user_logical,
    size_t page_count
    )
{
    if (!IS_ERR_OR_NULL(user_logical)) {
        vm_munmap((unsigned long)user_logical, page_count * PAGE_SIZE);
    }
}

vip_status_e vipdrv_map_user(
    size_t page_count,
    struct page **pages,
    void **logical,
    vip_bool_e no_cache
    )
{
    return vipdrv_map_user_access(page_count, pages, logical, no_cache, vip_true_e);
}

/* writable == vip_false_e: a read-only mapping that mprotect() cannot upgrade */
vip_status_e vipdrv_map_user_access(
    size_t page_count,
    struct page **pages,
    void **logical,
    vip_bool_e no_cache,
    vip_bool_e writable
    )
{
    vip_status_e status = VIP_SUCCESS;
    void *user_logical = VIP_NULL;
    struct vm_area_struct *vma = VIP_NULL;
    unsigned long start = 0;
    vip_uint32_t i = 0;

    user_logical = (void*)vm_mmap(NULL,
                        0L,
                        page_count * PAGE_SIZE,
                        writable ? (PROT_READ | PROT_WRITE) : PROT_READ,
                        MAP_SHARED | MAP_NORESERVE,
                        0);
    if (IS_ERR(user_logical)) {
        PRINTK_E("%s[%d], fail to map user logical\n", __FUNCTION__, __LINE__);
        dump_stack();
        *logical = VIP_NULL;
        vipGoOnError(VIP_ERROR_IO);
    }

    /*
     * The VMA is already in the tree (vm_mmap dropped mmap_lock), so changing
     * its flags/page_prot and remapping it needs the mmap write lock: since
     * per-VMA locking, vm_flags_set() asserts it (mmap_assert_write_locked).
     */
    vipdrv_mmap_write_lock(current->mm);
    vma = vipdrv_find_mapped_vma(user_logical, page_count);
    if (VIP_NULL == vma) {
        PRINTK_E("%s[%d], fail to find vma\n", __FUNCTION__, __LINE__);
        dump_stack();
        vipdrv_mmap_write_unlock(current->mm);
        vipGoOnError(VIP_ERROR_IO);
    }

    start = vma->vm_start;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    vm_flags_set(vma, vipdVM_FLAGS);
    if (!writable) {
        vm_flags_clear(vma, VM_MAYWRITE);
    }
#else
    vma->vm_flags |= vipdVM_FLAGS;
    if (!writable) {
        vma->vm_flags &= ~VM_MAYWRITE;
    }
#endif

    if (vip_true_e == no_cache) {
        #if USE_MEM_WRITE_COMOBINE
        vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
        #else
        vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
        #endif
    }

    for (i = 0; i < page_count; i++) {
        unsigned long pfn = page_to_pfn(pages[i]);
        if (remap_pfn_range(vma,
                            start,
                            pfn,
                            PAGE_SIZE,
                            vma->vm_page_prot) < 0) {
            PRINTK_E("%s(%d): remap_pfn_range error\n", __FUNCTION__, __LINE__);
            vipdrv_mmap_write_unlock(current->mm);
            vipGoOnError(VIP_ERROR_IO);
        }
        start += PAGE_SIZE;
    }
    *logical = user_logical;
    vipdrv_mmap_write_unlock(current->mm);
    return status;
onError:
    vipdrv_unmap_user_on_error(user_logical, page_count);
    return status;
}

vip_status_e vipdrv_unmap_user(
    size_t page_count,
    void *logical
    )
{
    vip_status_e status = VIP_SUCCESS;

    if (VIP_NULL != logical) {
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
        if (access_ok(logical, page_count * PAGE_SIZE)) {
        #else
        if (access_ok(VERIFY_WRITE, logical, page_count * PAGE_SIZE)) {
        #endif
            if (vm_munmap((unsigned long)logical, page_count * PAGE_SIZE) < 0) {
                PRINTK_E("fail to vm munmap user space\n");
                status = VIP_ERROR_IO;
            }
        }
        else {
            PRINTK_E("unmap user logical=0x%"PRPx" can not access\n", logical);
        }
    }

    return status;
}

vip_status_e vipdrv_map_user_dma_map(
    vip_uint32_t page_count,
    vip_physical_t cpu_physical,
    vip_uint8_t* kerl_logical,
    vip_size_t size,
    void **logical
    )
{
    void* user_logical = VIP_NULL;
    struct vm_area_struct *vma = VIP_NULL;
    vip_status_e status = VIP_SUCCESS;

    user_logical = (void*)vm_mmap(NULL,
                       0L,
                       page_count * PAGE_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_NORESERVE,
                       0);
    if (IS_ERR(user_logical)) {
        user_logical = VIP_NULL;
        PRINTK_E("fail to map user logical\n");
        vipGoOnError(VIP_ERROR_IO);
    }

    /* vma setup and the mmap below need the mmap write lock, see vipdrv_map_user */
    vipdrv_mmap_write_lock(current->mm);
    vma = vipdrv_find_mapped_vma(user_logical, page_count);
    if (VIP_NULL == vma) {
        vipdrv_mmap_write_unlock(current->mm);
        PRINTK_E("fail to faind vma fo CMA\n");
        dump_stack();
        vipGoOnError(VIP_ERROR_IO);
    }

   /* Make this mapping non-cached. */
#if USE_MEM_WRITE_COMOBINE
    vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
#else
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    vm_flags_set(vma, vipdVM_FLAGS);
#else
    vma->vm_flags |= vipdVM_FLAGS;
#endif

    if (dma_mmap_coherent(kdriver->device, vma, kerl_logical,
                         cpu_physical, PAGE_ALIGN(size))) {
        vipdrv_mmap_write_unlock(current->mm);
        PRINTK_E("CMA mmap user logical failed, vip_physical=0x%x, size=0x%08x\n",
                 cpu_physical, PAGE_ALIGN(size));
        vipGoOnError(VIP_ERROR_IO);
    }
    vipdrv_mmap_write_unlock(current->mm);

    *logical = user_logical;
    return status;
onError:
    vipdrv_unmap_user_on_error(user_logical, page_count);
    return status;
}

vip_status_e vipdrv_map_user_dma_buf(
    vip_uint32_t page_count,
    struct dma_buf *dma_buffer,
    unsigned long pgoff,
    void **logical
    )
{
    void* user_logical = VIP_NULL;
    struct vm_area_struct *vma = VIP_NULL;
    vip_status_e status = VIP_SUCCESS;
    int ret = -1;

    user_logical = (void*)vm_mmap(NULL,
                       0L,
                       page_count * PAGE_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_NORESERVE,
                       0);
    if (IS_ERR(user_logical)) {
        user_logical = VIP_NULL;
        PRINTK_E("fail to map user logical\n");
        vipGoOnError(VIP_ERROR_IO);
    }

    /* vma setup and the mmap below need the mmap write lock, see vipdrv_map_user */
    vipdrv_mmap_write_lock(current->mm);
    vma = vipdrv_find_mapped_vma(user_logical, page_count);
    if (VIP_NULL == vma) {
        vipdrv_mmap_write_unlock(current->mm);
        PRINTK_E("fail to faind vma fo CMA\n");
        dump_stack();
        vipGoOnError(VIP_ERROR_IO);
    }

   /* Make this mapping non-cached. */
#if USE_MEM_WRITE_COMOBINE
    vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
#else
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    vm_flags_set(vma, vipdVM_FLAGS);
#else
    vma->vm_flags |= vipdVM_FLAGS;
#endif

    ret = dma_buf_mmap(dma_buffer, vma, pgoff);
    vipdrv_mmap_write_unlock(current->mm);
    if (ret != 0) {
        PRINTK_E("dma buf mmap user logical fail page_count=%d\n", page_count);
        vipGoOnError(VIP_ERROR_IO);
    }

    *logical = user_logical;
    return status;
onError:
    vipdrv_unmap_user_on_error(user_logical, page_count);
    return status;
}

vip_status_e vipdrv_get_page_count(
    vipdrv_video_mem_handle_t *ptr,
    vip_uint32_t* page_count
    )
{
    vip_status_e status = VIP_SUCCESS;
    vipdrv_allocator_t* allocator = ptr->allocator;
    vip_physical_t physical = 0;
    vip_uint32_t page_offset = 0;
    physical = allocator->callback.phy_vip2cpu(ptr->physical_table[0]);
    page_offset = physical - (physical & PAGE_MASK);

    *page_count = GetPageCount(PAGE_ALIGN(ptr->size + page_offset));

    return status;
}

vip_status_e vipdrv_fill_pages(
    vipdrv_video_mem_handle_t *ptr,
    struct page **pages
    )
{
    vipdrv_allocator_t* allocator = ptr->allocator;
    vip_status_e status = VIP_SUCCESS;
    struct page *page = VIP_NULL;
    unsigned long pfn = 0;
    vip_uint32_t i = 0, j = 0, page_index = 0;
    vip_uint32_t page_offset = 0;
    vip_physical_t physical = 0;
    vip_uint32_t page_count = 0;

    vipdrv_get_page_count(ptr, &page_count);
    for (i = 0; i < ptr->physical_num; i++) {
        if (page_index == page_count) {
            break;
        }
        physical = allocator->callback.phy_vip2cpu(ptr->physical_table[i]);
        page_offset = physical - (physical & PAGE_MASK);
        pfn = __phys_to_pfn(physical);
        page = pfn_to_page(pfn);

        for (j = 0; j < GetPageCount(PAGE_ALIGN(ptr->size_table[i] + page_offset)); j++) {
            if (page_index == page_count) {
                break;
            }
            pages[page_index++] = nth_page(page, j);
        }
    }

    return status;
}

