/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include <hook.h>
#include <syscall.h>
#include <asm/atomic.h>
#include <asm/current.h>
#include "../common/kpm_demo_helpers.h"

///< The name of the module, each KPM must has a unique name.
KPM_MODULE_INFO("kpm-hide-maps", "1.1.1", "GPL v2", "wwb", "Hide instrumentation helper VMAs from /proc/<pid>/maps");

#ifndef __NR_prctl
#define __NR_prctl 167
#endif

#define PR_HIDEMAPS_REGISTER 0x484d0001UL
#define PR_HIDEMAPS_RELEASE  0x484d0002UL

#define HIDEMAPS_F_EXACT 0x1UL

#define HMAP_MAX_RANGES 64
#define HMAP_PAGE_SIZE 4096UL
#define HMAP_PAGE_MASK (~(HMAP_PAGE_SIZE - 1))
#define HMAP_VMA_VM_START_OFFSET 0x00
#define HMAP_VMA_VM_END_OFFSET   0x08
#define HMAP_VMA_VM_MM_OFFSET_DEFAULT 0x40
#define HMAP_VMA_VM_MM_SCAN_MIN  0x10
#define HMAP_VMA_VM_MM_SCAN_MAX  0x100

#define HMAP_EPERM   (-1)
#define HMAP_ENOENT  (-2)
#define HMAP_ENOMEM  (-12)
#define HMAP_EEXIST  (-17)
#define HMAP_EINVAL  (-22)
#define HMAP_ENOSYS  (-38)


typedef struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
} seq_file;

static void *(*vmalloc)(unsigned long size);
static void (*vfree)(void *point);
static void *(*get_task_mm)(void *task);
static void (*mmput)(void *mm);
static void *show_map_vma;
static void *exit_mmap;
static void *dup_mmap;
static int hooked_prctl;
static int hooked_exit_mmap;
static int hooked_dup_mmap;
static int vma_vm_mm_offset = HMAP_VMA_VM_MM_OFFSET_DEFAULT;

struct hidden_map_range {
    int active;
    void *mm;
    unsigned long start;
    unsigned long end;
    unsigned long flags;
};

static struct hidden_map_range hidden_ranges[HMAP_MAX_RANGES];
static atomic_t hidden_ranges_lock = ATOMIC_INIT(0);

static inline void hmap_cpu_relax(void)
{
    asm volatile("yield" ::: "memory");
}

static void hmap_lock(void)
{
    while (atomic_cmpxchg(&hidden_ranges_lock, 0, 1) != 0)
        hmap_cpu_relax();
}

static void hmap_unlock(void)
{
    atomic_set(&hidden_ranges_lock, 0);
}

static unsigned long hmap_align_down(unsigned long value)
{
    return value & HMAP_PAGE_MASK;
}

static unsigned long hmap_align_up(unsigned long value)
{
    return (value + HMAP_PAGE_SIZE - 1) & HMAP_PAGE_MASK;
}

static unsigned long hmap_vma_start(void *vma)
{
    return *(unsigned long *)((char *)vma + HMAP_VMA_VM_START_OFFSET);
}

static unsigned long hmap_vma_end(void *vma)
{
    return *(unsigned long *)((char *)vma + HMAP_VMA_VM_END_OFFSET);
}

static void *hmap_vma_mm(void *vma)
{
    if (!vma || vma_vm_mm_offset < 0)
        return NULL;
    return *(void **)((char *)vma + vma_vm_mm_offset);
}

static int hmap_find_vma_mm_offset(void *vma, void *expected_mm)
{
    int offset;

    if (!vma || !expected_mm)
        return -1;

    for (offset = HMAP_VMA_VM_MM_SCAN_MIN;
         offset <= HMAP_VMA_VM_MM_SCAN_MAX;
         offset += (int)sizeof(void *)) {
        if (*(void **)((char *)vma + offset) == expected_mm)
            return offset;
    }

    return -1;
}

static int hmap_normalize_range(unsigned long start, unsigned long size,
                                unsigned long *out_start,
                                unsigned long *out_end)
{
    unsigned long end;

    if (!start || !size)
        return HMAP_EINVAL;
    if (start + size < start)
        return HMAP_EINVAL;

    end = hmap_align_up(start + size);
    start = hmap_align_down(start);
    if (end <= start)
        return HMAP_EINVAL;

    *out_start = start;
    *out_end = end;
    return 0;
}

static int hmap_register_range(void *mm, unsigned long start,
                               unsigned long size, unsigned long flags)
{
    unsigned long range_start;
    unsigned long range_end;
    int free_slot = -1;
    int i;
    int ret;

    if (!mm)
        return HMAP_EPERM;

    ret = hmap_normalize_range(start, size, &range_start, &range_end);
    if (ret)
        return ret;

    hmap_lock();
    for (i = 0; i < HMAP_MAX_RANGES; i++) {
        struct hidden_map_range *r = &hidden_ranges[i];
        if (!r->active) {
            if (free_slot < 0)
                free_slot = i;
            continue;
        }
        if (r->mm == mm && r->start == range_start && r->end == range_end) {
            r->flags = flags;
            hmap_unlock();
            return 0;
        }
    }

    if (free_slot < 0) {
        hmap_unlock();
        return HMAP_ENOMEM;
    }

    hidden_ranges[free_slot].active = 1;
    hidden_ranges[free_slot].mm = mm;
    hidden_ranges[free_slot].start = range_start;
    hidden_ranges[free_slot].end = range_end;
    hidden_ranges[free_slot].flags = flags;
    hmap_unlock();

    pr_info("kpm-hide-maps: registered range mm=%px %lx-%lx flags=0x%lx\n",
            mm, range_start, range_end, flags);
    return 0;
}

static int hmap_release_range(void *mm, unsigned long start, unsigned long size)
{
    unsigned long range_start = 0;
    unsigned long range_end = 0;
    int release_all = !start && !size;
    int removed = 0;
    int ret;
    int i;

    if (!mm)
        return HMAP_EPERM;

    if (!release_all) {
        ret = hmap_normalize_range(start, size, &range_start, &range_end);
        if (ret)
            return ret;
    }

    hmap_lock();
    for (i = 0; i < HMAP_MAX_RANGES; i++) {
        struct hidden_map_range *r = &hidden_ranges[i];
        if (!r->active || r->mm != mm)
            continue;
        if (!release_all && (r->start != range_start || r->end != range_end))
            continue;
        r->active = 0;
        r->mm = NULL;
        r->start = 0;
        r->end = 0;
        r->flags = 0;
        removed++;
    }
    hmap_unlock();

    return removed > 0 ? 0 : HMAP_ENOENT;
}

static int hmap_clear_mm(void *mm)
{
    int removed = 0;
    int i;

    if (!mm)
        return 0;

    hmap_lock();
    for (i = 0; i < HMAP_MAX_RANGES; i++) {
        struct hidden_map_range *r = &hidden_ranges[i];
        if (!r->active || r->mm != mm)
            continue;
        r->active = 0;
        r->mm = NULL;
        r->start = 0;
        r->end = 0;
        r->flags = 0;
        removed++;
    }
    hmap_unlock();

    return removed;
}

static void hmap_clear_all(void)
{
    int i;

    hmap_lock();
    for (i = 0; i < HMAP_MAX_RANGES; i++) {
        hidden_ranges[i].active = 0;
        hidden_ranges[i].mm = NULL;
        hidden_ranges[i].start = 0;
        hidden_ranges[i].end = 0;
        hidden_ranges[i].flags = 0;
    }
    hmap_unlock();
}

static int hmap_copy_mm_ranges(void *dst_mm, void *src_mm)
{
    struct hidden_map_range copies[HMAP_MAX_RANGES];
    int count = 0;
    int copied = 0;
    int i;
    int j;

    if (!dst_mm || !src_mm || dst_mm == src_mm)
        return 0;

    hmap_lock();
    for (i = 0; i < HMAP_MAX_RANGES && count < HMAP_MAX_RANGES; i++) {
        if (hidden_ranges[i].active && hidden_ranges[i].mm == src_mm)
            copies[count++] = hidden_ranges[i];
    }

    for (i = 0; i < count; i++) {
        int exists = 0;
        int free_slot = -1;
        for (j = 0; j < HMAP_MAX_RANGES; j++) {
            struct hidden_map_range *r = &hidden_ranges[j];
            if (!r->active) {
                if (free_slot < 0)
                    free_slot = j;
                continue;
            }
            if (r->mm == dst_mm && r->start == copies[i].start &&
                r->end == copies[i].end) {
                exists = 1;
                break;
            }
        }
        if (exists || free_slot < 0)
            continue;
        hidden_ranges[free_slot] = copies[i];
        hidden_ranges[free_slot].mm = dst_mm;
        copied++;
    }
    hmap_unlock();

    if (copied > 0)
        pr_info("kpm-hide-maps: propagated %d ranges %px -> %px\n",
                copied, src_mm, dst_mm);
    return copied;
}

static int hmap_vma_matches_registered_range(void *vma)
{
    void *mm = hmap_vma_mm(vma);
    unsigned long start;
    unsigned long end;
    int matched = 0;
    int discovered_offset = -1;
    int old_offset = -1;
    int i;

    if (!vma)
        return 0;

    start = hmap_vma_start(vma);
    end = hmap_vma_end(vma);
    if (!start || end <= start)
        return 0;

    hmap_lock();
    for (i = 0; i < HMAP_MAX_RANGES; i++) {
        struct hidden_map_range *r = &hidden_ranges[i];
        int range_match;

        if (!r->active)
            continue;
        if (r->flags & HIDEMAPS_F_EXACT)
            range_match = start == r->start && end == r->end;
        else
            range_match = start < r->end && end > r->start;

        if (!range_match)
            continue;

        if (mm == r->mm) {
            matched = 1;
            break;
        }

        discovered_offset = hmap_find_vma_mm_offset(vma, r->mm);
        if (discovered_offset >= 0) {
            old_offset = vma_vm_mm_offset;
            vma_vm_mm_offset = discovered_offset;
            matched = 1;
            break;
        }
    }
    hmap_unlock();

    if (matched && discovered_offset >= 0 && old_offset != discovered_offset)
        pr_info("kpm-hide-maps: calibrated vm_area_struct.vm_mm offset 0x%x -> 0x%x\n",
                old_offset, discovered_offset);

    return matched;
}

static const char * const hidden_map_tokens[] = {
    "wwb_",
    "frida-server",
    "frida-helper",
    "frida-agent",
    "frida-gadget",
    "libfrida",
    "re.frida.server",
    "rustfrida",
    "rustFrida",
    "rust_frida",
    "rf_test",
    "linjector",
    "/data/local/tmp/rf",
    "/data/local/tmp/rf_",
    "/data/local/tmp/frida",
    "/memfd:rust",
    "/memfd:frida",
    "[anon:rust",
    "[anon:frida",
    "xposed",
    "Xposed",
    "lsposed",
    "LSPosed",
    "lspd",
    "org.lsposed",
    "liblspd",
    "riru",
    "Riru",
    "edxp",
    "EdXposed",
    "libriru_edxp",
    "lspatch",
    "LSPatch",
    "yukihook",
    "YukiHook",
    "com.highcapable.yukihookapi",
    "anydebug",
    "AnyDebug",
    "com.hhvvg.anydebug",
    NULL,
};

static int line_contains_any(const char *line, const char * const *tokens)
{
    const char * const *p;

    for (p = tokens; *p; p++) {
        if (strstr(line, *p))
            return 1;
    }
    return 0;
}

static int should_hide_maps_line(const char *line)
{
    if (!line)
        return 0;

    if (line_contains_any(line, hidden_map_tokens))
        return 1;

    return 0;
}

void show_map_vma_before(hook_fargs2_t* args, void * udata){
    seq_file* m = (seq_file*) args->arg0;
    args->local.data0 = m ? m->count : 0;
    args->local.data1 = hmap_vma_matches_registered_range((void *)args->arg1);
}

void show_map_vma_after(hook_fargs2_t* args, void * udata){
    seq_file* m = (seq_file*) args->arg0;
    size_t start = (size_t)args->local.data0;
    size_t end;
    size_t len;
    char *line;

    if (!m || !m->buf || !vmalloc || !vfree)
        return;

    end = m->count;
    if (end <= start || end > m->size)
        return;

    if (args->local.data1) {
        m->count = start;
        return;
    }

    len = end - start;
    line = vmalloc(len + 1);
    if (!line)
        return;

    memcpy(line, m->buf + start, len);
    line[len] = '\0';

    if (should_hide_maps_line(line)) {
        m->count = start;
    }

    vfree(line);
}

static void hide_maps_prctl_before(hook_fargs5_t *args, void *udata)
{
    unsigned long option = syscall_argn(args, 0);
    unsigned long pid = syscall_argn(args, 1);
    unsigned long start = syscall_argn(args, 2);
    unsigned long size = syscall_argn(args, 3);
    unsigned long flags = syscall_argn(args, 4);
    void *mm;
    int ret;

    (void)udata;

    if (option != PR_HIDEMAPS_REGISTER && option != PR_HIDEMAPS_RELEASE)
        return;

    if (pid != 0 || !get_task_mm || !mmput) {
        ret = HMAP_ENOSYS;
        goto out;
    }

    mm = get_task_mm(current);
    if (!mm) {
        ret = HMAP_EPERM;
        goto out;
    }

    if (option == PR_HIDEMAPS_REGISTER)
        ret = hmap_register_range(mm, start, size, flags);
    else
        ret = hmap_release_range(mm, start, size);

    mmput(mm);

out:
    args->ret = (u64)(long)ret;
    args->skip_origin = 1;
}

static void hide_maps_exit_mmap_before(hook_fargs1_t *args, void *udata)
{
    void *mm = (void *)args->arg0;
    int removed;

    (void)udata;

    removed = hmap_clear_mm(mm);
    if (removed > 0)
        pr_info("kpm-hide-maps: exit_mmap removed %d ranges for mm=%px\n",
                removed, mm);
}

static void hide_maps_dup_mmap_after(hook_fargs2_t *args, void *udata)
{
    void *child_mm = (void *)args->arg0;
    void *old_mm = (void *)args->arg1;

    (void)udata;
    hmap_copy_mm_ranges(child_mm, old_mm);
}

/**
 * @brief hello world initialization
 * @details 
 * 
 * @param args 
 * @param reserved 
 * @return int 
 */
static long hide_maps_init(const char *args, const char *event, void *__user reserved)
{
    (void)reserved;
    kpm_demo_log_init("kpm-hide-maps", event, args);

    vmalloc = (void *)kallsyms_lookup_name("vmalloc");
    vfree = (void *)kallsyms_lookup_name("vfree");
    get_task_mm = (void *)kallsyms_lookup_name("get_task_mm");
    mmput = (void *)kallsyms_lookup_name("mmput");
    exit_mmap = (void *)kallsyms_lookup_name("exit_mmap");
    dup_mmap = (void *)kallsyms_lookup_name("dup_mmap");
    if (!vmalloc || !vfree) {
        pr_err("kpm-hide-maps: vmalloc/vfree not found: vmalloc=%p vfree=%p\n",
               vmalloc, vfree);
        return -1;
    }
    if (!get_task_mm || !mmput) {
        pr_warn("kpm-hide-maps: range prctl disabled: get_task_mm=%px mmput=%px\n",
                get_task_mm, mmput);
    }

    pr_info("kpm-hide-maps: using vm_area_struct.vm_mm offset=0x%x\n",
            vma_vm_mm_offset);

    show_map_vma = (void *)kallsyms_lookup_name("show_map_vma");
    if (show_map_vma) {
        hook_wrap2(show_map_vma, show_map_vma_before, show_map_vma_after, NULL);
        pr_info("kpm-hide-maps: hooked show_map_vma %p\n", show_map_vma);
    } else {
        pr_err("kpm-hide-maps: show_map_vma not found\n");
        return -1;
    }

    if (get_task_mm && mmput) {
        hook_err_t err = hook_syscalln(__NR_prctl, 5, hide_maps_prctl_before, NULL, NULL);
        if (err == HOOK_NO_ERR) {
            hooked_prctl = 1;
            pr_info("kpm-hide-maps: hooked prctl for range ABI register=0x%lx release=0x%lx\n",
                    PR_HIDEMAPS_REGISTER, PR_HIDEMAPS_RELEASE);
        } else {
            pr_warn("kpm-hide-maps: failed to hook prctl: %d\n", err);
        }
    }

    if (exit_mmap) {
        hook_err_t err = hook_wrap1(exit_mmap, hide_maps_exit_mmap_before, NULL, NULL);
        if (err == HOOK_NO_ERR) {
            hooked_exit_mmap = 1;
            pr_info("kpm-hide-maps: hooked exit_mmap %p for range cleanup\n", exit_mmap);
        } else {
            pr_warn("kpm-hide-maps: failed to hook exit_mmap: %d\n", err);
        }
    } else {
        pr_warn("kpm-hide-maps: exit_mmap not found; stale range cleanup disabled\n");
    }

    if (dup_mmap) {
        hook_err_t err = hook_wrap2(dup_mmap, NULL, hide_maps_dup_mmap_after, NULL);
        if (err == HOOK_NO_ERR) {
            hooked_dup_mmap = 1;
            pr_info("kpm-hide-maps: hooked dup_mmap %p for fork propagation\n", dup_mmap);
        } else {
            pr_warn("kpm-hide-maps: failed to hook dup_mmap: %d\n", err);
        }
    } else {
        pr_warn("kpm-hide-maps: dup_mmap not found; fork propagation disabled\n");
    }
    return 0;
}



static long hide_maps_control0(const char *args, char *__user out_msg, int outlen)
{
    return kpm_demo_echo_control("kpm-hide-maps", args, out_msg, outlen);
}



static long hide_maps_exit(void *__user reserved)
{
    (void)reserved;
    if (hooked_dup_mmap && dup_mmap)
        hook_unwrap(dup_mmap, NULL, hide_maps_dup_mmap_after);
    if (hooked_exit_mmap && exit_mmap)
        hook_unwrap(exit_mmap, hide_maps_exit_mmap_before, NULL);
    if (hooked_prctl)
        unhook_syscalln(__NR_prctl, hide_maps_prctl_before, NULL);
    if (show_map_vma)
        unhook(show_map_vma);
    hmap_clear_all();
    return kpm_demo_log_exit("kpm-hide-maps");
}

KPM_INIT(hide_maps_init);
KPM_CTL0(hide_maps_control0);
KPM_EXIT(hide_maps_exit);
