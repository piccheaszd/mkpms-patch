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
#include "../common/kpm_demo_helpers.h"

///< The name of the module, each KPM must has a unique name.
KPM_MODULE_INFO("kpm-hide-maps", "1.0.1", "GPL v2", "wwb", "Hide wxshadow/rustfrida helper VMAs from /proc/<pid>/maps");


typedef struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
} seq_file;

static void *(*vmalloc)(unsigned long size);
static void (*vfree)(void *point);
static void *show_map_vma;

void show_map_vma_before(hook_fargs2_t* args, void * udata){
    seq_file* m = (seq_file*) args->arg0;
    args->local.data0 = m ? m->count : 0;
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

    len = end - start;
    line = vmalloc(len + 1);
    if (!line)
        return;

    memcpy(line, m->buf + start, len);
    line[len] = '\0';

    if (strstr(line, "wwb_")) {
        m->count = start;
    }

    vfree(line);
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
    if (!vmalloc || !vfree) {
        pr_err("kpm-hide-maps: vmalloc/vfree not found: vmalloc=%p vfree=%p\n",
               vmalloc, vfree);
        return -1;
    }

    show_map_vma = (void *)kallsyms_lookup_name("show_map_vma");
    if (show_map_vma) {
        hook_wrap2(show_map_vma, show_map_vma_before, show_map_vma_after, NULL);
        pr_info("kpm-hide-maps: hooked show_map_vma %p\n", show_map_vma);
    } else {
        pr_err("kpm-hide-maps: show_map_vma not found\n");
        return -1;
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
    if (show_map_vma)
        unhook(show_map_vma);
    return kpm_demo_log_exit("kpm-hide-maps");
}

KPM_INIT(hide_maps_init);
KPM_CTL0(hide_maps_control0);
KPM_EXIT(hide_maps_exit);
