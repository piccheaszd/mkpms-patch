/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Clean-room source reimplementation of the rustFrida Hook.RECOMP KPM ABI.
 *
 * This intentionally implements the local-device core first:
 *   - prctl(PR_RECOMPILE_REGISTER, 0, orig_page, recomp_page, 0)
 *   - prctl(PR_RECOMPILE_RELEASE, 0, orig_page, 0, 0)
 *   - original page UXN, instruction abort redirects PC to recomp page
 *   - signal frame PC is exported as the original page address when possible
 *
 * It is not a line-by-line translation of any release binary.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/mm_types.h>
#include <linux/kallsyms.h>
#include <linux/rculist.h>
#include <linux/err.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include <pgtable.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/atomic.h>
#include <stdbool.h>
#include <stddef.h>
#include "../common/kpm_demo_helpers.h"

struct task_struct_offset {
    int16_t pid_offset;
    int16_t tgid_offset;
    int16_t thread_pid_offset;
    int16_t ptracer_cred_offset;
    int16_t real_cred_offset;
    int16_t cred_offset;
    int16_t comm_offset;
    int16_t fs_offset;
    int16_t files_offset;
    int16_t loginuid_offset;
    int16_t sessionid_offset;
    int16_t seccomp_offset;
    int16_t security_offset;
    int16_t stack_offset;
    int16_t tasks_offset;
    int16_t mm_offset;
    int16_t active_mm_offset;
};

extern struct task_struct_offset task_struct_offset;

#ifndef __NR_prctl
#define __NR_prctl 167
#endif

#define PR_RECOMPILE_REGISTER 0x52430001UL
#define PR_RECOMPILE_RELEASE  0x52430002UL

#define RC_GFP_KERNEL 0xcc0U
#define RC_FORK_FIX_BATCH 64
#define RC_USER_REGSET_PRSTATUS 1U
#define RC_DBG_HOOK_HANDLED 0
#define RC_DBG_HOOK_ERROR 1
#define RC_SIGTRAP 5
#define RC_TRAP_TRACE 2

#ifndef CLONE_VM
#define CLONE_VM 0x00000100UL
#endif

#define RC_EPERM    (-1)
#define RC_ENOENT   (-2)
#define RC_EIO      (-5)
#define RC_ENOMEM   (-12)
#define RC_EFAULT   (-14)
#define RC_EBUSY    (-16)
#define RC_EEXIST   (-17)
#define RC_EINVAL   (-22)
#define RC_ENOSYS   (-38)
#define RC_EOPNOTSUPP (-95)

#define ESR_ELx_EC_SHIFT    26
#define ESR_ELx_EC_MASK     (0x3FUL << ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC(esr)     (((esr) & ESR_ELx_EC_MASK) >> ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC_IABT_LOW 0x20
#define ESR_ELx_EC_IABT_CUR 0x21

#define RC_DESC_TYPE_MASK 0x3UL
#define RC_DESC_TYPE_BLOCK 0x1UL
#define RC_DESC_TYPE_TABLE 0x3UL
#define RC_PTE_OA_MASK 0x0000FFFFFFFFF000UL

KPM_MODULE_INFO("recompile", "1.0.0", "GPL v2", "recompile",
                "Recompile Redirect - Execute recompiled code pages");

struct rc_lookup_data {
    const char *name;
    unsigned long addr;
};

struct rc_mapping {
    struct list_head list;
    int active;
    void *mm;
    unsigned long orig;
    unsigned long recomp;
    u64 orig_pte;
    u64 hidden_pte;
    int stripped;
    int deferred;
    int fork_paused;
};

struct rc_step_hook {
    struct list_head node;
    int (*fn)(struct pt_regs *regs, unsigned int esr);
};

typedef int (*rc_kallsyms_cb3_t)(void *data, const char *name,
                                 unsigned long addr);
typedef int (*rc_kallsyms_cb4_t)(void *data, const char *name,
                                 struct module *mod, unsigned long addr);
typedef int (*rc_kallsyms_each3_t)(rc_kallsyms_cb3_t fn, void *data);
typedef int (*rc_kallsyms_each4_t)(rc_kallsyms_cb4_t fn, void *data);

static void *(*kfunc_find_vma)(void *mm, unsigned long addr);
static void *(*kfunc_get_task_mm)(void *task);
static void (*kfunc_mmput)(void *mm);
static long (*kfunc_copy_from_kernel_nofault)(void *dst, const void *src,
                                              size_t size);
static void (*kfunc_flush_tlb_page)(void *vma, unsigned long uaddr);
static void (*kfunc___flush_tlb_range)(void *vma, unsigned long start,
                                       unsigned long end,
                                       unsigned long stride,
                                       bool last_level, int tlb_level);
static u64 (*kfunc___ptep_modify_prot_start)(void *vma, unsigned long addr,
                                             u64 *ptep);
static void (*kfunc___ptep_modify_prot_commit)(void *vma, unsigned long addr,
                                               u64 *ptep, u64 pte);
static void (*kfunc___split_huge_pmd)(void *vma, void *pmd,
                                      unsigned long address, bool freeze,
                                      void *page);
static void *(*kfunc_kzalloc)(size_t size, unsigned int flags);
static void (*kfunc_kfree)(void *ptr);
static unsigned long (*kfunc___get_free_pages)(unsigned int gfp_mask,
                                               unsigned int order);
static void (*kfunc_free_pages)(unsigned long addr, unsigned int order);
static struct task_struct *(*kfunc_find_task_by_vpid)(pid_t nr);
static void (*kfunc_rcu_read_lock)(void);
static void (*kfunc_rcu_read_unlock)(void);
static void *kfunc_fault_handler;
static void *kfunc_exit_mmap;
static void *kfunc_setup_sigframe;
static void *kfunc_setup_rt_frame;
static void *kfunc_compat_setup_sigframe;
static void *kfunc_compat_setup_rt_frame;
static void *kfunc_compat_setup_frame;
static void *kfunc_do_signal;
static void *kfunc_dup_mmap;
static void *kfunc_copy_process;
static void *kfunc_copy_regset_to_user;
static void *kfunc_regset_get;
static void *kfunc_regset_get_alloc;
static void *kfunc_perf_instruction_pointer;
static void *kfunc_perf_reg_value;
static void *kfunc_perf_callchain_user;
static void *kfunc_perf_bp_event;
static void *kfunc_single_step_handler;
static void *kfunc_do_el0_softstep;
static void (*kfunc_register_user_step_hook)(struct rc_step_hook *hook);
static void (*kfunc_unregister_user_step_hook)(struct rc_step_hook *hook);
static void (*kfunc_user_rewind_single_step)(void *task);
static void (*kfunc_arm64_force_sig_fault)(int signo, int code,
                                           unsigned long far,
                                           const char *str);
static void (*kfunc_raw_spin_lock)(void *lock);
static void (*kfunc_raw_spin_unlock)(void *lock);
static void *kptr_debug_hook_lock;
static s64 *kvar_memstart_addr;
static s64 *kvar_physvirt_offset;

static int rc_user_step_hook_fn(struct pt_regs *regs, unsigned int esr);

static LIST_HEAD(rc_mapping_list);
static int rc_active_mapping_count;
static struct rc_step_hook rc_user_step_hook = {
    .fn = rc_user_step_hook_fn,
};
static atomic_t rc_lock = ATOMIC_INIT(0);
static atomic_t rc_in_flight = ATOMIC_INIT(0);
static int rc_cb_param_style;
static int rc_page_shift = 12;
static int rc_page_stride = 9;
static int rc_page_level = 3;
static unsigned long rc_page_size = 4096;
static unsigned long rc_page_offset_base;
static s64 rc_detected_physvirt_offset;
static int rc_physvirt_offset_valid;
static bool rc_hooked_setup_sigframe;
static bool rc_hooked_setup_rt_frame;
static bool rc_hooked_compat_setup_sigframe;
static bool rc_hooked_compat_setup_rt_frame;
static bool rc_hooked_compat_setup_frame;
static bool rc_hooked_do_signal;
static bool rc_hooked_dup_mmap;
static bool rc_hooked_copy_process;
static bool rc_hooked_copy_regset_to_user;
static bool rc_hooked_regset_get;
static bool rc_hooked_regset_get_alloc;
static bool rc_hooked_perf_instruction_pointer;
static bool rc_hooked_perf_reg_value;
static bool rc_hooked_perf_callchain_user;
static bool rc_hooked_perf_bp_event;
static bool rc_hooked_single_step_handler;
static bool rc_hooked_do_el0_softstep;
static bool rc_user_step_hook_registered;
static bool rc_enable_user_step_api;

static inline void rc_cpu_relax(void)
{
    asm volatile("yield" ::: "memory");
}

static void rc_lock_acquire(void)
{
    while (atomic_cmpxchg(&rc_lock, 0, 1) != 0)
        rc_cpu_relax();
}

static void rc_lock_release(void)
{
    atomic_set(&rc_lock, 0);
}

static inline bool rc_is_kva(unsigned long addr)
{
    return (addr >> 48) == 0xffff;
}

static bool rc_args_enable_user_step(const char *args)
{
    if (!args)
        return false;

    return strstr(args, "user_step=1") ||
           strstr(args, "user_step=true") ||
           strstr(args, "user_step_api=1") ||
           strstr(args, "user_step_api=true");
}

static bool rc_safe_read_u64(unsigned long addr, u64 *out)
{
    if (!rc_is_kva(addr))
        return false;

    if (kfunc_copy_from_kernel_nofault) {
        if (kfunc_copy_from_kernel_nofault(out, (const void *)addr,
                                           sizeof(*out)) != 0)
            return false;
    } else {
        *out = *(u64 *)addr;
    }
    return true;
}

static bool rc_safe_read_u32(unsigned long addr, u32 *out)
{
    if (!rc_is_kva(addr))
        return false;

    if (kfunc_copy_from_kernel_nofault) {
        if (kfunc_copy_from_kernel_nofault(out, (const void *)addr,
                                           sizeof(*out)) != 0)
            return false;
    } else {
        *out = *(u32 *)addr;
    }
    return true;
}

static bool rc_safe_read_ptr(unsigned long addr, void **out)
{
    u64 value;

    if (!rc_safe_read_u64(addr, &value))
        return false;
    *out = (void *)(unsigned long)value;
    return true;
}

static inline unsigned long rc_page_mask(void)
{
    return ~(rc_page_size - 1);
}

static inline unsigned long rc_page_align(unsigned long addr)
{
    return addr & rc_page_mask();
}

static inline unsigned long rc_pte_addr_mask(void)
{
    return RC_PTE_OA_MASK & rc_page_mask();
}

static inline int rc_pmd_shift(void)
{
    return rc_page_shift + rc_page_stride;
}

static inline unsigned long rc_pmd_mask(void)
{
    return ~((1UL << rc_pmd_shift()) - 1);
}

static unsigned long rc_vaddr_to_paddr_at(unsigned long vaddr)
{
    u64 par;

    asm volatile("at s1e1r, %0" : : "r"(vaddr));
    asm volatile("isb");
    asm volatile("mrs %0, par_el1" : "=r"(par));
    if (par & 1)
        return 0;

    return (par & RC_PTE_OA_MASK) | (vaddr & (rc_page_size - 1));
}

static unsigned long rc_phys_to_virt_safe(unsigned long pa)
{
    if (rc_physvirt_offset_valid)
        return pa + rc_detected_physvirt_offset;

    if (kvar_physvirt_offset)
        return pa + *kvar_physvirt_offset;

    if (kvar_memstart_addr && rc_page_offset_base)
        return (pa - *kvar_memstart_addr) + rc_page_offset_base;

    return 0;
}

static void rc_probe_physvirt_translation(void)
{
    unsigned long test_vaddr;
    unsigned long test_paddr;
    unsigned long round_trip;

    if (!kfunc___get_free_pages || !kfunc_free_pages)
        return;

    test_vaddr = kfunc___get_free_pages(0xcc0, 0);
    if (!test_vaddr)
        return;

    test_paddr = rc_vaddr_to_paddr_at(test_vaddr);
    if (test_paddr) {
        rc_detected_physvirt_offset = (s64)test_vaddr - (s64)test_paddr;
        rc_physvirt_offset_valid = 1;
        round_trip = rc_phys_to_virt_safe(test_paddr);
        pr_info("recompile: physvirt_offset=%llx (from AT: kva=%lx pa=%lx match=%d)\n",
                rc_detected_physvirt_offset, test_vaddr, test_paddr,
                round_trip == test_vaddr);
    } else {
        pr_warn("recompile: AT translation failed for kva=%lx\n",
                test_vaddr);
    }

    kfunc_free_pages(test_vaddr, 0);
}

static int rc_lookup_cb_4arg(void *data, const char *name, struct module *mod,
                             unsigned long addr)
{
    struct rc_lookup_data *ld = data;

    (void)mod;
    if (strcmp(name, ld->name) == 0) {
        ld->addr = addr;
        return 1;
    }
    return 0;
}

static int rc_lookup_cb_3arg(void *data, const char *name,
                             unsigned long addr)
{
    struct rc_lookup_data *ld = data;

    if (strcmp(name, ld->name) == 0) {
        ld->addr = addr;
        return 1;
    }
    return 0;
}

static unsigned long rc_lookup_name_with_style(const char *name, int style)
{
    struct rc_lookup_data ld = { .name = name, .addr = 0 };

    if (!kallsyms_on_each_symbol)
        return 0;

    if (style == 3)
        ((rc_kallsyms_each3_t)kallsyms_on_each_symbol)(rc_lookup_cb_3arg,
                                                       &ld);
    else
        ((rc_kallsyms_each4_t)kallsyms_on_each_symbol)(rc_lookup_cb_4arg,
                                                       &ld);

    return ld.addr;
}

static void rc_detect_kallsyms_style(void)
{
    unsigned long addr;

    if (rc_cb_param_style || !kallsyms_on_each_symbol)
        return;

    addr = rc_lookup_name_with_style("_stext", 4);
    if (!rc_is_kva(addr))
        addr = rc_lookup_name_with_style("init_task", 4);
    if (rc_is_kva(addr)) {
        rc_cb_param_style = 4;
        pr_info("recompile: kallsyms_on_each_symbol uses 4-param callback\n");
        return;
    }

    addr = rc_lookup_name_with_style("_stext", 3);
    if (!rc_is_kva(addr))
        addr = rc_lookup_name_with_style("init_task", 3);
    if (rc_is_kva(addr)) {
        rc_cb_param_style = 3;
        pr_info("recompile: kallsyms_on_each_symbol uses 3-param callback\n");
        return;
    }

    pr_warn("recompile: could not detect callback style, using kallsyms_lookup_name\n");
}

static unsigned long rc_lookup_name_safe(const char *name)
{
    rc_detect_kallsyms_style();

    if (rc_cb_param_style)
        return rc_lookup_name_with_style(name, rc_cb_param_style);

    if (kallsyms_lookup_name)
        return kallsyms_lookup_name(name);

    return 0;
}

static void *rc_resolve_required(const char *name)
{
    void *addr = (void *)rc_lookup_name_safe(name);

    if (!addr)
        pr_err("recompile: required symbol not found: %s\n", name);
    return addr;
}

static void rc_probe_page_table_config(void)
{
    u64 tcr_el1;
    u64 t0sz, tg0, va_bits, t1sz, k_va_bits;
    unsigned long stext;
    int levels;

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    t0sz = tcr_el1 & 0x3f;
    tg0 = (tcr_el1 >> 14) & 0x3;

    switch (tg0) {
    case 0:
        rc_page_shift = 12;
        break;
    case 1:
        rc_page_shift = 16;
        break;
    case 2:
        rc_page_shift = 14;
        break;
    default:
        rc_page_shift = 12;
        break;
    }

    rc_page_stride = rc_page_shift - 3;
    rc_page_size = 1UL << rc_page_shift;
    va_bits = 64 - t0sz;
    levels = (int)((va_bits - rc_page_shift + rc_page_stride - 1) /
                   rc_page_stride);
    rc_page_level = levels;

    t1sz = (tcr_el1 >> 16) & 0x3f;
    k_va_bits = 64 - t1sz;
    rc_page_offset_base = ~0UL << (k_va_bits - 1);

    stext = rc_lookup_name_safe("_stext");
    if (stext && rc_is_kva(stext))
        rc_page_offset_base = stext & (~0UL << (k_va_bits - 1));

    pr_info("recompile: page_level=%d va_bits=%llu page_shift=%d PAGE_OFFSET=%lx\n",
            rc_page_level, va_bits, rc_page_shift, rc_page_offset_base);
}

static inline void *rc_mm_pgd(void *mm)
{
    if (!mm || mm_struct_offset.pgd_offset < 0)
        return NULL;
    return *(void **)((char *)mm + mm_struct_offset.pgd_offset);
}

static inline void *rc_task_mm_borrowed(struct task_struct *task)
{
    void *mm = NULL;

    if (!task)
        return NULL;

    if (task_struct_offset.mm_offset >= 0)
        mm = *(void **)((char *)task + task_struct_offset.mm_offset);
    if (!mm && task_struct_offset.active_mm_offset >= 0)
        mm = *(void **)((char *)task + task_struct_offset.active_mm_offset);

    return mm;
}

static inline unsigned long rc_vma_start(void *vma)
{
    return *(unsigned long *)vma;
}

static inline unsigned long rc_vma_end(void *vma)
{
    return *(unsigned long *)((char *)vma + sizeof(unsigned long));
}

static bool rc_vma_covers(void *vma, unsigned long addr)
{
    if (!vma || !rc_is_kva((unsigned long)vma))
        return false;
    return rc_vma_start(vma) <= addr && rc_vma_end(vma) > addr;
}

static u64 *rc_get_user_pmd(void *mm, unsigned long addr)
{
    u64 *table;
    int start_level;
    int level;
    unsigned long idx_mask;

    table = (u64 *)rc_mm_pgd(mm);
    if (!table || !rc_is_kva((unsigned long)table))
        return NULL;

    if (rc_page_level < 2 || rc_page_level > 4)
        return NULL;

    start_level = 4 - rc_page_level;
    idx_mask = (1UL << rc_page_stride) - 1;

    for (level = start_level; level < 2; level++) {
        int shift = rc_page_shift + rc_page_stride * (3 - level);
        unsigned long idx = (addr >> shift) & idx_mask;
        u64 desc;
        unsigned long next_pa;
        unsigned long next_kva;

        if (!rc_safe_read_u64((unsigned long)&table[idx], &desc))
            return NULL;
        if (!(desc & PTE_VALID))
            return NULL;
        if ((desc & RC_DESC_TYPE_MASK) != RC_DESC_TYPE_TABLE)
            return NULL;

        next_pa = desc & rc_pte_addr_mask();
        next_kva = rc_phys_to_virt_safe(next_pa);
        if (!rc_is_kva(next_kva))
            return NULL;
        table = (u64 *)next_kva;
    }

    return &table[(addr >> rc_pmd_shift()) & idx_mask];
}

static int rc_try_split_pmd(void *mm, void *vma, unsigned long addr)
{
    u64 *pmd;
    u64 pmd_val;
    unsigned long block_addr;

    pmd = rc_get_user_pmd(mm, addr);
    if (!pmd)
        return 0;
    if (!rc_safe_read_u64((unsigned long)pmd, &pmd_val) || !pmd_val)
        return 0;

    if ((pmd_val & RC_DESC_TYPE_MASK) != RC_DESC_TYPE_BLOCK)
        return 0;

    if (!vma) {
        pr_err("recompile: addr %lx is PMD block but vma is NULL (cannot split)\n",
               addr);
        return RC_EFAULT;
    }

    if (!kfunc___split_huge_pmd) {
        pr_err("recompile: addr %lx is PMD block but __split_huge_pmd not available\n",
               addr);
        return RC_ENOSYS;
    }

    block_addr = addr & rc_pmd_mask();
    kfunc___split_huge_pmd(vma, pmd, block_addr, false, NULL);

    if (!rc_safe_read_u64((unsigned long)pmd, &pmd_val))
        return RC_EFAULT;
    if ((pmd_val & RC_DESC_TYPE_MASK) == RC_DESC_TYPE_BLOCK) {
        pr_err("recompile: PMD split failed for %lx\n", block_addr);
        return RC_EIO;
    }

    return 0;
}

static u64 *rc_get_user_pte(void *mm, unsigned long addr)
{
    u64 *table;
    int start_level;
    int level;
    unsigned long idx_mask;

    table = (u64 *)rc_mm_pgd(mm);
    if (!table || !rc_is_kva((unsigned long)table))
        return NULL;

    if (rc_page_level < 2 || rc_page_level > 4)
        return NULL;

    start_level = 4 - rc_page_level;
    idx_mask = (1UL << rc_page_stride) - 1;

    for (level = start_level; level < 3; level++) {
        int shift = rc_page_shift + rc_page_stride * (3 - level);
        unsigned long idx = (addr >> shift) & idx_mask;
        u64 desc;
        unsigned long next_pa;
        unsigned long next_kva;

        if (!rc_safe_read_u64((unsigned long)&table[idx], &desc))
            return NULL;
        if (!(desc & PTE_VALID))
            return NULL;
        if ((desc & RC_DESC_TYPE_MASK) == RC_DESC_TYPE_BLOCK) {
            pr_warn("recompile: addr %lx is still a PMD block after split attempt\n",
                    addr);
            return NULL;
        }
        if ((desc & RC_DESC_TYPE_MASK) != RC_DESC_TYPE_TABLE)
            return NULL;

        next_pa = desc & rc_pte_addr_mask();
        next_kva = rc_phys_to_virt_safe(next_pa);
        if (!rc_is_kva(next_kva))
            return NULL;
        table = (u64 *)next_kva;
    }

    return &table[(addr >> rc_page_shift) & idx_mask];
}

static void rc_flush_tlb_page(void *vma, unsigned long uaddr)
{
    if (kfunc_flush_tlb_page && vma) {
        kfunc_flush_tlb_page(vma, uaddr);
    } else if (kfunc___flush_tlb_range && vma) {
        kfunc___flush_tlb_range(vma, uaddr, uaddr + rc_page_size,
                                rc_page_size, true, 3);
    }

    asm volatile("dsb ishst" : : : "memory");
    asm volatile("tlbi vaale1is, %0" : : "r"(uaddr >> 12) : "memory");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static void rc_set_pte(u64 *ptep, u64 pte)
{
    asm volatile("dsb ishst" : : : "memory");
    *(volatile u64 *)ptep = pte;
    asm volatile("dsb ishst" : : : "memory");
}

static void rc_write_user_pte(void *vma, unsigned long addr, u64 *ptep,
                              u64 pte)
{
    if (kfunc___ptep_modify_prot_start &&
        kfunc___ptep_modify_prot_commit && vma) {
        kfunc___ptep_modify_prot_start(vma, addr, ptep);
        kfunc___ptep_modify_prot_commit(vma, addr, ptep, pte);
    } else {
        rc_set_pte(ptep, pte);
    }

    rc_flush_tlb_page(vma, addr);
}

static int rc_try_strip_mapping_locked(struct rc_mapping *m, void *vma)
{
    u64 *ptep;
    u64 old_pte;

    if (!m || !m->active)
        return RC_EINVAL;
    if (m->stripped)
        return 0;

    ptep = rc_get_user_pte(m->mm, m->orig);
    if (!ptep)
        return 1;

    if (!rc_safe_read_u64((unsigned long)ptep, &old_pte))
        return RC_EFAULT;
    if (!(old_pte & PTE_VALID))
        return 1;
    if (old_pte & PTE_CONT) {
        pr_err("recompile: unsupported contiguous PTE format: 0x%llx\n",
               old_pte);
        return RC_EOPNOTSUPP;
    }
    if (old_pte & PTE_UXN) {
        pr_err("recompile: original page already UXN: %lx\n", m->orig);
        return RC_EINVAL;
    }

    m->orig_pte = old_pte;
    m->hidden_pte = old_pte | PTE_UXN;
    rc_write_user_pte(vma, m->orig, ptep, m->hidden_pte);
    m->stripped = 1;
    m->deferred = 0;

    return 0;
}

static struct rc_mapping *rc_alloc_mapping(void)
{
    struct rc_mapping *m;

    if (!kfunc_kzalloc)
        return NULL;

    m = kfunc_kzalloc(sizeof(*m), RC_GFP_KERNEL);
    if (!m)
        return NULL;

    memset(m, 0, sizeof(*m));
    INIT_LIST_HEAD(&m->list);
    return m;
}

static void rc_free_mapping(struct rc_mapping *m)
{
    if (m && kfunc_kfree)
        kfunc_kfree(m);
}

static struct rc_mapping *rc_find_mapping_locked(void *mm, unsigned long orig)
{
    struct list_head *pos;
    struct rc_mapping *m;

    for (pos = rc_mapping_list.next; pos != &rc_mapping_list;
         pos = pos->next) {
        m = list_entry(pos, struct rc_mapping, list);
        if (m->active && m->mm == mm && m->orig == orig)
            return m;
    }
    return NULL;
}

static bool rc_translate_orig_to_recomp(void *mm, unsigned long pc,
                                        unsigned long *out_pc)
{
    unsigned long page = rc_page_align(pc);
    struct rc_mapping *m;

    rc_lock_acquire();
    m = rc_find_mapping_locked(mm, page);
    if (m && m->stripped) {
        *out_pc = m->recomp + (pc - m->orig);
        rc_lock_release();
        return true;
    }
    rc_lock_release();
    return false;
}

static bool rc_has_unstripped_mapping(void *mm, unsigned long pc)
{
    unsigned long page = rc_page_align(pc);
    struct rc_mapping *m;

    rc_lock_acquire();
    m = rc_find_mapping_locked(mm, page);
    if (m && !m->stripped) {
        rc_lock_release();
        return true;
    }
    rc_lock_release();
    return false;
}

static bool rc_translate_recomp_to_orig(void *mm, unsigned long pc,
                                        unsigned long *out_pc)
{
    struct list_head *pos;
    struct rc_mapping *m;

    rc_lock_acquire();
    for (pos = rc_mapping_list.next; pos != &rc_mapping_list;
         pos = pos->next) {
        unsigned long start;
        unsigned long end;

        m = list_entry(pos, struct rc_mapping, list);
        if (!m->active || m->mm != mm)
            continue;

        start = m->recomp;
        end = start + rc_page_size;
        if (pc >= start && pc < end) {
            *out_pc = m->orig + (pc - start);
            rc_lock_release();
            return true;
        }
    }
    rc_lock_release();
    return false;
}

static void rc_detach_mapping_locked(struct rc_mapping *m)
{
    if (!m || !m->active)
        return;

    m->active = 0;
    if (rc_active_mapping_count > 0)
        rc_active_mapping_count--;
    list_del_init(&m->list);
}

static int rc_restore_mapping_locked(struct rc_mapping *m, const char *reason)
{
    u64 *ptep;
    u64 cur;
    void *vma;
    unsigned long orig;
    unsigned long recomp;
    bool restored = false;

    if (!m)
        return RC_EINVAL;

    orig = m->orig;
    recomp = m->recomp;

    if (!m->stripped) {
        pr_info("recompile: [%s] cleaned deferred mapping %lx->%lx\n",
                reason, orig, recomp);
        rc_detach_mapping_locked(m);
        rc_free_mapping(m);
        return 0;
    }

    ptep = rc_get_user_pte(m->mm, m->orig);
    if (ptep && rc_safe_read_u64((unsigned long)ptep, &cur) &&
        ((cur & rc_pte_addr_mask()) == (m->orig_pte & rc_pte_addr_mask()))) {
        vma = kfunc_find_vma ? kfunc_find_vma(m->mm, m->orig) : NULL;
        if (!rc_vma_covers(vma, m->orig))
            vma = NULL;
        rc_write_user_pte(vma, m->orig, ptep, m->orig_pte);
        restored = true;
    }

    pr_info("recompile: [%s] cleaned mapping %lx->%lx%s\n",
            reason, orig, recomp, restored ? "" : " (pte skipped)");
    rc_detach_mapping_locked(m);
    rc_free_mapping(m);
    return restored ? 0 : RC_EFAULT;
}

static int rc_release_mm(void *mm, unsigned long orig, const char *reason)
{
    int ret = RC_ENOENT;
    struct rc_mapping *m;

    rc_lock_acquire();
    if (orig) {
        unsigned long page = rc_page_align(orig);

        m = rc_find_mapping_locked(mm, page);
        if (m)
            ret = rc_restore_mapping_locked(m, reason);
    } else {
        struct list_head *pos;
        struct list_head *next;

        ret = 0;
        for (pos = rc_mapping_list.next; pos != &rc_mapping_list;
             pos = next) {
            next = pos->next;
            m = list_entry(pos, struct rc_mapping, list);
            if (m->active && m->mm == mm)
                rc_restore_mapping_locked(m, reason);
        }
    }
    rc_lock_release();

    return ret;
}

static void *rc_resolve_pid_to_mm(unsigned long pid)
{
    struct task_struct *task;
    void *mm = NULL;

    if (pid == 0)
        return kfunc_get_task_mm(current);

    if (!kfunc_find_task_by_vpid || !kfunc_rcu_read_lock ||
        !kfunc_rcu_read_unlock)
        return NULL;

    kfunc_rcu_read_lock();
    task = kfunc_find_task_by_vpid((pid_t)pid);
    if (task)
        mm = kfunc_get_task_mm(task);
    kfunc_rcu_read_unlock();

    return mm;
}

static int rc_do_register(void *mm, unsigned long orig, unsigned long recomp)
{
    unsigned long orig_page = rc_page_align(orig);
    unsigned long recomp_page = rc_page_align(recomp);
    struct rc_mapping *mapping = NULL;
    u64 *ptep;
    u64 old_pte;
    u64 hidden_pte;
    void *vma;
    bool deferred = false;
    int ret = 0;

    if (!mm || !orig_page || !recomp_page)
        return RC_EINVAL;
    if (orig != orig_page || recomp != recomp_page)
        return RC_EINVAL;

    rc_lock_acquire();
    if (rc_find_mapping_locked(mm, orig_page)) {
        rc_lock_release();
        return RC_EEXIST;
    }
    rc_lock_release();

    vma = kfunc_find_vma ? kfunc_find_vma(mm, orig_page) : NULL;
    if (!rc_vma_covers(vma, orig_page)) {
        pr_err("recompile: no vma for page %lx\n", orig_page);
        return RC_EFAULT;
    }

    ret = rc_try_split_pmd(mm, vma, orig_page);
    if (ret < 0)
        return ret;

    ptep = rc_get_user_pte(mm, orig_page);
    if (!ptep) {
        deferred = true;
        old_pte = 0;
        hidden_pte = 0;
    } else if (!rc_safe_read_u64((unsigned long)ptep, &old_pte)) {
        pr_err("recompile: failed to read PTE for page %lx\n", orig_page);
        return RC_EFAULT;
    } else if (!(old_pte & PTE_VALID)) {
        deferred = true;
        hidden_pte = 0;
    }

    if (!deferred && (old_pte & PTE_CONT)) {
        pr_err("recompile: unsupported contiguous PTE format: 0x%llx\n",
               old_pte);
        return RC_EOPNOTSUPP;
    }

    if (!deferred && (old_pte & PTE_UXN)) {
        pr_err("recompile: original page already UXN: %lx\n", orig_page);
        return RC_EINVAL;
    }

    if (!deferred)
        hidden_pte = old_pte | PTE_UXN;

    mapping = rc_alloc_mapping();
    if (!mapping)
        return RC_ENOMEM;

    rc_lock_acquire();
    if (rc_find_mapping_locked(mm, orig_page)) {
        ret = RC_EEXIST;
        goto out_unlock;
    }

    mapping->active = 1;
    mapping->mm = mm;
    mapping->orig = orig_page;
    mapping->recomp = recomp_page;
    mapping->orig_pte = old_pte;
    mapping->hidden_pte = hidden_pte;
    mapping->stripped = deferred ? 0 : 1;
    mapping->deferred = deferred ? 1 : 0;
    mapping->fork_paused = 0;
    list_add_tail(&mapping->list, &rc_mapping_list);
    rc_active_mapping_count++;

    if (deferred) {
        pr_info("recompile: deferred strip for %lx (PTE absent, will strip on first fault-in)\n",
                orig_page);
    } else {
        rc_write_user_pte(vma, orig_page, ptep, hidden_pte);
    }

    pr_info("recompile: registered mapping: %lx -> %lx (pid mm=%px)\n",
            orig_page, recomp_page, mm);
    mapping = NULL;

out_unlock:
    rc_lock_release();
    if (mapping)
        rc_free_mapping(mapping);
    return ret;
}

static void recompile_prctl_before(hook_fargs5_t *args, void *udata)
{
    unsigned long option = syscall_argn(args, 0);
    unsigned long pid = syscall_argn(args, 1);
    unsigned long orig = syscall_argn(args, 2);
    unsigned long recomp = syscall_argn(args, 3);
    void *mm = NULL;
    int ret;

    (void)udata;

    if (option != PR_RECOMPILE_REGISTER && option != PR_RECOMPILE_RELEASE)
        return;

    mm = rc_resolve_pid_to_mm(pid);
    if (!mm) {
        ret = RC_EPERM;
        goto out;
    }

    if (option == PR_RECOMPILE_REGISTER)
        ret = rc_do_register(mm, orig, recomp);
    else
        ret = rc_release_mm(mm, orig, "release");

    kfunc_mmput(mm);

out:
    args->ret = (u64)(long)ret;
    args->skip_origin = 1;
}

static void recompile_fault_before(hook_fargs3_t *args, void *udata)
{
    unsigned long far = (unsigned long)args->arg0;
    unsigned long esr = (unsigned long)args->arg1;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    unsigned long fault_pc;
    unsigned long new_pc;
    void *mm;
    unsigned int ec;

    (void)udata;
    atomic_inc(&rc_in_flight);
    args->local.data0 = 0;

    if (!regs || !user_mode(regs))
        goto out;

    ec = ESR_ELx_EC(esr);
    if (ec != ESR_ELx_EC_IABT_LOW && ec != ESR_ELx_EC_IABT_CUR)
        goto out;

    fault_pc = far ? far : regs->pc;
    mm = kfunc_get_task_mm(current);
    if (!mm)
        goto out;

    if (rc_translate_orig_to_recomp(mm, fault_pc, &new_pc)) {
        regs->pc = new_pc;
        args->ret = 0;
        args->skip_origin = 1;
    } else if (rc_has_unstripped_mapping(mm, fault_pc)) {
        args->local.data0 = 1;
        args->local.data1 = (u64)(unsigned long)regs;
        args->local.data2 = fault_pc;
    }

    kfunc_mmput(mm);

out:
    atomic_dec(&rc_in_flight);
}

static void recompile_fault_after(hook_fargs3_t *args, void *udata)
{
    struct pt_regs *regs;
    unsigned long fault_pc;
    unsigned long page;
    void *mm;
    void *vma;
    struct rc_mapping *m;
    int ret;

    (void)udata;
    atomic_inc(&rc_in_flight);

    if (!args->local.data0)
        goto out;

    regs = (struct pt_regs *)(unsigned long)args->local.data1;
    fault_pc = (unsigned long)args->local.data2;
    if (!regs || !user_mode(regs) || (long)args->ret != 0)
        goto out;

    mm = kfunc_get_task_mm(current);
    if (!mm)
        goto out;

    page = rc_page_align(fault_pc);
    vma = kfunc_find_vma ? kfunc_find_vma(mm, page) : NULL;
    if (!rc_vma_covers(vma, page))
        vma = NULL;

    rc_lock_acquire();
    m = rc_find_mapping_locked(mm, page);
    if (m && !m->stripped) {
        ret = rc_try_strip_mapping_locked(m, vma);
        if (ret == 0) {
            regs->pc = m->recomp + (fault_pc - page);
        } else if (ret < 0) {
            pr_warn("recompile: deferred strip failed for %lx: %d\n",
                    page, ret);
        }
    }
    rc_lock_release();

    kfunc_mmput(mm);

out:
    atomic_dec(&rc_in_flight);
}

static void rc_sanitize_regs_pc_for_mm(void *mm, hook_local_t *local,
                                       struct pt_regs *regs)
{
    unsigned long orig_pc;

    if (!local)
        return;

    local->data0 = 0;
    if (!regs || !user_mode(regs))
        return;

    if (!mm)
        return;

    if (rc_translate_recomp_to_orig(mm, regs->pc, &orig_pc)) {
        local->data0 = 1;
        local->data1 = regs->pc;
        local->data2 = (u64)(unsigned long)regs;
        local->data3 = orig_pc;
        regs->pc = orig_pc;
    }
}

static void rc_sanitize_regs_pc_shared(hook_local_t *local,
                                       struct pt_regs *regs)
{
    void *mm;

    mm = kfunc_get_task_mm(current);
    if (!mm) {
        if (local)
            local->data0 = 0;
        return;
    }

    rc_sanitize_regs_pc_for_mm(mm, local, regs);
    kfunc_mmput(mm);
}

static void rc_restore_sanitized_pc_shared(hook_local_t *local)
{
    struct pt_regs *regs;

    if (!local || !local->data0)
        return;

    regs = (struct pt_regs *)(unsigned long)local->data2;
    if (regs && regs->pc == local->data3)
        regs->pc = local->data1;
}

static void rc_sanitize_task_pc_shared(hook_local_t *local,
                                       struct task_struct *task)
{
    struct pt_regs *regs;
    void *mm;

    if (!local)
        return;

    local->data0 = 0;
    if (!task)
        return;

    regs = _task_pt_reg(task);
    if (!regs || !user_mode(regs))
        return;

    mm = rc_task_mm_borrowed(task);
    if (!mm)
        return;

    rc_sanitize_regs_pc_for_mm(mm, local, regs);
}

static int rc_user_step_hook_fn(struct pt_regs *regs, unsigned int esr)
{
    hook_local_t local;
    void *mm;

    (void)esr;

    if (!regs || !user_mode(regs))
        return RC_DBG_HOOK_ERROR;
    if (!rc_active_mapping_count)
        return RC_DBG_HOOK_ERROR;

    atomic_inc(&rc_in_flight);
    memset(&local, 0, sizeof(local));

    mm = rc_task_mm_borrowed(current);
    rc_sanitize_regs_pc_for_mm(mm, &local, regs);
    if (!local.data0) {
        atomic_dec(&rc_in_flight);
        return RC_DBG_HOOK_ERROR;
    }

    if (kfunc_arm64_force_sig_fault)
        kfunc_arm64_force_sig_fault(RC_SIGTRAP, RC_TRAP_TRACE, regs->pc,
                                    "recompile");
    if (kfunc_user_rewind_single_step)
        kfunc_user_rewind_single_step(current);

    rc_restore_sanitized_pc_shared(&local);
    atomic_dec(&rc_in_flight);
    return RC_DBG_HOOK_HANDLED;
}

static bool rc_regset_is_prstatus(void *regset)
{
    u32 core_note_type;

    if (!regset || !rc_is_kva((unsigned long)regset))
        return false;
    if (!rc_safe_read_u32((unsigned long)regset + 48, &core_note_type))
        return false;

    return core_note_type == RC_USER_REGSET_PRSTATUS;
}

static void recompile_copy_regset_to_user_before(hook_fargs6_t *args,
                                                 void *udata)
{
    struct task_struct *task = (struct task_struct *)args->arg0;
    void *view = (void *)args->arg1;
    unsigned int setno = (unsigned int)args->arg2;
    void *regsets;
    u32 nsets;
    void *regset;

    (void)udata;
    atomic_inc(&rc_in_flight);
    args->local.data0 = 0;

    if (!view || !rc_is_kva((unsigned long)view))
        goto out;
    if (!rc_safe_read_ptr((unsigned long)view + 8, &regsets) || !regsets)
        goto out;
    if (!rc_safe_read_u32((unsigned long)view + 16, &nsets) || setno >= nsets)
        goto out;

    regset = (char *)regsets + (setno * 64UL);
    if (rc_regset_is_prstatus(regset))
        rc_sanitize_task_pc_shared(&args->local, task);

out:
    atomic_dec(&rc_in_flight);
}

static void recompile_copy_regset_to_user_after(hook_fargs6_t *args,
                                                void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);
    rc_restore_sanitized_pc_shared(&args->local);
    atomic_dec(&rc_in_flight);
}

static void recompile_regset_get_before(hook_fargs5_t *args, void *udata)
{
    struct task_struct *task = (struct task_struct *)args->arg0;
    void *regset = (void *)args->arg1;

    (void)udata;
    atomic_inc(&rc_in_flight);
    args->local.data0 = 0;

    if (rc_regset_is_prstatus(regset))
        rc_sanitize_task_pc_shared(&args->local, task);

    atomic_dec(&rc_in_flight);
}

static void recompile_regset_get_after(hook_fargs5_t *args, void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);
    rc_restore_sanitized_pc_shared(&args->local);
    atomic_dec(&rc_in_flight);
}

static void recompile_setup_frame_before(hook_fargs4_t *args, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)args->arg3;

    (void)udata;
    atomic_inc(&rc_in_flight);

    rc_sanitize_regs_pc_shared(&args->local, regs);

    atomic_dec(&rc_in_flight);
}

static void recompile_setup_frame_after(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);

    rc_restore_sanitized_pc_shared(&args->local);

    atomic_dec(&rc_in_flight);
}

static void recompile_regs_arg0_before(hook_fargs1_t *args, void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);
    rc_sanitize_regs_pc_shared(&args->local,
                               (struct pt_regs *)(unsigned long)args->arg0);
    atomic_dec(&rc_in_flight);
}

static void recompile_regs_arg0_after(hook_fargs1_t *args, void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);
    rc_restore_sanitized_pc_shared(&args->local);
    atomic_dec(&rc_in_flight);
}

static void recompile_regs2_arg0_before(hook_fargs2_t *args, void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);
    rc_sanitize_regs_pc_shared(&args->local,
                               (struct pt_regs *)(unsigned long)args->arg0);
    atomic_dec(&rc_in_flight);
}

static void recompile_regs2_arg0_after(hook_fargs2_t *args, void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);
    rc_restore_sanitized_pc_shared(&args->local);
    atomic_dec(&rc_in_flight);
}

static void recompile_perf_reg_value_before(hook_fargs2_t *args, void *udata)
{
    unsigned long idx = (unsigned long)args->arg1;

    (void)udata;
    atomic_inc(&rc_in_flight);
    args->local.data0 = 0;

    if (idx == 0x20 || idx == 0x0f)
        rc_sanitize_regs_pc_shared(&args->local,
                                   (struct pt_regs *)(unsigned long)args->arg0);

    atomic_dec(&rc_in_flight);
}

static void recompile_perf_reg_value_after(hook_fargs2_t *args, void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);
    rc_restore_sanitized_pc_shared(&args->local);
    atomic_dec(&rc_in_flight);
}

static void recompile_regs2_arg1_before(hook_fargs2_t *args, void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);
    rc_sanitize_regs_pc_shared(&args->local,
                               (struct pt_regs *)(unsigned long)args->arg1);
    atomic_dec(&rc_in_flight);
}

static void recompile_regs3_arg2_before(hook_fargs3_t *args, void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);
    rc_sanitize_regs_pc_shared(&args->local,
                               (struct pt_regs *)(unsigned long)args->arg2);
    atomic_dec(&rc_in_flight);
}

static void recompile_regs3_arg2_after(hook_fargs3_t *args, void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);
    rc_restore_sanitized_pc_shared(&args->local);
    atomic_dec(&rc_in_flight);
}

static void recompile_regs2_arg1_after(hook_fargs2_t *args, void *udata)
{
    (void)udata;
    atomic_inc(&rc_in_flight);
    rc_restore_sanitized_pc_shared(&args->local);
    atomic_dec(&rc_in_flight);
}

static int rc_pause_mm_for_fork(void *mm)
{
    struct list_head *pos;
    int changed = 0;

    rc_lock_acquire();
    for (pos = rc_mapping_list.next; pos != &rc_mapping_list;
         pos = pos->next) {
        struct rc_mapping *m = list_entry(pos, struct rc_mapping, list);
        u64 *ptep;
        u64 cur;
        void *vma;

        if (!m->active || m->mm != mm || m->fork_paused || !m->stripped)
            continue;

        ptep = rc_get_user_pte(mm, m->orig);
        if (!ptep || !rc_safe_read_u64((unsigned long)ptep, &cur))
            continue;
        if ((cur & rc_pte_addr_mask()) !=
            (m->orig_pte & rc_pte_addr_mask()))
            continue;
        if (!(cur & PTE_UXN))
            continue;

        vma = kfunc_find_vma ? kfunc_find_vma(mm, m->orig) : NULL;
        if (!rc_vma_covers(vma, m->orig))
            vma = NULL;

        rc_write_user_pte(vma, m->orig, ptep, m->orig_pte);
        m->fork_paused = 1;
        changed++;
    }
    rc_lock_release();

    return changed;
}

static int rc_resume_mm_after_fork(void *mm)
{
    struct list_head *pos;
    int changed = 0;

    rc_lock_acquire();
    for (pos = rc_mapping_list.next; pos != &rc_mapping_list;
         pos = pos->next) {
        struct rc_mapping *m = list_entry(pos, struct rc_mapping, list);
        u64 *ptep;
        u64 cur;
        void *vma;

        if (!m->active || m->mm != mm || !m->fork_paused || !m->stripped)
            continue;

        ptep = rc_get_user_pte(mm, m->orig);
        if (!ptep || !rc_safe_read_u64((unsigned long)ptep, &cur)) {
            m->fork_paused = 0;
            continue;
        }
        if ((cur & rc_pte_addr_mask()) !=
            (m->orig_pte & rc_pte_addr_mask())) {
            m->fork_paused = 0;
            continue;
        }

        vma = kfunc_find_vma ? kfunc_find_vma(mm, m->orig) : NULL;
        if (!rc_vma_covers(vma, m->orig))
            vma = NULL;

        rc_write_user_pte(vma, m->orig, ptep, m->hidden_pte);
        m->fork_paused = 0;
        changed++;
    }
    rc_lock_release();

    return changed;
}

static int rc_fix_child_ptes(void *child_mm, void *parent_mm)
{
    unsigned long pages[RC_FORK_FIX_BATCH];
    u64 parent_ptes[RC_FORK_FIX_BATCH];
    int count = 0;
    int fixed = 0;
    int i;
    struct list_head *pos;

    if (!child_mm || !parent_mm || child_mm == parent_mm)
        return 0;

    rc_lock_acquire();
    for (pos = rc_mapping_list.next; pos != &rc_mapping_list;
         pos = pos->next) {
        struct rc_mapping *m = list_entry(pos, struct rc_mapping, list);

        if (!m->active || m->mm != parent_mm || !m->stripped)
            continue;
        if (count >= RC_FORK_FIX_BATCH)
            break;

        pages[count] = m->orig;
        parent_ptes[count] = m->orig_pte;
        count++;
    }
    rc_lock_release();

    if (!count)
        return 0;

    for (i = 0; i < count; i++) {
        u64 *ptep;
        u64 cur;

        ptep = rc_get_user_pte(child_mm, pages[i]);
        if (!ptep || !rc_safe_read_u64((unsigned long)ptep, &cur))
            continue;
        if (!(cur & PTE_VALID) || !(cur & PTE_UXN))
            continue;
        if ((cur & rc_pte_addr_mask()) !=
            (parent_ptes[i] & rc_pte_addr_mask()))
            continue;

        rc_set_pte(ptep, cur & ~PTE_UXN);
        fixed++;
    }

    if (fixed > 0)
        flush_tlb_all();
    if (count == RC_FORK_FIX_BATCH)
        pr_warn("recompile: [fork-fix-child] too many pages, truncating at %d\n",
                RC_FORK_FIX_BATCH);
    if (fixed > 0)
        pr_info("recompile: [fork-fix-child] child_mm=%px parent_mm=%px pages=%d\n",
                child_mm, parent_mm, fixed);

    return fixed;
}

static void before_dup_mmap_rc(hook_fargs2_t *args, void *udata)
{
    void *oldmm = (void *)args->arg1;
    int changed = 0;

    (void)udata;
    atomic_inc(&rc_in_flight);
    args->local.data0 = 0;

    if (oldmm) {
        changed = rc_pause_mm_for_fork(oldmm);
        args->local.data0 = (changed > 0);
        args->local.data1 = (u64)(unsigned long)oldmm;
    }

    atomic_dec(&rc_in_flight);
}

static void after_dup_mmap_rc(hook_fargs2_t *args, void *udata)
{
    void *child_mm = (void *)args->arg0;
    void *oldmm = (void *)(unsigned long)args->local.data1;

    (void)udata;
    atomic_inc(&rc_in_flight);

    if (args->local.data0 && oldmm)
        rc_resume_mm_after_fork(oldmm);
    if (oldmm && child_mm)
        rc_fix_child_ptes(child_mm, oldmm);

    atomic_dec(&rc_in_flight);
}

static void before_copy_process_rc(hook_fargs8_t *args, void *udata)
{
    unsigned long clone_flags = (unsigned long)args->arg0;
    void *mm;
    int changed;

    (void)udata;
    atomic_inc(&rc_in_flight);
    args->local.data0 = 0;

    if (clone_flags & CLONE_VM)
        goto out;

    mm = kfunc_get_task_mm(current);
    if (!mm)
        goto out;

    changed = rc_pause_mm_for_fork(mm);
    if (changed > 0) {
        args->local.data0 = 1;
        args->local.data1 = (u64)(unsigned long)mm;
    } else {
        kfunc_mmput(mm);
    }

out:
    atomic_dec(&rc_in_flight);
}

static void after_copy_process_rc(hook_fargs8_t *args, void *udata)
{
    void *mm = (void *)(unsigned long)args->local.data1;

    (void)udata;
    atomic_inc(&rc_in_flight);

    if (args->local.data0 && mm) {
        struct task_struct *child = (struct task_struct *)(unsigned long)args->ret;
        void *child_mm = NULL;

        if (!IS_ERR(child))
            child_mm = rc_task_mm_borrowed(child);
        if (child_mm && child_mm != mm)
            rc_fix_child_ptes(child_mm, mm);
        rc_resume_mm_after_fork(mm);
        kfunc_mmput(mm);
    }

    atomic_dec(&rc_in_flight);
}

static void recompile_exit_mmap_before(hook_fargs1_t *args, void *udata)
{
    void *mm = (void *)args->arg0;
    struct list_head *pos;
    struct list_head *next;
    int cleaned = 0;

    (void)udata;
    atomic_inc(&rc_in_flight);

    if (!mm)
        goto out;

    rc_lock_acquire();
    for (pos = rc_mapping_list.next; pos != &rc_mapping_list;
         pos = next) {
        struct rc_mapping *m = list_entry(pos, struct rc_mapping, list);

        next = pos->next;
        if (m->active && m->mm == mm) {
            rc_restore_mapping_locked(m, "exit_mmap");
            cleaned++;
        }
    }
    rc_lock_release();

    if (cleaned > 0)
        pr_info("recompile: [exit_mmap] cleaned %d mappings for mm=%px\n",
                cleaned, mm);

out:
    atomic_dec(&rc_in_flight);
}

static void rc_wait_for_handlers_drain(const char *phase)
{
    int i;
    int iters = 0;

    for (i = 0; i < 200000; i++)
        rc_cpu_relax();

    while (atomic_read(&rc_in_flight) > 0) {
        rc_cpu_relax();
        if (++iters > 10000000) {
            pr_warn("recompile: [%s] timeout waiting for handlers (in_flight=%d)\n",
                    phase, atomic_read(&rc_in_flight));
            break;
        }
    }
}

static int rc_register_user_step_hook_api(void)
{
    bool can_manual_unregister;

    if (!kfunc_register_user_step_hook)
        return RC_ENOSYS;

    can_manual_unregister = kptr_debug_hook_lock && kfunc_raw_spin_lock &&
                            kfunc_raw_spin_unlock;
    if (!can_manual_unregister && !kfunc_unregister_user_step_hook) {
        pr_warn("recompile: register_user_step_hook available but no unregister path\n");
        return RC_ENOSYS;
    }

    INIT_LIST_HEAD(&rc_user_step_hook.node);
    rc_user_step_hook.fn = rc_user_step_hook_fn;
    kfunc_register_user_step_hook(&rc_user_step_hook);
    rc_user_step_hook_registered = true;

    if (!kptr_debug_hook_lock)
        pr_warn("recompile: debug_hook_lock not found, falling back to unregister_user_step_hook on unload\n");
    else if (!can_manual_unregister)
        pr_warn("recompile: raw spin lock helpers missing, falling back to unregister_user_step_hook on unload\n");

    pr_info("recompile: registered user_step_hook API\n");
    return 0;
}

static void rc_unregister_user_step_hook_manual(void)
{
    if (!rc_user_step_hook_registered)
        return;

    if (kptr_debug_hook_lock && kfunc_raw_spin_lock &&
        kfunc_raw_spin_unlock) {
        kfunc_raw_spin_lock(kptr_debug_hook_lock);
        list_del_rcu(&rc_user_step_hook.node);
        kfunc_raw_spin_unlock(kptr_debug_hook_lock);
    } else if (kfunc_unregister_user_step_hook) {
        kfunc_unregister_user_step_hook(&rc_user_step_hook);
    } else {
        pr_err("recompile: no available user_step_hook unregister path\n");
        return;
    }

    rc_user_step_hook_registered = false;
    INIT_LIST_HEAD(&rc_user_step_hook.node);
}

static int rc_restore_all(const char *reason)
{
    struct list_head *pos;
    struct list_head *next;
    int cleaned = 0;

    rc_lock_acquire();
    for (pos = rc_mapping_list.next; pos != &rc_mapping_list;
         pos = next) {
        struct rc_mapping *m = list_entry(pos, struct rc_mapping, list);

        next = pos->next;
        if (m->active) {
            rc_restore_mapping_locked(m, reason);
            cleaned++;
        }
    }
    rc_lock_release();

    return cleaned;
}

static int rc_resolve_symbols(void)
{
    pr_info("recompile: resolving symbols...\n");

    kfunc_find_vma = (typeof(kfunc_find_vma))rc_resolve_required("find_vma");
    kfunc_get_task_mm = (typeof(kfunc_get_task_mm))rc_resolve_required("get_task_mm");
    kfunc_mmput = (typeof(kfunc_mmput))rc_resolve_required("mmput");

    kfunc_copy_from_kernel_nofault =
        (typeof(kfunc_copy_from_kernel_nofault))
            rc_lookup_name_safe("copy_from_kernel_nofault");
    if (!kfunc_copy_from_kernel_nofault)
        kfunc_copy_from_kernel_nofault =
            (typeof(kfunc_copy_from_kernel_nofault))
                rc_lookup_name_safe("probe_kernel_read");

    kfunc_flush_tlb_page =
        (typeof(kfunc_flush_tlb_page))rc_lookup_name_safe("flush_tlb_page");
    kfunc___flush_tlb_range =
        (typeof(kfunc___flush_tlb_range))
            rc_lookup_name_safe("__flush_tlb_range");
    kfunc___ptep_modify_prot_start =
        (typeof(kfunc___ptep_modify_prot_start))
            rc_lookup_name_safe("__ptep_modify_prot_start");
    kfunc___ptep_modify_prot_commit =
        (typeof(kfunc___ptep_modify_prot_commit))
            rc_lookup_name_safe("__ptep_modify_prot_commit");
    kfunc___split_huge_pmd =
        (typeof(kfunc___split_huge_pmd))
            rc_lookup_name_safe("__split_huge_pmd");
    kfunc_kzalloc = (typeof(kfunc_kzalloc))rc_lookup_name_safe("kzalloc");
    if (!kfunc_kzalloc)
        kfunc_kzalloc =
            (typeof(kfunc_kzalloc))rc_lookup_name_safe("__kmalloc");
    kfunc_kfree = (typeof(kfunc_kfree))rc_lookup_name_safe("kfree");
    kfunc___get_free_pages =
        (typeof(kfunc___get_free_pages))
            rc_lookup_name_safe("__get_free_pages");
    kfunc_free_pages =
        (typeof(kfunc_free_pages))rc_lookup_name_safe("free_pages");

    kfunc_fault_handler = (void *)rc_lookup_name_safe("do_mem_abort");
    if (!kfunc_fault_handler)
        kfunc_fault_handler = (void *)rc_lookup_name_safe("do_page_fault");
    if (!kfunc_fault_handler)
        pr_err("recompile: required symbol not found: do_mem_abort/do_page_fault\n");

    kfunc_exit_mmap = (void *)rc_lookup_name_safe("exit_mmap");
    if (!kfunc_exit_mmap)
        kfunc_exit_mmap = (void *)rc_lookup_name_safe("__mmput");
    if (!kfunc_exit_mmap)
        pr_err("recompile: required symbol not found: exit_mmap/__mmput\n");

    kfunc_setup_sigframe = (void *)rc_lookup_name_safe("setup_sigframe");
    kfunc_setup_rt_frame = (void *)rc_lookup_name_safe("setup_rt_frame");
    if (!kfunc_setup_sigframe && !kfunc_setup_rt_frame)
        pr_warn("recompile: setup_sigframe/setup_rt_frame not found, signal PC export is limited\n");

    kfunc_compat_setup_sigframe =
        (void *)rc_lookup_name_safe("compat_setup_sigframe");
    kfunc_compat_setup_rt_frame =
        (void *)rc_lookup_name_safe("compat_setup_rt_frame");
    kfunc_compat_setup_frame =
        (void *)rc_lookup_name_safe("compat_setup_frame");
    kfunc_do_signal = (void *)rc_lookup_name_safe("do_signal");
    kfunc_copy_regset_to_user =
        (void *)rc_lookup_name_safe("copy_regset_to_user");
    kfunc_regset_get = (void *)rc_lookup_name_safe("regset_get");
    kfunc_regset_get_alloc =
        (void *)rc_lookup_name_safe("regset_get_alloc");
    kfunc_perf_instruction_pointer =
        (void *)rc_lookup_name_safe("perf_instruction_pointer");
    kfunc_perf_reg_value = (void *)rc_lookup_name_safe("perf_reg_value");
    kfunc_perf_callchain_user =
        (void *)rc_lookup_name_safe("perf_callchain_user");
    kfunc_perf_bp_event = (void *)rc_lookup_name_safe("perf_bp_event");
    kfunc_single_step_handler =
        (void *)rc_lookup_name_safe("single_step_handler");
    kfunc_do_el0_softstep = (void *)rc_lookup_name_safe("do_el0_softstep");
    kfunc_register_user_step_hook =
        (typeof(kfunc_register_user_step_hook))
            rc_lookup_name_safe("register_user_step_hook");
    kfunc_unregister_user_step_hook =
        (typeof(kfunc_unregister_user_step_hook))
            rc_lookup_name_safe("unregister_user_step_hook");
    kfunc_user_rewind_single_step =
        (typeof(kfunc_user_rewind_single_step))
            rc_lookup_name_safe("user_rewind_single_step");
    kfunc_arm64_force_sig_fault =
        (typeof(kfunc_arm64_force_sig_fault))
            rc_lookup_name_safe("arm64_force_sig_fault");
    kfunc_raw_spin_lock =
        (typeof(kfunc_raw_spin_lock))rc_lookup_name_safe("_raw_spin_lock");
    if (!kfunc_raw_spin_lock)
        kfunc_raw_spin_lock =
            (typeof(kfunc_raw_spin_lock))
                rc_lookup_name_safe("__raw_spin_lock");
    kfunc_raw_spin_unlock =
        (typeof(kfunc_raw_spin_unlock))rc_lookup_name_safe("_raw_spin_unlock");
    if (!kfunc_raw_spin_unlock)
        kfunc_raw_spin_unlock =
            (typeof(kfunc_raw_spin_unlock))
                rc_lookup_name_safe("__raw_spin_unlock");
    kptr_debug_hook_lock = (void *)rc_lookup_name_safe("debug_hook_lock");

    kfunc_find_task_by_vpid =
        (typeof(kfunc_find_task_by_vpid))
            rc_lookup_name_safe("find_task_by_vpid");
    kfunc_rcu_read_lock =
        (typeof(kfunc_rcu_read_lock))rc_lookup_name_safe("__rcu_read_lock");
    kfunc_rcu_read_unlock =
        (typeof(kfunc_rcu_read_unlock))rc_lookup_name_safe("__rcu_read_unlock");
    kfunc_dup_mmap = (void *)rc_lookup_name_safe("dup_mmap");
    kfunc_copy_process = (void *)rc_lookup_name_safe("copy_process");

    kvar_physvirt_offset =
        (s64 *)rc_lookup_name_safe("physvirt_offset");
    kvar_memstart_addr =
        (s64 *)rc_lookup_name_safe("memstart_addr");

    if (!kfunc_find_vma || !kfunc_get_task_mm || !kfunc_mmput ||
        !kfunc_kzalloc || !kfunc_kfree ||
        !kfunc_fault_handler || !kfunc_exit_mmap)
        return RC_ENOSYS;

    pr_info("recompile: symbols resolved (fault=%px setup_sigframe=%px setup_rt_frame=%px compat_frame=%px/%px/%px do_signal=%px regset=%px/%px/%px perf=%px/%px/%px bp=%px step=%px/%px api=%px/%px rewind=%px force_sig=%px debug_lock=%px raw_spin=%px/%px alloc=%px/%px flush=%px range=%px split_pmd=%px pages=%px/%px dup_mmap=%px copy_process=%px)\n",
            kfunc_fault_handler, kfunc_setup_sigframe,
            kfunc_setup_rt_frame, kfunc_compat_setup_sigframe,
            kfunc_compat_setup_rt_frame, kfunc_compat_setup_frame,
            kfunc_do_signal,
            kfunc_copy_regset_to_user, kfunc_regset_get,
            kfunc_regset_get_alloc, kfunc_perf_instruction_pointer,
            kfunc_perf_reg_value, kfunc_perf_callchain_user,
            kfunc_perf_bp_event, kfunc_single_step_handler,
            kfunc_do_el0_softstep, kfunc_register_user_step_hook,
            kfunc_unregister_user_step_hook, kfunc_user_rewind_single_step,
            kfunc_arm64_force_sig_fault, kptr_debug_hook_lock,
            kfunc_raw_spin_lock, kfunc_raw_spin_unlock, kfunc_kzalloc,
            kfunc_kfree, kfunc_flush_tlb_page,
            kfunc___flush_tlb_range, kfunc___split_huge_pmd,
            kfunc___get_free_pages, kfunc_free_pages, kfunc_dup_mmap,
            kfunc_copy_process);
    return 0;
}

static long recompile_init(const char *args, const char *event,
                           void *__user reserved)
{
    hook_err_t err;
    int ret;

    (void)args;
    (void)event;
    (void)reserved;

    pr_info("recompile: initializing open-source core...\n");
    rc_enable_user_step_api = rc_args_enable_user_step(args);

    ret = rc_resolve_symbols();
    if (ret < 0)
        return ret;

    rc_probe_page_table_config();
    rc_probe_physvirt_translation();
    if (mm_struct_offset.pgd_offset < 0) {
        pr_err("recompile: mm_struct_offset.pgd_offset is unavailable\n");
        return RC_ENOSYS;
    }

    err = hook_syscalln(__NR_prctl, 5, recompile_prctl_before, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook prctl: %d\n", err);
        return RC_EIO;
    }

    err = hook_wrap3(kfunc_fault_handler, recompile_fault_before,
                     recompile_fault_after, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook fault handler: %d\n", err);
        unhook_syscalln(__NR_prctl, recompile_prctl_before, NULL);
        return RC_EIO;
    }

    err = hook_wrap1(kfunc_exit_mmap, recompile_exit_mmap_before, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("recompile: failed to hook exit_mmap: %d\n", err);
        hook_unwrap(kfunc_fault_handler, recompile_fault_before,
                    recompile_fault_after);
        unhook_syscalln(__NR_prctl, recompile_prctl_before, NULL);
        return RC_EIO;
    }

    if (kfunc_setup_sigframe) {
        err = hook_wrap4(kfunc_setup_sigframe, recompile_setup_frame_before,
                         recompile_setup_frame_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook setup_sigframe: %d\n", err);
            kfunc_setup_sigframe = NULL;
        } else {
            rc_hooked_setup_sigframe = true;
        }
    }

    if (kfunc_setup_rt_frame) {
        err = hook_wrap4(kfunc_setup_rt_frame, recompile_setup_frame_before,
                         recompile_setup_frame_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook setup frame: %d\n", err);
            kfunc_setup_rt_frame = NULL;
        } else {
            rc_hooked_setup_rt_frame = true;
        }
    }

    if (kfunc_compat_setup_sigframe) {
        err = hook_wrap4(kfunc_compat_setup_sigframe,
                         recompile_setup_frame_before,
                         recompile_setup_frame_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook compat_setup_sigframe: %d\n",
                    err);
            kfunc_compat_setup_sigframe = NULL;
        } else {
            rc_hooked_compat_setup_sigframe = true;
        }
    }

    if (kfunc_compat_setup_rt_frame) {
        err = hook_wrap4(kfunc_compat_setup_rt_frame,
                         recompile_setup_frame_before,
                         recompile_setup_frame_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook compat_setup_rt_frame: %d\n",
                    err);
            kfunc_compat_setup_rt_frame = NULL;
        } else {
            rc_hooked_compat_setup_rt_frame = true;
        }
    }

    if (kfunc_compat_setup_frame) {
        err = hook_wrap4(kfunc_compat_setup_frame,
                         recompile_setup_frame_before,
                         recompile_setup_frame_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook compat_setup_frame: %d\n",
                    err);
            kfunc_compat_setup_frame = NULL;
        } else {
            rc_hooked_compat_setup_frame = true;
        }
    }

    if (kfunc_do_signal) {
        err = hook_wrap1(kfunc_do_signal, recompile_regs_arg0_before,
                         recompile_regs_arg0_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook do_signal: %d\n", err);
            kfunc_do_signal = NULL;
        } else {
            rc_hooked_do_signal = true;
        }
    }

    if (kfunc_copy_regset_to_user) {
        err = hook_wrap6(kfunc_copy_regset_to_user,
                         recompile_copy_regset_to_user_before,
                         recompile_copy_regset_to_user_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook copy_regset_to_user: %d\n",
                    err);
            kfunc_copy_regset_to_user = NULL;
        } else {
            rc_hooked_copy_regset_to_user = true;
        }
    }

    if (kfunc_regset_get) {
        err = hook_wrap5(kfunc_regset_get, recompile_regset_get_before,
                         recompile_regset_get_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook regset_get: %d\n", err);
            kfunc_regset_get = NULL;
        } else {
            rc_hooked_regset_get = true;
        }
    }

    if (kfunc_regset_get_alloc) {
        err = hook_wrap5(kfunc_regset_get_alloc, recompile_regset_get_before,
                         recompile_regset_get_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook regset_get_alloc: %d\n", err);
            kfunc_regset_get_alloc = NULL;
        } else {
            rc_hooked_regset_get_alloc = true;
        }
    }

    if (kfunc_perf_instruction_pointer) {
        err = hook_wrap1(kfunc_perf_instruction_pointer,
                         recompile_regs_arg0_before,
                         recompile_regs_arg0_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook perf_instruction_pointer: %d\n",
                    err);
            kfunc_perf_instruction_pointer = NULL;
        } else {
            rc_hooked_perf_instruction_pointer = true;
        }
    }

    if (kfunc_perf_reg_value) {
        err = hook_wrap2(kfunc_perf_reg_value, recompile_perf_reg_value_before,
                         recompile_perf_reg_value_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook perf_reg_value: %d\n", err);
            kfunc_perf_reg_value = NULL;
        } else {
            rc_hooked_perf_reg_value = true;
        }
    }

    if (kfunc_perf_callchain_user) {
        err = hook_wrap4(kfunc_perf_callchain_user,
                         recompile_setup_frame_before,
                         recompile_setup_frame_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook perf_callchain_user: %d\n",
                    err);
            kfunc_perf_callchain_user = NULL;
        } else {
            rc_hooked_perf_callchain_user = true;
        }
    }

    if (kfunc_perf_bp_event) {
        err = hook_wrap2(kfunc_perf_bp_event, recompile_regs2_arg1_before,
                         recompile_regs2_arg1_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook perf_bp_event: %d\n", err);
            kfunc_perf_bp_event = NULL;
        } else {
            rc_hooked_perf_bp_event = true;
        }
    }

    if (rc_enable_user_step_api && kfunc_register_user_step_hook)
        rc_register_user_step_hook_api();

    if (!rc_user_step_hook_registered && kfunc_single_step_handler) {
        err = hook_wrap3(kfunc_single_step_handler,
                         recompile_regs3_arg2_before,
                         recompile_regs3_arg2_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook single_step_handler: %d\n",
                    err);
            kfunc_single_step_handler = NULL;
        } else {
            rc_hooked_single_step_handler = true;
        }
    }

    if (kfunc_do_el0_softstep) {
        err = hook_wrap2(kfunc_do_el0_softstep, recompile_regs2_arg1_before,
                         recompile_regs2_arg1_after, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook do_el0_softstep: %d\n", err);
            kfunc_do_el0_softstep = NULL;
        } else {
            rc_hooked_do_el0_softstep = true;
        }
    }

    if (kfunc_dup_mmap) {
        err = hook_wrap2(kfunc_dup_mmap, before_dup_mmap_rc,
                         after_dup_mmap_rc, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook dup_mmap: %d\n", err);
            kfunc_dup_mmap = NULL;
        } else {
            rc_hooked_dup_mmap = true;
        }
    }

    if (!rc_hooked_dup_mmap && kfunc_copy_process) {
        err = hook_wrap8(kfunc_copy_process, before_copy_process_rc,
                         after_copy_process_rc, NULL);
        if (err != HOOK_NO_ERR) {
            pr_warn("recompile: failed to hook copy_process: %d\n", err);
            kfunc_copy_process = NULL;
        } else {
            rc_hooked_copy_process = true;
        }
    }

    pr_info("recompile: module loaded (user_step_api=%d)\n",
            rc_enable_user_step_api ? 1 : 0);
    return 0;
}

static long recompile_exit(void *__user reserved)
{
    int cleaned;

    (void)reserved;

    unhook_syscalln(__NR_prctl, recompile_prctl_before, NULL);
    rc_wait_for_handlers_drain("phase1-prctl");

    if (rc_user_step_hook_registered) {
        rc_unregister_user_step_hook_manual();
        rc_wait_for_handlers_drain("phase0-user_step_hook");
    }

    cleaned = rc_restore_all("module unload");

    if (rc_hooked_dup_mmap) {
        hook_unwrap(kfunc_dup_mmap, before_dup_mmap_rc, after_dup_mmap_rc);
        rc_hooked_dup_mmap = false;
        rc_wait_for_handlers_drain("phase2-dup_mmap");
    }

    if (rc_hooked_copy_process) {
        hook_unwrap(kfunc_copy_process, before_copy_process_rc,
                    after_copy_process_rc);
        rc_hooked_copy_process = false;
        rc_wait_for_handlers_drain("phase2-copy_process");
    }

    if (rc_hooked_do_el0_softstep) {
        hook_unwrap(kfunc_do_el0_softstep, recompile_regs2_arg1_before,
                    recompile_regs2_arg1_after);
        rc_hooked_do_el0_softstep = false;
        rc_wait_for_handlers_drain("phase2-do_el0_softstep");
    }

    if (rc_hooked_single_step_handler) {
        hook_unwrap(kfunc_single_step_handler, recompile_regs3_arg2_before,
                    recompile_regs3_arg2_after);
        rc_hooked_single_step_handler = false;
        rc_wait_for_handlers_drain("phase2-single_step_handler");
    }

    if (rc_hooked_perf_bp_event) {
        hook_unwrap(kfunc_perf_bp_event, recompile_regs2_arg1_before,
                    recompile_regs2_arg1_after);
        rc_hooked_perf_bp_event = false;
        rc_wait_for_handlers_drain("phase2-perf_bp_event");
    }

    if (rc_hooked_perf_callchain_user) {
        hook_unwrap(kfunc_perf_callchain_user, recompile_setup_frame_before,
                    recompile_setup_frame_after);
        rc_hooked_perf_callchain_user = false;
        rc_wait_for_handlers_drain("phase2-perf_callchain_user");
    }

    if (rc_hooked_perf_reg_value) {
        hook_unwrap(kfunc_perf_reg_value, recompile_perf_reg_value_before,
                    recompile_perf_reg_value_after);
        rc_hooked_perf_reg_value = false;
        rc_wait_for_handlers_drain("phase2-perf_reg_value");
    }

    if (rc_hooked_perf_instruction_pointer) {
        hook_unwrap(kfunc_perf_instruction_pointer, recompile_regs_arg0_before,
                    recompile_regs_arg0_after);
        rc_hooked_perf_instruction_pointer = false;
        rc_wait_for_handlers_drain("phase2-perf_instruction_pointer");
    }

    if (rc_hooked_regset_get_alloc) {
        hook_unwrap(kfunc_regset_get_alloc, recompile_regset_get_before,
                    recompile_regset_get_after);
        rc_hooked_regset_get_alloc = false;
        rc_wait_for_handlers_drain("phase2-regset_get_alloc");
    }

    if (rc_hooked_regset_get) {
        hook_unwrap(kfunc_regset_get, recompile_regset_get_before,
                    recompile_regset_get_after);
        rc_hooked_regset_get = false;
        rc_wait_for_handlers_drain("phase2-regset_get");
    }

    if (rc_hooked_copy_regset_to_user) {
        hook_unwrap(kfunc_copy_regset_to_user,
                    recompile_copy_regset_to_user_before,
                    recompile_copy_regset_to_user_after);
        rc_hooked_copy_regset_to_user = false;
        rc_wait_for_handlers_drain("phase2-copy_regset_to_user");
    }

    if (rc_hooked_do_signal) {
        hook_unwrap(kfunc_do_signal, recompile_regs_arg0_before,
                    recompile_regs_arg0_after);
        rc_hooked_do_signal = false;
        rc_wait_for_handlers_drain("phase2-do_signal");
    }

    if (rc_hooked_compat_setup_frame) {
        hook_unwrap(kfunc_compat_setup_frame, recompile_setup_frame_before,
                    recompile_setup_frame_after);
        rc_hooked_compat_setup_frame = false;
        rc_wait_for_handlers_drain("phase2-compat_setup_frame");
    }

    if (rc_hooked_compat_setup_rt_frame) {
        hook_unwrap(kfunc_compat_setup_rt_frame, recompile_setup_frame_before,
                    recompile_setup_frame_after);
        rc_hooked_compat_setup_rt_frame = false;
        rc_wait_for_handlers_drain("phase2-compat_setup_rt_frame");
    }

    if (rc_hooked_compat_setup_sigframe) {
        hook_unwrap(kfunc_compat_setup_sigframe, recompile_setup_frame_before,
                    recompile_setup_frame_after);
        rc_hooked_compat_setup_sigframe = false;
        rc_wait_for_handlers_drain("phase2-compat_setup_sigframe");
    }

    if (rc_hooked_setup_rt_frame) {
        hook_unwrap(kfunc_setup_rt_frame, recompile_setup_frame_before,
                    recompile_setup_frame_after);
        rc_hooked_setup_rt_frame = false;
        rc_wait_for_handlers_drain("phase2-setup_frame");
    }

    if (rc_hooked_setup_sigframe) {
        hook_unwrap(kfunc_setup_sigframe, recompile_setup_frame_before,
                    recompile_setup_frame_after);
        rc_hooked_setup_sigframe = false;
        rc_wait_for_handlers_drain("phase2-setup_sigframe");
    }

    if (kfunc_fault_handler) {
        hook_unwrap(kfunc_fault_handler, recompile_fault_before,
                    recompile_fault_after);
        rc_wait_for_handlers_drain("phase3-fault");
    }

    if (kfunc_exit_mmap) {
        hook_unwrap(kfunc_exit_mmap, recompile_exit_mmap_before, NULL);
        rc_wait_for_handlers_drain("phase4-exit_mmap");
    }

    pr_info("recompile: unloaded (cleaned %d mappings)\n", cleaned);
    return 0;
}

KPM_INIT(recompile_init);
KPM_EXIT(recompile_exit);
