/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * anti-detect: Hide emulator files from apps
 * - Blocks stat/access/readlink with ENOENT
 * - Filters directory listings (getdents64) to remove matching entries
 * - Allows openat (needed for GPU rendering via goldfish_pipe)
 * - Only affects regular apps (uid >= 10000)
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <syscall.h>
#include <kputils.h>
#include <kallsyms.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include "../common/kpm_demo_helpers.h"

KPM_MODULE_INFO("anti-detect",
                "1.2.9",
                "GPL v2",
                "wwb",
                "Hide emulator, KernelPatch, and instrumentation artifacts from apps");

/* anti-detect-supercall.c */
extern int supercall_guard_init(const char *superkey);
extern void supercall_guard_exit(void);

#define AID_APP_START 10000
#define FILENAME_BUF_SIZE 256

#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

#ifndef PTRACE_TRACEME
#define PTRACE_TRACEME 0
#endif

#ifndef PR_GET_DUMPABLE
#define PR_GET_DUMPABLE 3
#endif

/* Resolved kernel functions */
static void *(*kfn_kmalloc)(size_t size, unsigned int flags);
static void (*kfn_kfree)(const void *ptr);
static unsigned long (*kfn_copy_from_user)(void *to, const void __user *from, unsigned long n);
static long (*kfn_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);
static void *(*kfn_find_vma)(void *mm, unsigned long addr);
static void *(*kfn_get_task_mm)(void *task);
static void (*kfn_mmput)(void *mm);
static char *(*kfn_d_path)(const void *path, char *buf, int buflen);

/* GFP_KERNEL = 0xcc0 on most kernels */
#define GFP_KERNEL_VAL 0xcc0

/*
 * Offsets confirmed from this device's BTF
 * (6.1.75-android14-11-o-g7cddc8f99e91).
 */
#define VMA_VM_START_OFFSET 0x00
#define VMA_VM_END_OFFSET   0x08
#define VMA_VM_FILE_OFFSET  0x88
#define FILE_F_PATH_OFFSET  0x10
#define CALLER_PATH_BUF_SIZE 1024
#define MAX_ERRNO_VALUE 4095UL

struct linux_dirent64 {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

static const char * const hidden_path_tokens[] = {
    "goldfish_",
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
    "/data/local/tmp/rf_",
    "/data/local/tmp/frida",
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

static const char * const hidden_link_tokens[] = {
    "wwb_",
    "memfd:rust",
    "memfd:frida",
    "[anon:rust",
    "[anon:frida",
    "/data/local/tmp/rf_",
    "/data/local/tmp/frida",
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

static int contains_any_token(const char *name, const char * const *tokens)
{
    for (const char * const *p = tokens; *p; p++) {
        if (strstr(name, *p))
            return 1;
    }
    return 0;
}

static int should_hide_path(const char *name)
{
    return contains_any_token(name, hidden_path_tokens);
}

static int should_hide_link_target(const char *name)
{
    return contains_any_token(name, hidden_link_tokens);
}

/* Block stat/access/readlink for hidden files */
static void before_stat_syscall(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (uid < AID_APP_START) return;

    const char __user *ufilename = (const char __user *)syscall_argn(args, 1);
    char buf[FILENAME_BUF_SIZE];
    long len = compat_strncpy_from_user(buf, ufilename, sizeof(buf));
    if (len <= 0) return;

    if (should_hide_path(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

/* Hide symlink targets such as proc-fd entries pointing at helper memfds. */
static void after_readlinkat_syscall(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (uid < AID_APP_START) return;

    long ret = (long)args->ret;
    if (ret <= 0) return;

    char __user *ubuf = (char __user *)syscall_argn(args, 2);
    char buf[FILENAME_BUF_SIZE];
    long n = ret;

    if (!ubuf) return;
    if (n >= FILENAME_BUF_SIZE)
        n = FILENAME_BUF_SIZE - 1;
    if (kfn_copy_from_user(buf, ubuf, n))
        return;
    buf[n] = '\0';

    if (should_hide_link_target(buf)) {
        char empty = '\0';
        compat_copy_to_user(ubuf, &empty, 1);
        args->ret = -ENOENT;
    }
}

/* Pre-scan user dirent buffer for hidden entries without allocating */
static int getdents_has_hidden(char __user *ubuf, long len)
{
    unsigned short reclen;
    char name[FILENAME_BUF_SIZE];
    char __user *pos = ubuf;
    char __user *end = ubuf + len;

    while (pos < end) {
        if (kfn_copy_from_user(&reclen, pos + offsetof(struct linux_dirent64, d_reclen), 2))
            return 0;
        if (reclen == 0 || pos + reclen > end) break;
        long nlen = compat_strncpy_from_user(name, pos + offsetof(struct linux_dirent64, d_name), sizeof(name));
        if (nlen > 0 && should_hide_path(name))
            return 1;
        pos += reclen;
    }
    return 0;
}

/* Filter directory listings to remove hidden entries */
static void after_getdents64(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (uid < AID_APP_START) return;

    long ret = (long)args->ret;
    if (ret <= 0) return;

    char __user *ubuf = (char __user *)syscall_argn(args, 1);

    /* Fast path: no hidden entries, skip allocation entirely */
    if (!getdents_has_hidden(ubuf, ret))
        return;

    /* Skip filtering for huge buffers to avoid unbounded kmalloc */
    if (ret > 256 * 1024)
        return;

    char *kbuf = kfn_kmalloc(ret, GFP_KERNEL_VAL);
    if (!kbuf) return;

    if (kfn_copy_from_user(kbuf, ubuf, ret)) {
        kfn_kfree(kbuf);
        return;
    }

    char *src = kbuf;
    char *end = kbuf + ret;
    char *dst = kbuf;
    long new_ret = 0;

    while (src < end) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)src;
        unsigned short reclen = d->d_reclen;
        if (reclen == 0 || src + reclen > end) break;

        if (!should_hide_path(d->d_name)) {
            if (dst != src)
                memmove(dst, src, reclen);
            dst += reclen;
            new_ret += reclen;
        }
        src += reclen;
    }

    if (new_ret != ret) {
        if (new_ret == 0 || compat_copy_to_user(ubuf, kbuf, new_ret) == new_ret)
            args->ret = new_ret;
    }

    kfn_kfree(kbuf);
}

static void before_ptrace_syscall(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (uid < AID_APP_START) return;

    if ((long)syscall_argn(args, 0) == PTRACE_TRACEME) {
        args->ret = 0;
        args->skip_origin = 1;
    }
}

static void before_prctl_syscall(hook_fargs5_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (uid < AID_APP_START) return;

    if ((long)syscall_argn(args, 0) == PR_GET_DUMPABLE) {
        args->ret = 0;
        args->skip_origin = 1;
    }
}

static int is_err_ptr(const void *ptr)
{
    return (unsigned long)ptr >= (unsigned long)-MAX_ERRNO_VALUE;
}

static int looks_like_kernel_ptr(const void *ptr)
{
    return ptr && ((long)ptr < 0);
}

static int read_kernel_field(const void *addr, void *out, size_t size)
{
    if (!kfn_copy_from_kernel_nofault || !addr || !out)
        return 0;

    return kfn_copy_from_kernel_nofault(out, addr, size) == 0;
}

static int read_kernel_ulong_field(const void *base, unsigned long offset,
                                   unsigned long *out)
{
    return read_kernel_field((const char *)base + offset, out, sizeof(*out));
}

static int read_kernel_ptr_field(const void *base, unsigned long offset,
                                 void **out)
{
    return read_kernel_field((const char *)base + offset, out, sizeof(*out));
}

static int caller_addr_matches_path_token(unsigned long addr, const char *token)
{
    void *mm;
    void *vma;
    void *file = NULL;
    unsigned long start = 0;
    unsigned long end = 0;
    char *buf = NULL;
    char *path;
    int matched = 0;

    if (!addr || !token || !kfn_find_vma || !kfn_get_task_mm || !kfn_mmput ||
        !kfn_d_path || !kfn_kmalloc || !kfn_kfree ||
        !kfn_copy_from_kernel_nofault)
        return 0;

    mm = kfn_get_task_mm(current);
    if (!mm)
        return 0;

    vma = kfn_find_vma(mm, addr);
    if (!vma)
        goto out_mm;

    if (!read_kernel_ulong_field(vma, VMA_VM_START_OFFSET, &start) ||
        !read_kernel_ulong_field(vma, VMA_VM_END_OFFSET, &end) ||
        start > addr || end <= addr)
        goto out_mm;

    if (!read_kernel_ptr_field(vma, VMA_VM_FILE_OFFSET, &file) ||
        !looks_like_kernel_ptr(file))
        goto out_mm;

    buf = kfn_kmalloc(CALLER_PATH_BUF_SIZE, GFP_KERNEL_VAL);
    if (!buf)
        goto out_mm;

    path = kfn_d_path((const char *)file + FILE_F_PATH_OFFSET,
                      buf, CALLER_PATH_BUF_SIZE);
    if (!is_err_ptr(path)) {
        unsigned long p = (unsigned long)path;
        unsigned long b = (unsigned long)buf;

        if (p >= b && p < b + CALLER_PATH_BUF_SIZE)
            matched = strstr(path, token) != NULL;
    }

    kfn_kfree(buf);

out_mm:
    kfn_mmput(mm);
    return matched;
}

static int classify_xloader_exit(long nr, long status, const char *comm,
                                 unsigned long pc, unsigned long lr)
{
    if (nr != __NR_exit_group || status != 0)
        return 0;

    if (caller_addr_matches_path_token(lr, "libxloader.so") ||
        caller_addr_matches_path_token(pc, "libxloader.so"))
        return 1;

    if (comm && strstr(comm, "mo.client") && ((lr & 0xffffUL) == 0xe120UL))
        return 2;

    return 0;
}

static void before_exit_syscall(hook_fargs1_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (uid < AID_APP_START) return;

    long status = (long)syscall_argn(args, 0);
    struct pt_regs *regs = NULL;
    long nr = -1;

    if (has_syscall_wrapper)
        regs = (struct pt_regs *)((hook_fargs0_t *)args)->args[0];
    if (regs)
        nr = regs->syscallno;

    if (!regs || !user_mode(regs))
        return;

    const char *comm = get_task_comm(current);
    unsigned long pc = (unsigned long)regs->pc;
    unsigned long lr = (unsigned long)regs->regs[30];
    int xloader_reason = classify_xloader_exit(nr, status, comm, pc, lr);

    if (xloader_reason) {
        pr_info("anti-detect: bypass xloader exit_group comm=%s pc=%lx lr=%lx reason=%d\n",
                comm ? comm : "<null>", pc, lr, xloader_reason);
        args->ret = 0;
        args->skip_origin = 1;
    }
}

static int resolve_symbols(void)
{
    /* kmalloc - try multiple names */
    kfn_kmalloc = (typeof(kfn_kmalloc))kallsyms_lookup_name("kmalloc");
    if (!kfn_kmalloc)
        kfn_kmalloc = (typeof(kfn_kmalloc))kallsyms_lookup_name("__kmalloc");
    if (!kfn_kmalloc) {
        pr_err("anti-detect: kmalloc not found\n");
        return -1;
    }

    /* kfree */
    kfn_kfree = (typeof(kfn_kfree))kallsyms_lookup_name("kfree");
    if (!kfn_kfree) {
        pr_err("anti-detect: kfree not found\n");
        return -1;
    }

    /* copy_from_user - try multiple names */
    kfn_copy_from_user = (typeof(kfn_copy_from_user))kallsyms_lookup_name("_copy_from_user");
    if (!kfn_copy_from_user)
        kfn_copy_from_user = (typeof(kfn_copy_from_user))kallsyms_lookup_name("copy_from_user");
    if (!kfn_copy_from_user)
        kfn_copy_from_user = (typeof(kfn_copy_from_user))kallsyms_lookup_name("__arch_copy_from_user");
    if (!kfn_copy_from_user) {
        pr_err("anti-detect: copy_from_user not found\n");
        return -1;
    }

    kfn_copy_from_kernel_nofault = (typeof(kfn_copy_from_kernel_nofault))
        kallsyms_lookup_name("copy_from_kernel_nofault");
    kfn_find_vma = (typeof(kfn_find_vma))kallsyms_lookup_name("find_vma");
    kfn_get_task_mm = (typeof(kfn_get_task_mm))kallsyms_lookup_name("get_task_mm");
    kfn_mmput = (typeof(kfn_mmput))kallsyms_lookup_name("mmput");
    kfn_d_path = (typeof(kfn_d_path))kallsyms_lookup_name("d_path");

    pr_info("anti-detect: symbols resolved: kmalloc=%px kfree=%px copy_from_user=%px\n",
            kfn_kmalloc, kfn_kfree, kfn_copy_from_user);
    if (kfn_copy_from_kernel_nofault && kfn_find_vma && kfn_get_task_mm &&
        kfn_mmput && kfn_d_path) {
        pr_info("anti-detect: xloader caller path detection enabled\n");
    } else {
        pr_warn("anti-detect: xloader caller path detection disabled: nofault=%px find_vma=%px get_task_mm=%px mmput=%px d_path=%px\n",
                kfn_copy_from_kernel_nofault, kfn_find_vma, kfn_get_task_mm,
                kfn_mmput, kfn_d_path);
    }
    return 0;
}

struct syscall_hook {
    int nr;
    int narg;
    void *before;
    void *after;
};

static const struct syscall_hook hooks[] = {
    /* stat/access - block with ENOENT */
    { __NR_faccessat,     3, before_stat_syscall, 0 },
    { __NR_faccessat2,    4, before_stat_syscall, 0 },
    { __NR3264_fstatat,   4, before_stat_syscall, 0 },
    { __NR_statx,         5, before_stat_syscall, 0 },
    { __NR_readlinkat,    4, before_stat_syscall, after_readlinkat_syscall },
    /* getdents64 - filter output */
    { __NR_getdents64,    3, 0, after_getdents64 },
    /* native anti-debug probes */
    { __NR_ptrace,        4, before_ptrace_syscall, 0 },
    { __NR_prctl,         5, before_prctl_syscall, 0 },
    /* libxloader self-exit bypass */
    { __NR_exit,          1, before_exit_syscall, 0 },
    { __NR_exit_group,    1, before_exit_syscall, 0 },
};

#define NUM_HOOKS (sizeof(hooks) / sizeof(hooks[0]))

static int hooks_installed;

static long anti_detect_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("anti-detect: loading...\n");

    if (resolve_symbols())
        return -1;

    for (hooks_installed = 0; hooks_installed < NUM_HOOKS; hooks_installed++) {
        const struct syscall_hook *h = &hooks[hooks_installed];
        hook_err_t err = hook_syscalln(h->nr, h->narg, h->before, h->after, 0);
        if (err) {
            pr_err("anti-detect: hook syscall %d failed: %d\n", h->nr, err);
            goto rollback;
        }
    }

    pr_info("anti-detect: %d hooks installed\n", hooks_installed);

    /* args = superkey for supercall guard (optional) */
    if (supercall_guard_init(args))
        goto rollback_supercall;

    return 0;

rollback_supercall:
    supercall_guard_exit();
rollback:
    while (hooks_installed-- > 0) {
        const struct syscall_hook *h = &hooks[hooks_installed];
        unhook_syscalln(h->nr, h->before, h->after);
    }
    return -1;
}

static long anti_detect_exit(void *__user reserved)
{
    supercall_guard_exit();
    int i;
    for (i = NUM_HOOKS; i-- > 0;) {
        const struct syscall_hook *h = &hooks[i];
        unhook_syscalln(h->nr, h->before, h->after);
    }
    pr_info("anti-detect: unloaded\n");
    return 0;
}

KPM_INIT(anti_detect_init);
KPM_EXIT(anti_detect_exit);
