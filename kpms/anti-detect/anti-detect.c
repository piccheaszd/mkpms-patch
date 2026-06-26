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
#include <hook.h>
#include <kputils.h>
#include <kallsyms.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include "../common/kpm_demo_helpers.h"

KPM_MODULE_INFO("anti-detect",
                "1.2.25",
                "GPL v2",
                "wwb",
                "Hide emulator, KernelPatch, and instrumentation artifacts from apps");

/* anti-detect-supercall.c */
extern int supercall_guard_init(const char *superkey);
extern void supercall_guard_exit(void);

#define AID_APP_START 10000
#define AID_ISOLATED_START 99000
#define AID_ISOLATED_END 99999
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
static void *(*kfn_fget)(unsigned int fd);
static void (*kfn_fput)(void *file);
static void *kfn_exit_mmap;

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
#define FD_PATH_BUF_SIZE 1024
#define READ_SANITIZE_MAX (64 * 1024)
#define MAX_ERRNO_VALUE 4095UL
#define AD_MAX_PROFILES 64

#define PR_ANTIDETECT_REGISTER 0x41440001UL
#define PR_ANTIDETECT_RELEASE  0x41440002UL

#define AD_F_AUDIT_ONLY       (1UL << 0)
#define AD_F_HIDE_PATHS       (1UL << 1)
#define AD_F_HIDE_LINKS       (1UL << 2)
#define AD_F_FILTER_DIRS      (1UL << 3)
#define AD_F_FILTER_STATUS    (1UL << 4)
#define AD_F_GUARD_PTRACE     (1UL << 5)
#define AD_F_GUARD_DUMPABLE   (1UL << 6)
#define AD_F_BLOCK_SELF_EXIT  (1UL << 7)
#define AD_F_BLOCK_SELF_KILL  (1UL << 8)
#define AD_F_FEATURE_MASK     (AD_F_HIDE_PATHS | AD_F_HIDE_LINKS | \
                               AD_F_FILTER_DIRS | AD_F_FILTER_STATUS | \
                               AD_F_GUARD_PTRACE | AD_F_GUARD_DUMPABLE | \
                               AD_F_BLOCK_SELF_EXIT | AD_F_BLOCK_SELF_KILL)
#define AD_F_ALLOWED_MASK     (AD_F_AUDIT_ONLY | AD_F_FEATURE_MASK)

enum anti_detect_event {
    AD_EVT_PATH_HIT,
    AD_EVT_LINK_HIT,
    AD_EVT_DIRENT_HIT,
    AD_EVT_TRACERPID_HIT,
    AD_EVT_PTRACE_TRACEME,
    AD_EVT_PR_GET_DUMPABLE,
    AD_EVT_EXIT_BYPASS,
    AD_EVT_KILL_BYPASS,
    AD_EVT_MAX,
};

struct linux_dirent64 {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

struct anti_detect_profile {
    int active;
    void *mm;
    unsigned long flags;
    unsigned long profile_id;
    unsigned long events[AD_EVT_MAX];
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
    "/data/local/tmp/rf",
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
    "/data/local/tmp/rf",
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

static const char * const self_protect_loader_tokens[] = {
    "libxloader.so",
    "libbochk_aos.so",
    NULL,
};

static uid_t lsposed_manager_uid = (uid_t)-1;
static uid_t bochk_app_uid = (uid_t)-1;
static struct anti_detect_profile ad_profiles[AD_MAX_PROFILES];
static int ad_profiles_lock;
static int ad_profile_count;
static int hooked_exit_mmap;

static int should_skip_process(uid_t uid);
static int is_err_ptr(const void *ptr);
static int looks_like_kernel_ptr(const void *ptr);

static inline void ad_cpu_relax(void)
{
    asm volatile("yield" ::: "memory");
}

static void ad_lock_profiles(void)
{
    while (__sync_lock_test_and_set(&ad_profiles_lock, 1) != 0)
        ad_cpu_relax();
}

static void ad_unlock_profiles(void)
{
    __sync_lock_release(&ad_profiles_lock);
}

static unsigned long ad_normalize_flags(unsigned long flags)
{
    if (flags == 0)
        flags |= AD_F_FEATURE_MASK;
    return flags;
}

static void ad_log_profile_stats(const char *prefix,
                                 const struct anti_detect_profile *profile)
{
    if (!profile)
        return;

    pr_info("anti-detect: %s profile id=%lu mm=%px flags=0x%lx path=%lu link=%lu dir=%lu tracerpid=%lu ptrace=%lu dumpable=%lu exit=%lu kill=%lu\n",
            prefix, profile->profile_id, profile->mm, profile->flags,
            profile->events[AD_EVT_PATH_HIT],
            profile->events[AD_EVT_LINK_HIT],
            profile->events[AD_EVT_DIRENT_HIT],
            profile->events[AD_EVT_TRACERPID_HIT],
            profile->events[AD_EVT_PTRACE_TRACEME],
            profile->events[AD_EVT_PR_GET_DUMPABLE],
            profile->events[AD_EVT_EXIT_BYPASS],
            profile->events[AD_EVT_KILL_BYPASS]);
}

static void ad_copy_profile(struct anti_detect_profile *dst,
                            const struct anti_detect_profile *src)
{
    int i;

    if (!dst || !src)
        return;

    dst->active = src->active;
    dst->mm = src->mm;
    dst->flags = src->flags;
    dst->profile_id = src->profile_id;
    for (i = 0; i < AD_EVT_MAX; i++)
        dst->events[i] = src->events[i];
}

static int ad_register_profile(void *mm, unsigned long flags,
                               unsigned long profile_id)
{
    int free_slot = -1;
    int i;

    if (!mm)
        return -EPERM;
    if (flags & ~AD_F_ALLOWED_MASK)
        return -EINVAL;

    flags = ad_normalize_flags(flags);

    ad_lock_profiles();
    for (i = 0; i < AD_MAX_PROFILES; i++) {
        struct anti_detect_profile *p = &ad_profiles[i];
        if (!p->active) {
            if (free_slot < 0)
                free_slot = i;
            continue;
        }
        if (p->mm == mm) {
            p->flags = flags;
            p->profile_id = profile_id;
            memset(p->events, 0, sizeof(p->events));
            ad_unlock_profiles();
            pr_info("anti-detect: updated profile id=%lu mm=%px flags=0x%lx\n",
                    profile_id, mm, flags);
            return 0;
        }
    }

    if (free_slot < 0) {
        ad_unlock_profiles();
        return -ENOMEM;
    }

    memset(&ad_profiles[free_slot], 0, sizeof(ad_profiles[free_slot]));
    ad_profiles[free_slot].active = 1;
    ad_profiles[free_slot].mm = mm;
    ad_profiles[free_slot].flags = flags;
    ad_profiles[free_slot].profile_id = profile_id;
    ad_profile_count++;
    ad_unlock_profiles();

    pr_info("anti-detect: registered profile id=%lu mm=%px flags=0x%lx\n",
            profile_id, mm, flags);
    return 0;
}

static int ad_release_profile(void *mm)
{
    struct anti_detect_profile released;
    int found = 0;
    int i;

    if (!mm)
        return -EPERM;

    memset(&released, 0, sizeof(released));

    ad_lock_profiles();
    for (i = 0; i < AD_MAX_PROFILES; i++) {
        struct anti_detect_profile *p = &ad_profiles[i];
        if (!p->active || p->mm != mm)
            continue;

        ad_copy_profile(&released, p);
        memset(p, 0, sizeof(*p));
        if (ad_profile_count > 0)
            ad_profile_count--;
        found = 1;
        break;
    }
    ad_unlock_profiles();

    if (!found)
        return -ENOENT;

    ad_log_profile_stats("released", &released);
    return 0;
}

static int ad_clear_mm_profiles(void *mm)
{
    struct anti_detect_profile released;
    int removed = 0;
    int i;

    if (!mm)
        return 0;

    memset(&released, 0, sizeof(released));

    ad_lock_profiles();
    for (i = 0; i < AD_MAX_PROFILES; i++) {
        struct anti_detect_profile *p = &ad_profiles[i];
        if (!p->active || p->mm != mm)
            continue;

        ad_copy_profile(&released, p);
        memset(p, 0, sizeof(*p));
        if (ad_profile_count > 0)
            ad_profile_count--;
        removed++;
        break;
    }
    ad_unlock_profiles();

    if (removed)
        ad_log_profile_stats("exit_mmap", &released);
    return removed;
}

static int ad_current_profile_flags(unsigned long *flags)
{
    void *mm;
    int found = 0;
    int i;

    if (flags)
        *flags = 0;
    if (ad_profile_count <= 0 || !kfn_get_task_mm || !kfn_mmput)
        return 0;

    mm = kfn_get_task_mm(current);
    if (!mm)
        return 0;

    ad_lock_profiles();
    for (i = 0; i < AD_MAX_PROFILES; i++) {
        struct anti_detect_profile *p = &ad_profiles[i];
        if (!p->active || p->mm != mm)
            continue;
        if (flags)
            *flags = p->flags;
        found = 1;
        break;
    }
    ad_unlock_profiles();

    kfn_mmput(mm);
    return found;
}

static void ad_count_event(enum anti_detect_event event)
{
    void *mm;
    int i;

    if (event < 0 || event >= AD_EVT_MAX)
        return;
    if (ad_profile_count <= 0 || !kfn_get_task_mm || !kfn_mmput)
        return;

    mm = kfn_get_task_mm(current);
    if (!mm)
        return;

    ad_lock_profiles();
    for (i = 0; i < AD_MAX_PROFILES; i++) {
        struct anti_detect_profile *p = &ad_profiles[i];
        if (!p->active || p->mm != mm)
            continue;
        p->events[event]++;
        break;
    }
    ad_unlock_profiles();

    kfn_mmput(mm);
}

static int ad_should_apply(uid_t uid, unsigned long feature, int *audit_only)
{
    unsigned long flags = 0;

    if (audit_only)
        *audit_only = 0;

    if (ad_current_profile_flags(&flags)) {
        if ((flags & feature) == 0)
            return 0;
        if (audit_only)
            *audit_only = (flags & AD_F_AUDIT_ONLY) != 0;
        return 1;
    }

    if (uid < AID_APP_START || should_skip_process(uid))
        return 0;

    return 1;
}

static long ad_register_current(unsigned long flags, unsigned long profile_id)
{
    void *mm;
    int ret;

    if (!kfn_get_task_mm || !kfn_mmput)
        return -ENOSYS;

    mm = kfn_get_task_mm(current);
    if (!mm)
        return -EPERM;

    ret = ad_register_profile(mm, flags, profile_id);
    kfn_mmput(mm);
    return ret;
}

static long ad_release_current(void)
{
    void *mm;
    int ret;

    if (!kfn_get_task_mm || !kfn_mmput)
        return -ENOSYS;

    mm = kfn_get_task_mm(current);
    if (!mm)
        return -EPERM;

    ret = ad_release_profile(mm);
    kfn_mmput(mm);
    return ret;
}

static int contains_any_token(const char *name, const char * const *tokens)
{
    for (const char * const *p = tokens; *p; p++) {
        if (strstr(name, *p))
            return 1;
    }
    return 0;
}

static int task_comm_contains(struct task_struct *task, const char *token)
{
    const char *comm;

    if (!task || !token)
        return 0;

    comm = get_task_comm(task);
    return comm && strstr(comm, token);
}

static int current_is_lsposed_manager(void)
{
    uid_t uid = current_uid();

    if (uid == lsposed_manager_uid)
        return 1;

    if (task_comm_contains(current, "lsposed.manager") ||
        task_comm_contains(current, "org.lsposed")) {
        lsposed_manager_uid = uid;
        return 1;
    }

    return 0;
}

static void cache_bochk_uid_if_named(uid_t uid)
{
    if (uid >= AID_APP_START && task_comm_contains(current, "bochk.app.aos"))
        bochk_app_uid = uid;
}

static int current_name_is_bochk_component(void)
{
    return task_comm_contains(current, "bochk.app.aos") ||
           task_comm_contains(current, "fiqlohqeo");
}

static int uid_is_isolated(uid_t uid)
{
    return uid >= AID_ISOLATED_START && uid <= AID_ISOLATED_END;
}

static int current_is_bochk_process(uid_t uid)
{
    cache_bochk_uid_if_named(uid);
    return uid >= AID_APP_START && uid == bochk_app_uid;
}

static int should_skip_process(uid_t uid)
{
    /*
     * BOCHK reports integrity code 03 when these syscall results are tampered
     * with. Keep its main and obfuscated helper processes outside this KPM and
     * handle only UI-level behavior there.
     */
    if (uid_is_isolated(uid))
        return 1;

    cache_bochk_uid_if_named(uid);
    return current_name_is_bochk_component() ||
           (uid >= AID_APP_START && uid == bochk_app_uid);
}

static int current_may_see_hidden_artifacts(void)
{
    return current_is_lsposed_manager();
}

static int should_hide_path(const char *name)
{
    if (current_may_see_hidden_artifacts())
        return 0;

    return contains_any_token(name, hidden_path_tokens);
}

static int should_hide_link_target(const char *name)
{
    if (current_may_see_hidden_artifacts())
        return 0;

    return contains_any_token(name, hidden_link_tokens);
}

/* Block stat/access/readlink for hidden files */
static void before_stat_syscall(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    int audit_only = 0;
    if (!ad_should_apply(uid, AD_F_HIDE_PATHS, &audit_only)) return;

    const char __user *ufilename = (const char __user *)syscall_argn(args, 1);
    char buf[FILENAME_BUF_SIZE];
    long len = compat_strncpy_from_user(buf, ufilename, sizeof(buf));
    if (len <= 0) return;

    if (should_hide_path(buf)) {
        ad_count_event(AD_EVT_PATH_HIT);
        if (audit_only)
            return;
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

/* Hide symlink targets such as proc-fd entries pointing at helper memfds. */
static void after_readlinkat_syscall(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    int audit_only = 0;
    if (!ad_should_apply(uid, AD_F_HIDE_LINKS, &audit_only)) return;

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
        ad_count_event(AD_EVT_LINK_HIT);
        if (audit_only)
            return;
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
    int audit_only = 0;
    if (!ad_should_apply(uid, AD_F_FILTER_DIRS, &audit_only)) return;

    long ret = (long)args->ret;
    if (ret <= 0) return;

    char __user *ubuf = (char __user *)syscall_argn(args, 1);

    /* Fast path: no hidden entries, skip allocation entirely */
    if (!getdents_has_hidden(ubuf, ret))
        return;
    ad_count_event(AD_EVT_DIRENT_HIT);
    if (audit_only)
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

static int sanitize_tracerpid_line(char *buf, long len)
{
    char *p = buf;
    char *end = buf + len;
    int changed = 0;

    while (p < end && (p = strstr(p, "TracerPid:")) != NULL) {
        char *line_end = p;
        char *digits;
        int nonzero = 0;

        while (line_end < end && *line_end && *line_end != '\n')
            line_end++;

        digits = p + strlen("TracerPid:");
        while (digits < line_end && (*digits == ' ' || *digits == '\t'))
            digits++;

        if (digits >= line_end || *digits < '0' || *digits > '9') {
            p = line_end + (line_end < end);
            continue;
        }

        for (char *q = digits; q < line_end && *q >= '0' && *q <= '9'; q++) {
            if (*q != '0')
                nonzero = 1;
        }

        if (nonzero) {
            *digits++ = '0';
            while (digits < line_end && *digits >= '0' && *digits <= '9')
                *digits++ = ' ';
            changed = 1;
        }

        p = line_end + (line_end < end);
    }

    return changed;
}

static int string_ends_with(const char *value, const char *suffix)
{
    size_t value_len;
    size_t suffix_len;

    if (!value || !suffix)
        return 0;

    value_len = strlen(value);
    suffix_len = strlen(suffix);
    if (suffix_len > value_len)
        return 0;

    return memcmp(value + value_len - suffix_len, suffix, suffix_len) == 0;
}

static int fd_path_is_proc_status(long fd)
{
    void *file;
    char *buf;
    char *path;
    int matched = 0;

    if (fd < 0 || !kfn_fget || !kfn_fput || !kfn_d_path ||
        !kfn_kmalloc || !kfn_kfree)
        return 0;

    file = kfn_fget((unsigned int)fd);
    if (!file || is_err_ptr(file) || !looks_like_kernel_ptr(file))
        return 0;

    buf = kfn_kmalloc(FD_PATH_BUF_SIZE, GFP_KERNEL_VAL);
    if (!buf)
        goto out_file;

    path = kfn_d_path((const char *)file + FILE_F_PATH_OFFSET,
                      buf, FD_PATH_BUF_SIZE);
    if (!is_err_ptr(path)) {
        unsigned long p = (unsigned long)path;
        unsigned long b = (unsigned long)buf;

        if (p >= b && p < b + FD_PATH_BUF_SIZE &&
            strstr(path, "/proc/") && string_ends_with(path, "/status"))
            matched = 1;
    }

    kfn_kfree(buf);

out_file:
    kfn_fput(file);
    return matched;
}

static void after_read_syscall(hook_fargs3_t *args, void *udata)
{
    uid_t uid = current_uid();
    int audit_only = 0;
    long ret = (long)args->ret;
    long fd = (long)syscall_argn(args, 0);
    char __user *ubuf;
    char *kbuf;

    if (!ad_should_apply(uid, AD_F_FILTER_STATUS, &audit_only) ||
        ret <= 0 || ret > READ_SANITIZE_MAX)
        return;

    if (!fd_path_is_proc_status(fd))
        return;

    ubuf = (char __user *)syscall_argn(args, 1);
    if (!ubuf)
        return;

    kbuf = kfn_kmalloc(ret + 1, GFP_KERNEL_VAL);
    if (!kbuf)
        return;

    if (kfn_copy_from_user(kbuf, ubuf, ret)) {
        kfn_kfree(kbuf);
        return;
    }
    kbuf[ret] = '\0';

    if (sanitize_tracerpid_line(kbuf, ret)) {
        ad_count_event(AD_EVT_TRACERPID_HIT);
        if (!audit_only && compat_copy_to_user(ubuf, kbuf, ret) == ret)
            pr_info("anti-detect: sanitized TracerPid for comm=%s uid=%u\n",
                    get_task_comm(current), uid);
    }

    kfn_kfree(kbuf);
}

static void before_ptrace_syscall(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    int audit_only = 0;
    if (!ad_should_apply(uid, AD_F_GUARD_PTRACE, &audit_only)) return;

    if ((long)syscall_argn(args, 0) == PTRACE_TRACEME) {
        ad_count_event(AD_EVT_PTRACE_TRACEME);
        if (audit_only)
            return;
        args->ret = 0;
        args->skip_origin = 1;
    }
}

static void before_prctl_syscall(hook_fargs5_t *args, void *udata)
{
    unsigned long option = syscall_argn(args, 0);
    uid_t uid = current_uid();
    int audit_only = 0;
    long ret;

    if (option == PR_ANTIDETECT_REGISTER) {
        unsigned long pid = syscall_argn(args, 1);
        unsigned long flags = syscall_argn(args, 2);
        unsigned long profile_id = syscall_argn(args, 3);

        ret = pid == 0 ? ad_register_current(flags, profile_id) : -EINVAL;
        args->ret = (u64)ret;
        args->skip_origin = 1;
        return;
    }

    if (option == PR_ANTIDETECT_RELEASE) {
        unsigned long pid = syscall_argn(args, 1);

        ret = pid == 0 ? ad_release_current() : -EINVAL;
        args->ret = (u64)ret;
        args->skip_origin = 1;
        return;
    }

    if (!ad_should_apply(uid, AD_F_GUARD_DUMPABLE, &audit_only)) return;

    if ((long)option == PR_GET_DUMPABLE) {
        ad_count_event(AD_EVT_PR_GET_DUMPABLE);
        if (audit_only)
            return;
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

static int caller_addr_matches_any_path_token(unsigned long addr,
                                              const char * const *tokens)
{
    for (const char * const *p = tokens; *p; p++) {
        if (caller_addr_matches_path_token(addr, *p))
            return 1;
    }

    return 0;
}

static int caller_matches_self_protect_loader(unsigned long pc, unsigned long lr)
{
    return caller_addr_matches_any_path_token(lr, self_protect_loader_tokens) ||
           caller_addr_matches_any_path_token(pc, self_protect_loader_tokens);
}

static int is_self_protect_exit_status(long status)
{
    return status == 0 || status == 1 || status == 255 ||
           (unsigned long)status == 0xffffffffUL;
}

static int classify_self_protect_exit(long nr, long status, const char *comm,
                                      uid_t uid,
                                      unsigned long pc, unsigned long lr)
{
    if (nr != __NR_exit && nr != __NR_exit_group)
        return 0;

    if (is_self_protect_exit_status(status) && current_is_bochk_process(uid))
        return 4;

    if (is_self_protect_exit_status(status) &&
        caller_matches_self_protect_loader(pc, lr))
        return 1;

    if (status == 0 && comm && strstr(comm, "mo.client") && ((lr & 0xffffUL) == 0xe120UL))
        return 2;

    return 0;
}

static int is_fatal_signal(long sig)
{
    return sig == 4 || sig == 5 || sig == 6 || sig == 7 ||
           sig == 9 || sig == 11 || sig == 15;
}

static int classify_self_protect_kill(long sig, uid_t uid,
                                      unsigned long pc, unsigned long lr)
{
    if (!is_fatal_signal(sig))
        return 0;

    if (current_is_bochk_process(uid))
        return 4;

    if (caller_matches_self_protect_loader(pc, lr))
        return 3;

    return 0;
}

static void before_exit_syscall(hook_fargs1_t *args, void *udata)
{
    uid_t uid = current_uid();
    int audit_only = 0;
    if (!ad_should_apply(uid, AD_F_BLOCK_SELF_EXIT, &audit_only)) return;

    long status = (long)syscall_argn(args, 0);
    struct pt_regs *regs = NULL;
    long nr = -1;

    if (has_syscall_wrapper)
        regs = (struct pt_regs *)((hook_fargs0_t *)args)->args[0];
    if (regs)
        nr = regs->syscallno;

    if (!regs || !user_mode(regs))
        return;

    /*
     * Audit-only must stay async-light here. The caller-path classifier walks
     * current->mm VMAs and calls d_path(); doing that from BOCHK's exit path
     * was the only extra 0x181 surface when the device became unresponsive.
     */
    if (audit_only) {
        if (is_self_protect_exit_status(status))
            ad_count_event(AD_EVT_EXIT_BYPASS);
        return;
    }

    const char *comm = get_task_comm(current);
    unsigned long pc = (unsigned long)regs->pc;
    unsigned long lr = (unsigned long)regs->regs[30];
    int self_protect_reason = classify_self_protect_exit(nr, status, comm, uid, pc, lr);

    if (self_protect_reason) {
        ad_count_event(AD_EVT_EXIT_BYPASS);
        pr_info("anti-detect: bypass self-protect exit nr=%ld status=%ld comm=%s pc=%lx lr=%lx reason=%d\n",
                nr, status, comm ? comm : "<null>", pc, lr, self_protect_reason);
        args->ret = 0;
        args->skip_origin = 1;
    }
}

static void before_kill_syscall(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    int audit_only = 0;
    if (!ad_should_apply(uid, AD_F_BLOCK_SELF_KILL, &audit_only)) return;

    struct pt_regs *regs = NULL;
    long nr = -1;
    long target = (long)syscall_argn(args, 0);
    long sig = (long)syscall_argn(args, 1);
    long tid = -1;

    if (has_syscall_wrapper)
        regs = (struct pt_regs *)((hook_fargs0_t *)args)->args[0];
    if (regs)
        nr = regs->syscallno;

    if (!regs || !user_mode(regs))
        return;

    if (nr == __NR_tgkill || nr == __NR_rt_tgsigqueueinfo) {
        tid = (long)syscall_argn(args, 1);
        sig = (long)syscall_argn(args, 2);
    }

    /*
     * Same rule as exit: audit-only records the cheap signal class only. Caller
     * VMA/path resolution is reserved for the active blocking mode.
     */
    if (audit_only) {
        if (is_fatal_signal(sig))
            ad_count_event(AD_EVT_KILL_BYPASS);
        return;
    }

    const char *comm = get_task_comm(current);
    unsigned long pc = (unsigned long)regs->pc;
    unsigned long lr = (unsigned long)regs->regs[30];
    int reason = classify_self_protect_kill(sig, uid, pc, lr);

    if (reason) {
        ad_count_event(AD_EVT_KILL_BYPASS);
        pr_info("anti-detect: bypass self-protect kill nr=%ld target=%ld tid=%ld sig=%ld comm=%s pc=%lx lr=%lx reason=%d\n",
                nr, target, tid, sig, comm ? comm : "<null>", pc, lr, reason);
        args->ret = 0;
        args->skip_origin = 1;
    }
}

static void anti_detect_exit_mmap_before(hook_fargs1_t *args, void *udata)
{
    void *mm = (void *)args->arg0;

    (void)udata;
    ad_clear_mm_profiles(mm);
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
    kfn_fget = (typeof(kfn_fget))kallsyms_lookup_name("fget");
    kfn_fput = (typeof(kfn_fput))kallsyms_lookup_name("fput");
    kfn_exit_mmap = (void *)kallsyms_lookup_name("exit_mmap");

    pr_info("anti-detect: symbols resolved: kmalloc=%px kfree=%px copy_from_user=%px\n",
            kfn_kmalloc, kfn_kfree, kfn_copy_from_user);
    if (kfn_copy_from_kernel_nofault && kfn_find_vma && kfn_get_task_mm &&
        kfn_mmput && kfn_d_path) {
        pr_info("anti-detect: self-protect caller path detection enabled\n");
    } else {
        pr_warn("anti-detect: self-protect caller path detection disabled: nofault=%px find_vma=%px get_task_mm=%px mmput=%px d_path=%px\n",
                kfn_copy_from_kernel_nofault, kfn_find_vma, kfn_get_task_mm,
                kfn_mmput, kfn_d_path);
    }
    if (!kfn_get_task_mm || !kfn_mmput)
        pr_warn("anti-detect: per-mm profiles disabled: get_task_mm=%px mmput=%px\n",
                kfn_get_task_mm, kfn_mmput);
    if (!kfn_fget || !kfn_fput || !kfn_d_path)
        pr_warn("anti-detect: fd-aware status filtering disabled: fget=%px fput=%px d_path=%px\n",
                kfn_fget, kfn_fput, kfn_d_path);
    if (!kfn_exit_mmap)
        pr_warn("anti-detect: exit_mmap not found; profile cleanup relies on release/module unload\n");
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
    /* proc status - hide self ptrace parent from app reads */
    { __NR_read,          3, 0, after_read_syscall },
    /* native anti-debug probes */
    { __NR_ptrace,        4, before_ptrace_syscall, 0 },
    { __NR_prctl,         5, before_prctl_syscall, 0 },
    /* native loader self-exit bypass */
    { __NR_exit,          1, before_exit_syscall, 0 },
    { __NR_exit_group,    1, before_exit_syscall, 0 },
    { __NR_kill,          2, before_kill_syscall, 0 },
    { __NR_tkill,         2, before_kill_syscall, 0 },
    { __NR_tgkill,        3, before_kill_syscall, 0 },
    { __NR_rt_sigqueueinfo, 3, before_kill_syscall, 0 },
    { __NR_rt_tgsigqueueinfo, 4, before_kill_syscall, 0 },
    { __NR_pidfd_send_signal, 4, before_kill_syscall, 0 },
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

    if (kfn_exit_mmap) {
        hook_err_t err = hook_wrap1(kfn_exit_mmap, anti_detect_exit_mmap_before, NULL, NULL);
        if (err == HOOK_NO_ERR) {
            hooked_exit_mmap = 1;
            pr_info("anti-detect: hooked exit_mmap %p for profile cleanup\n",
                    kfn_exit_mmap);
        } else {
            pr_warn("anti-detect: failed to hook exit_mmap: %d\n", err);
        }
    }

    /* args = superkey for supercall guard (optional) */
    if (supercall_guard_init(args))
        goto rollback_supercall;

    return 0;

rollback_supercall:
    supercall_guard_exit();
    if (hooked_exit_mmap && kfn_exit_mmap) {
        hook_unwrap(kfn_exit_mmap, anti_detect_exit_mmap_before, NULL);
        hooked_exit_mmap = 0;
    }
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
    if (hooked_exit_mmap && kfn_exit_mmap) {
        hook_unwrap(kfn_exit_mmap, anti_detect_exit_mmap_before, NULL);
        hooked_exit_mmap = 0;
    }
    int i;
    for (i = NUM_HOOKS; i-- > 0;) {
        const struct syscall_hook *h = &hooks[i];
        unhook_syscalln(h->nr, h->before, h->after);
    }
    ad_lock_profiles();
    memset(ad_profiles, 0, sizeof(ad_profiles));
    ad_profile_count = 0;
    ad_unlock_profiles();
    pr_info("anti-detect: unloaded\n");
    return 0;
}

KPM_INIT(anti_detect_init);
KPM_EXIT(anti_detect_exit);
