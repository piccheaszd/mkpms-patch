// SPDX-License-Identifier: GPL-2.0-or-later
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#define PR_RECOMPILE_REGISTER 0x52430001UL
#define PR_RECOMPILE_RELEASE  0x52430002UL

typedef int (*page_fn_t)(void);

static void on_signal(int sig, siginfo_t *si, void *ctx)
{
    (void)ctx;
    fprintf(stderr, "[recomp-prctl-smoke] signal=%d addr=%p\n", sig,
            si ? si->si_addr : NULL);
    _exit(128 + sig);
}

static void install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_signal;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}

static void emit_ret_imm32(void *page, uint16_t value)
{
    uint32_t *insn = (uint32_t *)page;

    insn[0] = 0x52800000u | ((uint32_t)value << 5); /* movz w0, #value */
    insn[1] = 0xd65f03c0u;                          /* ret */
    __builtin___clear_cache((char *)page, (char *)page + 8);
}

static void *map_code_page(long page_size, uint16_t ret_value)
{
    void *page = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (page == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    emit_ret_imm32(page, ret_value);
    if (mprotect(page, (size_t)page_size, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect RX");
        munmap(page, (size_t)page_size);
        return NULL;
    }

    return page;
}

static int call_page(const char *label, void *page)
{
    int value = ((page_fn_t)page)();

    printf("[recomp-prctl-smoke] %s -> %d\n", label, value);
    return value;
}

int main(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    void *orig;
    void *recomp;
    int before;
    int direct;
    int redirected;
    int after_release;
    int rc;

    install_signal_handlers();

    if (page_size <= 0) {
        fprintf(stderr, "[recomp-prctl-smoke] invalid page size: %ld\n",
                page_size);
        return 2;
    }

    orig = map_code_page(page_size, 7);
    recomp = map_code_page(page_size, 42);
    if (!orig || !recomp)
        return 2;

    printf("[recomp-prctl-smoke] page_size=%ld orig=%p recomp=%p\n",
           page_size, orig, recomp);

    before = call_page("before", orig);
    direct = call_page("recomp-direct", recomp);
    if (before != 7 || direct != 42) {
        fprintf(stderr, "[recomp-prctl-smoke] initial code check failed\n");
        return 3;
    }

    errno = 0;
    rc = prctl(PR_RECOMPILE_REGISTER, 0, (unsigned long)orig,
               (unsigned long)recomp, 0);
    printf("[recomp-prctl-smoke] register rc=%d errno=%d\n", rc, errno);
    if (rc != 0)
        return 4;

    redirected = call_page("after-register", orig);

    errno = 0;
    rc = prctl(PR_RECOMPILE_RELEASE, 0, (unsigned long)orig, 0, 0);
    printf("[recomp-prctl-smoke] release rc=%d errno=%d\n", rc, errno);
    if (rc != 0)
        return 5;

    after_release = call_page("after-release", orig);

    if (redirected != 42 || after_release != 7) {
        fprintf(stderr,
                "[recomp-prctl-smoke] unexpected values redirected=%d after_release=%d\n",
                redirected, after_release);
        return 6;
    }

    printf("[recomp-prctl-smoke] OK\n");
    munmap(orig, (size_t)page_size);
    munmap(recomp, (size_t)page_size);
    return 0;
}
