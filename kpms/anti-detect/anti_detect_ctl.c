/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

#define PR_ANTIDETECT_SET_MODE 0x41440003UL
#define PR_ANTIDETECT_ADD_PERSISTENT_UID 0x41440005UL
#define PR_ANTIDETECT_CLEAR_PERSISTENT_UIDS 0x41440006UL

#define AD_MODE_PROFILE_ONLY (1UL << 0)
#define AD_PERSISTENT_UID_ACTIVE (1UL << 0)
#define AD_PERSISTENT_UID_PAIC_COMPAT (1UL << 1)
#define AD_PERSISTENT_UID_PAIC_FULL (1UL << 2)
#define AD_PERSISTENT_UID_PAIC_HIDE_ONLY (1UL << 3)

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s add-uid <uid>\n"
            "  %s add-uid-active <uid>\n"
            "  %s add-uid-paic <uid>       # PAIC daily: light hide + one-shot exit\n"
            "  %s add-uid-paic-full <uid>  # PAIC debug: full hide + one-shot exit\n"
            "  %s add-uid-paic-hide <uid>  # PAIC probe: light hide only\n"
            "  %s clear-uids\n"
            "  %s mode profile-only|legacy\n",
            argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

static int parse_ulong(const char *value, unsigned long *out)
{
    char *end = NULL;
    unsigned long parsed;

    if (!value || !*value || !out)
        return -1;

    errno = 0;
    parsed = strtoul(value, &end, 0);
    if (errno || !end || *end)
        return -1;

    *out = parsed;
    return 0;
}

static int run_prctl2(unsigned long option, unsigned long arg2, unsigned long arg3)
{
    int rc = prctl((int)option, arg2, arg3, 0, 0);

    if (rc < 0) {
        fprintf(stderr, "prctl(0x%lx, %lu, %lu) failed: %s (errno=%d)\n",
                option, arg2, arg3, strerror(errno), errno);
        return 1;
    }

    printf("ok: prctl(0x%lx, %lu, %lu) -> %d\n", option, arg2, arg3, rc);
    return 0;
}

static int run_prctl(unsigned long option, unsigned long arg2)
{
    return run_prctl2(option, arg2, 0);
}

int main(int argc, char **argv)
{
    unsigned long value;

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    if (!strcmp(argv[1], "add-uid")) {
        if (argc != 3 || parse_ulong(argv[2], &value) != 0) {
            usage(argv[0]);
            return 2;
        }
        return run_prctl2(PR_ANTIDETECT_ADD_PERSISTENT_UID, value, 0);
    }

    if (!strcmp(argv[1], "add-uid-active")) {
        if (argc != 3 || parse_ulong(argv[2], &value) != 0) {
            usage(argv[0]);
            return 2;
        }
        return run_prctl2(PR_ANTIDETECT_ADD_PERSISTENT_UID, value,
                          AD_PERSISTENT_UID_ACTIVE);
    }

    if (!strcmp(argv[1], "add-uid-paic")) {
        if (argc != 3 || parse_ulong(argv[2], &value) != 0) {
            usage(argv[0]);
            return 2;
        }
        return run_prctl2(PR_ANTIDETECT_ADD_PERSISTENT_UID, value,
                          AD_PERSISTENT_UID_PAIC_COMPAT);
    }

    if (!strcmp(argv[1], "add-uid-paic-full")) {
        if (argc != 3 || parse_ulong(argv[2], &value) != 0) {
            usage(argv[0]);
            return 2;
        }
        return run_prctl2(PR_ANTIDETECT_ADD_PERSISTENT_UID, value,
                          AD_PERSISTENT_UID_PAIC_COMPAT |
                          AD_PERSISTENT_UID_PAIC_FULL);
    }

    if (!strcmp(argv[1], "add-uid-paic-hide")) {
        if (argc != 3 || parse_ulong(argv[2], &value) != 0) {
            usage(argv[0]);
            return 2;
        }
        return run_prctl2(PR_ANTIDETECT_ADD_PERSISTENT_UID, value,
                          AD_PERSISTENT_UID_PAIC_COMPAT |
                          AD_PERSISTENT_UID_PAIC_HIDE_ONLY);
    }

    if (!strcmp(argv[1], "clear-uids")) {
        if (argc != 2) {
            usage(argv[0]);
            return 2;
        }
        return run_prctl(PR_ANTIDETECT_CLEAR_PERSISTENT_UIDS, 0);
    }

    if (!strcmp(argv[1], "mode")) {
        if (argc != 3) {
            usage(argv[0]);
            return 2;
        }
        if (!strcmp(argv[2], "profile-only")) {
            return run_prctl(PR_ANTIDETECT_SET_MODE, AD_MODE_PROFILE_ONLY);
        }
        if (!strcmp(argv[2], "legacy")) {
            return run_prctl(PR_ANTIDETECT_SET_MODE, 0);
        }
        usage(argv[0]);
        return 2;
    }

    usage(argv[0]);
    return 2;
}
