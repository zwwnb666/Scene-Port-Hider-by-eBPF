// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "hideport.skel.h"

#define MAX_PORTS 16
#define MAX_UIDS 32

struct config {
    uint16_t ports[MAX_PORTS];
    int port_count;
    uint32_t uids[MAX_UIDS];
    int uid_count;
};

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--port PORT]... [--uid UID]... [UID...]\n"
            "\n"
            "Default hidden ports: 8788, 8765.\n"
            "Default allowed UIDs: 0, 1000.\n"
            "Bare numeric arguments are treated as UID whitelist entries.\n",
            argv0);
}

static int parse_ulong(const char *text, unsigned long max, unsigned long *out)
{
    char *end = NULL;
    unsigned long value;

    if (!text || !*text)
        return -EINVAL;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || *end != '\0' || value > max)
        return -EINVAL;

    *out = value;
    return 0;
}

static int add_port(struct config *cfg, unsigned long port)
{
    if (port == 0 || port > 65535 || cfg->port_count >= MAX_PORTS)
        return -EINVAL;

    cfg->ports[cfg->port_count++] = (uint16_t)port;
    return 0;
}

static int add_uid(struct config *cfg, unsigned long uid)
{
    if (uid > UINT32_MAX || cfg->uid_count >= MAX_UIDS)
        return -EINVAL;

    cfg->uids[cfg->uid_count++] = (uint32_t)uid;
    return 0;
}

static int parse_args(int argc, char **argv, struct config *cfg)
{
    unsigned long value;
    int saw_custom_port = 0;

    memset(cfg, 0, sizeof(*cfg));
    add_port(cfg, 8788);
    add_port(cfg, 8765);
    add_uid(cfg, 0);
    add_uid(cfg, 1000);

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *value_text = NULL;

        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            usage(argv[0]);
            return 1;
        }

        if (!strcmp(arg, "--port")) {
            if (++i >= argc)
                return -EINVAL;
            value_text = argv[i];
            if (parse_ulong(value_text, 65535, &value) || value == 0)
                return -EINVAL;
            if (!saw_custom_port) {
                cfg->port_count = 0;
                saw_custom_port = 1;
            }
            if (add_port(cfg, value))
                return -EINVAL;
            continue;
        }

        if (!strncmp(arg, "--port=", 7)) {
            value_text = arg + 7;
            if (parse_ulong(value_text, 65535, &value) || value == 0)
                return -EINVAL;
            if (!saw_custom_port) {
                cfg->port_count = 0;
                saw_custom_port = 1;
            }
            if (add_port(cfg, value))
                return -EINVAL;
            continue;
        }

        if (!strcmp(arg, "--uid")) {
            if (++i >= argc)
                return -EINVAL;
            value_text = argv[i];
            if (parse_ulong(value_text, UINT32_MAX, &value))
                return -EINVAL;
            if (add_uid(cfg, value))
                return -EINVAL;
            continue;
        }

        if (!strncmp(arg, "--uid=", 6)) {
            value_text = arg + 6;
            if (parse_ulong(value_text, UINT32_MAX, &value))
                return -EINVAL;
            if (add_uid(cfg, value))
                return -EINVAL;
            continue;
        }

        if (parse_ulong(arg, UINT32_MAX, &value) || add_uid(cfg, value))
            return -EINVAL;
    }

    return 0;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        return -errno;

    return 0;
}

static int setup_ports(struct hideport_bpf *skel, const struct config *cfg)
{
    __u8 value = 1;

    for (int i = 0; i < cfg->port_count; i++) {
        __u16 key = htons(cfg->ports[i]);

        if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_ports),
                                &key, &value, BPF_ANY)) {
            fprintf(stderr, "failed to add port %u: %s\n",
                    cfg->ports[i], strerror(errno));
            return -errno;
        }
        fprintf(stderr, "hidden port: %u\n", cfg->ports[i]);
    }

    return 0;
}

static int setup_uids(struct hideport_bpf *skel, const struct config *cfg)
{
    __u8 value = 1;

    for (int i = 0; i < cfg->uid_count; i++) {
        __u32 key = cfg->uids[i];

        if (bpf_map_update_elem(bpf_map__fd(skel->maps.allowed_uids),
                                &key, &value, BPF_ANY)) {
            fprintf(stderr, "failed to add uid %u: %s\n",
                    cfg->uids[i], strerror(errno));
            return -errno;
        }
        fprintf(stderr, "allowed uid: %u\n", cfg->uids[i]);
    }

    return 0;
}

static struct bpf_link *try_attach_symbols(struct bpf_program *prog,
                                           const char *const *symbols,
                                           size_t count,
                                           const char *kind)
{
    for (size_t i = 0; i < count; i++) {
        struct bpf_link *link;
        long err;

        link = bpf_program__attach_kprobe(prog, false, symbols[i]);
        err = libbpf_get_error(link);
        if (!err) {
            fprintf(stderr, "attached %s probe to %s\n", kind, symbols[i]);
            return link;
        }

        fprintf(stderr, "attach %s probe to %s failed: %ld (%s)\n",
                kind, symbols[i], err, strerror((int)-err));
    }

    return NULL;
}

int main(int argc, char **argv)
{
    static const char *const direct_symbols[] = {
        "__sys_bind",
        "__se_sys_bind",
        "sys_bind",
        "SyS_bind",
    };
    static const char *const arm64_symbols[] = {
        "__arm64_sys_bind",
    };
    struct config cfg;
    struct hideport_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    struct bpf_link *lsm_link = NULL;
    int err;

    err = parse_args(argc, argv, &cfg);
    if (err) {
        if (err < 0)
            usage(argv[0]);
        return err < 0 ? 2 : 0;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = bump_memlock_rlimit();
    if (err)
        fprintf(stderr, "warning: failed to raise RLIMIT_MEMLOCK: %s\n",
                strerror(-err));

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = hideport_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    err = hideport_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = setup_ports(skel, &cfg);
    if (err)
        goto cleanup;

    err = setup_uids(skel, &cfg);
    if (err)
        goto cleanup;

    link = try_attach_symbols(skel->progs.hideport_bind_direct,
                              direct_symbols,
                              sizeof(direct_symbols) / sizeof(direct_symbols[0]),
                              "direct");
    if (!link) {
        link = try_attach_symbols(skel->progs.hideport_bind_arm64_syscall,
                                  arm64_symbols,
                                  sizeof(arm64_symbols) / sizeof(arm64_symbols[0]),
                                  "arm64 syscall-wrapper");
    }

    if (!link) {
        fprintf(stderr, "failed to attach any bind kprobe candidate\n");
        err = 1;
        goto cleanup;
    }

    lsm_link = bpf_program__attach(skel->progs.restrict_luna_fork);
    if (!lsm_link) {
        fprintf(stderr, "failed to attach restrict_luna_fork LSM hook\n");
    } else {
        fprintf(stderr, "LSM hook for Luna fork attached\n");
    }
    fprintf(stderr, "hideport loaded\n");
    while (!exiting)
        sleep(1);

    err = 0;

cleanup:
        if (lsm_link) bpf_link__destroy(lsm_link);
    bpf_link__destroy(link);
    hideport_bpf__destroy(skel);
    return err;
}


