// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define MIN_SOCKADDR_PORT_LEN 4

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u16);
    __type(value, __u8);
} target_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u8);
} allowed_uids SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline int read_bind_port(const void *uaddr, int addrlen, __u16 *port)
{
    __u16 family = 0;

    if (!uaddr || addrlen < MIN_SOCKADDR_PORT_LEN)
        return 0;

    if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
        return 0;

    if (family != AF_INET && family != AF_INET6)
        return 0;

    if (bpf_probe_read_user(port, sizeof(*port), (const char *)uaddr + 2) < 0)
        return 0;

    return 1;
}

static __always_inline int hideport_maybe_rewrite(struct pt_regs *ctx,
                                                  const void *uaddr,
                                                  int addrlen)
{
    __u16 port = 0;
    __u16 replacement_port = 0;
    __u32 uid;
    __u8 *match;

    (void)ctx;

    if (!read_bind_port(uaddr, addrlen, &port))
        return 0;

    match = bpf_map_lookup_elem(&target_ports, &port);
    if (!match)
        return 0;

    uid = (__u32)bpf_get_current_uid_gid();
    match = bpf_map_lookup_elem(&allowed_uids, &uid);
    if (match)
        return 0;

    /*
     * This target kernel does not expose bpf_override_return(). Rewrite the
     * requested port to 0 instead, so bind() succeeds on an ephemeral port.
     */
    bpf_probe_write_user((void *)((char *)uaddr + 2),
                         &replacement_port,
                         sizeof(replacement_port));
    return 0;
}

SEC("kprobe/__sys_bind")
int hideport_bind_direct(struct pt_regs *ctx)
{
    const void *uaddr = (const void *)PT_REGS_PARM2(ctx);
    int addrlen = (int)PT_REGS_PARM3(ctx);

    return hideport_maybe_rewrite(ctx, uaddr, addrlen);
}

SEC("kprobe/__arm64_sys_bind")
int hideport_bind_arm64_syscall(struct pt_regs *ctx)
{
    const struct pt_regs *syscall_regs = (const struct pt_regs *)PT_REGS_PARM1(ctx);
    const void *uaddr = (const void *)BPF_CORE_READ(syscall_regs, regs[1]);
    int addrlen = (int)BPF_CORE_READ(syscall_regs, regs[2]);

    return hideport_maybe_rewrite(ctx, uaddr, addrlen);
}
#ifndef EPERM
#define EPERM 1
#endif

SEC("lsm/task_alloc")
int BPF_PROG(restrict_luna_fork, struct task_struct *task, unsigned long clone_flags, int ret)
{
    if (ret != 0)
        return ret;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (comm[0] == 'l' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'a' &&
        comm[4] == '.' && comm[5] == 's' && comm[6] == 'a' && comm[7] == 'f' &&
        comm[8] == 'e' && comm[9] == '.' && comm[10] == 'l' && comm[11] == 'u' &&
        comm[12] == 'n' && comm[13] == 'a' && comm[14] == '\0') {
        return -EPERM;
    }

    return 0;
}
