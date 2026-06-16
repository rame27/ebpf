/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * helpers.h - Inline BPF helper wrappers used across kernel programs.
 *
 * Provides:
 *   - fill_proc_ctx()  : populate a proc_ctx from the current task
 *   - read_str_safe()  : bounded bpf_probe_read_str wrapper
 *   - ntohl / ntohs    : byte-swap macros safe in BPF context
 */

#ifndef __HELPERS_H
#define __HELPERS_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/* ── Byte-order helpers ──────────────────────────────────────────────── */

#ifndef __constant_swab16
#define __constant_swab16(x) \
    ((((x) & 0x00ff) << 8) | \
     (((x) & 0xff00) >> 8))
#endif

#ifndef __bpf_htons
#define __bpf_htons(x) \
    ((__u16)(__builtin_constant_p(x) ?              \
        __constant_swab16(x) :                     \
        __builtin_bswap16((__u16)(x))))
#endif

#ifndef __bpf_ntohs
#define __bpf_ntohs(x) __bpf_htons(x)
#endif

#ifndef __bpf_htonl
#define __bpf_htonl(x) \
    ((__u32)(__builtin_constant_p(x) ?              \
        ___constant_swab32(x) :                     \
        __builtin_bswap32((__u32)(x))))
#endif

#ifndef __bpf_ntohl
#define __bpf_ntohl(x) __bpf_htonl(x)
#endif

/* ── Fill proc_ctx from the current task_struct ─────────────────────── */

static __always_inline void fill_proc_ctx(struct proc_ctx *ctx)
{
    __u64 id   = bpf_get_current_pid_tgid();
    __u64 ugid = bpf_get_current_uid_gid();

    ctx->pid   = (__u32)(id & 0xFFFFFFFF);
    ctx->tgid  = (__u32)(id >> 32);
    ctx->uid   = (__u32)(ugid & 0xFFFFFFFF);
    ctx->gid   = (__u32)(ugid >> 32);
    ctx->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&ctx->comm, sizeof(ctx->comm));
}

/* ── Bounded string read helper ─────────────────────────────────────── */

static __always_inline int read_str_safe(void *dst, int size,
                                          const void *unsafe_ptr)
{
    return bpf_probe_read_kernel_str(dst, size, unsafe_ptr);
}

/* ── Bounded user-string read helper ───────────────────────────────── */

static __always_inline int read_ustr_safe(void *dst, int size,
                                           const void __user *unsafe_ptr)
{
    return bpf_probe_read_user_str(dst, size, unsafe_ptr);
}

#endif /* __HELPERS_H */
