/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * common.h - Shared constants, macros, and primitive types used across
 *            all eBPF kernel programs in this project.
 *
 * Requirements:
 *   - Included by every .bpf.c kernel program.
 *   - Must compile under the BPF restricted C dialect (no libc, no FP).
 *   - Userspace loaders include this via <vmlinux.h> or <linux/types.h>
 *     before including this header.
 */

#ifndef __COMMON_H
#define __COMMON_H

#ifndef __user
#define __user
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 1
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#ifndef TC_ACT_PIPE
#define TC_ACT_PIPE 3
#endif

/* ── Compiler / verifier helpers ─────────────────────────────────────── */

#define TASK_COMM_LEN   16
#define MAX_FILENAME    256
#define MAX_ARGS_SIZE   256
#define MAX_DNS_NAME    128
#define MAX_ENVP_SIZE   128

/* Force a value to be seen by the verifier as bounded. */
#define CLAMP(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))

/* Avoid compiler warnings on intentionally unused variables inside BPF. */
#define UNUSED(x) ((void)(x))

/* ── Network helpers ─────────────────────────────────────────────────── */

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_HLEN   14

#define IPPROTO_TCP  6
#define IPPROTO_UDP  17
#define IPPROTO_ICMP 1

/* ── Ring-buffer / perf map sizing ──────────────────────────────────── */

#define RINGBUF_SIZE_BYTES (1 << 24)   /* 16 MiB */

/* ── Common process metadata embedded in every event ────────────────── */

struct proc_ctx {
    unsigned int  pid;
    unsigned int  tgid;
    unsigned int  uid;
    unsigned int  gid;
    char          comm[TASK_COMM_LEN];
    unsigned long long ts_ns;   /* ktime_get_ns() at event time */
};

/* ── Event type discriminator ────────────────────────────────────────── */

enum event_type {
    EVT_NET_TRAFFIC      = 1,
    EVT_PROC_EXEC        = 2,
    EVT_FILE_INTEGRITY   = 3,
    EVT_SYSCALL_ANOMALY  = 4,
    EVT_DNS_QUERY        = 5,
    EVT_PRIV_ESC         = 6,
    EVT_TCP_CONN         = 7,
};

#endif /* __COMMON_H */
