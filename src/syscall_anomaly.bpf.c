// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * syscall_anomaly.bpf.c - Syscall Anomaly Detector (eBPF kernel program)
 *
 * Attaches to:
 *   raw_tracepoint/sys_enter  - fires on every syscall entry
 *
 * Mechanism:
 *   1. Per-(pid, syscall_nr) counter incremented on every invocation.
 *   2. A sliding window is approximated by sampling: if the counter
 *      exceeds the HIGH_THRESHOLD within a short wall-clock window,
 *      an anomaly event is emitted.
 *   3. The anomaly score (0-100) is proportional to how much the count
 *      exceeds the threshold.
 *
 * This is an in-kernel heuristic.  Production systems would pair this
 * with userspace ML baselines, but the BPF layer provides zero-copy
 * pre-filtering to keep overhead minimal.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "maps.h"
#include "helpers.h"
#include "events.h"

/* ── Tuning constants ────────────────────────────────────────────────── */

#define WINDOW_NS        (1000000000ULL)   /* 1-second evaluation window  */
#define HIGH_THRESHOLD   200               /* syscalls/sec to flag        */
#define SCORE_CAP        100

/* Per-PID per-syscall window state */
struct window_state {
    __u64 window_start_ns;
    __u64 count;
};

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key,         struct syscall_key);
    __type(value,       struct window_state);
} syscall_windows SEC(".maps");

/* ── Raw tracepoint: sys_enter ───────────────────────────────────────── */

SEC("raw_tracepoint/sys_enter")
int detect_syscall_anomaly(struct bpf_raw_tracepoint_args *ctx)
{
    /* ctx->args[1] = syscall number on x86-64 */
    unsigned long syscall_nr = ctx->args[1];
    __u64 now = bpf_ktime_get_ns();

    __u64 id  = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(id & 0xFFFFFFFF);

    struct syscall_key key = {
        .pid        = pid,
        .syscall_nr = (__u32)syscall_nr,
    };

    struct window_state *ws = bpf_map_lookup_elem(&syscall_windows, &key);
    if (!ws) {
        struct window_state init = {
            .window_start_ns = now,
            .count           = 1,
        };
        bpf_map_update_elem(&syscall_windows, &key, &init, BPF_ANY);
        return 0;
    }

    /* Reset window if expired */
    if (now - ws->window_start_ns >= WINDOW_NS) {
        ws->window_start_ns = now;
        ws->count           = 1;
        return 0;
    }

    ws->count++;

    /* Emit event only when crossing threshold */
    if (ws->count != HIGH_THRESHOLD)
        return 0;

    struct syscall_event *e =
        bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_proc_ctx(&e->proc);
    e->syscall_nr    = syscall_nr;
    e->count         = (__u32)ws->count;

    /* Score: linearly mapped; cap at SCORE_CAP */
    __u64 excess     = ws->count - HIGH_THRESHOLD;
    __u64 score      = (excess * SCORE_CAP) / HIGH_THRESHOLD;
    e->anomaly_score = score > SCORE_CAP ? SCORE_CAP : (__u32)score;

    /* Capture first three syscall args from pt_regs */
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    e->args[0] = BPF_CORE_READ(regs, di);
    e->args[1] = BPF_CORE_READ(regs, si);
    e->args[2] = BPF_CORE_READ(regs, dx);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
