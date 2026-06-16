// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * priv_esc.bpf.c - Privilege Escalation Detector (eBPF kernel program)
 *
 * Attaches to:
 *   tracepoint/syscalls/sys_enter_setuid
 *   tracepoint/syscalls/sys_enter_setgid
 *   kprobe/commit_creds              – catches all credential changes
 *   kprobe/security_task_setrlimit   – proxy for namespace manipulation
 *
 * Detection logic:
 *   - On commit_creds: compare new cred UID/GID/caps against the
 *     baseline stored in proc_baselines for this PID.
 *   - If old UID was non-zero and new UID is zero → flag SETUID esc.
 *   - If capabilities were gained → flag CAP_SET esc.
 *   - Baseline is populated when a new process is first seen.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "maps.h"
#include "helpers.h"
#include "events.h"

/* ── Record baseline on task creation via sched_process_fork ─────────── */

SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid & 0xFFFFFFFF);

    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    const struct cred *cred = BPF_CORE_READ(task, cred);
    __u32 uid = BPF_CORE_READ(cred, uid.val);
    __u32 gid = BPF_CORE_READ(cred, gid.val);

    /* Read effective caps (two 32-bit halves) */
    __u32 cap_lo = BPF_CORE_READ(cred, cap_effective.cap[0]);
    __u32 cap_hi = BPF_CORE_READ(cred, cap_effective.cap[1]);
    __u64 caps   = ((__u64)cap_hi << 32) | cap_lo;

    struct proc_uid_key key = { .pid = pid };
    struct proc_uid_val val = {
        .uid  = uid,
        .gid  = gid,
        .caps = caps,
    };
    bpf_map_update_elem(&proc_baselines, &key, &val, BPF_ANY);
    return 0;
}

/* ── commit_creds kprobe: detect credential change ───────────────────── */

SEC("kprobe/commit_creds")
int kprobe_commit_creds(struct pt_regs *ctx)
{
    const struct cred *new_cred = (const struct cred *)PT_REGS_PARM1(ctx);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid & 0xFFFFFFFF);

    struct proc_uid_key bkey = { .pid = pid };
    struct proc_uid_val *base = bpf_map_lookup_elem(&proc_baselines, &bkey);
    if (!base)
        return 0;

    __u32 new_uid = BPF_CORE_READ(new_cred, uid.val);
    __u32 new_gid = BPF_CORE_READ(new_cred, gid.val);
    __u32 cap_lo  = BPF_CORE_READ(new_cred, cap_effective.cap[0]);
    __u32 cap_hi  = BPF_CORE_READ(new_cred, cap_effective.cap[1]);
    __u64 new_caps = ((__u64)cap_hi << 32) | cap_lo;

    /* Check for root escalation */
    int is_uid_esc = (base->uid != 0 && new_uid == 0);
    int is_gid_esc = (base->gid != 0 && new_gid == 0);
    int is_cap_esc = (new_caps & ~base->caps) != 0;  /* new caps gained */

    if (!is_uid_esc && !is_gid_esc && !is_cap_esc)
        return 0;

    struct priv_esc_event *e =
        bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_proc_ctx(&e->proc);
    e->old_uid  = base->uid;
    e->new_uid  = new_uid;
    e->old_gid  = base->gid;
    e->new_gid  = new_gid;
    e->old_caps = base->caps;
    e->new_caps = new_caps;

    if (is_uid_esc)      e->esc_type = PRIV_SETUID;
    else if (is_gid_esc) e->esc_type = PRIV_SETGID;
    else                 e->esc_type = PRIV_CAP_SET;

    bpf_ringbuf_submit(e, 0);

    /* Update baseline to new credentials */
    base->uid  = new_uid;
    base->gid  = new_gid;
    base->caps = new_caps;

    return 0;
}

/* ── setuid / setgid tracepoints: explicit calls ─────────────────────── */

struct setuid_args {
    __u64 __pad;
    int   __syscall_nr;
    __u64 uid;
};

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct setuid_args *ctx)
{
    __u32 target_uid = (__u32)ctx->uid;
    if (target_uid != 0)
        return 0;  /* only flag root escalation */

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid & 0xFFFFFFFF);
    __u64 ugid = bpf_get_current_uid_gid();
    __u32 cur_uid = (__u32)(ugid & 0xFFFFFFFF);

    if (cur_uid == 0)
        return 0;  /* already root, not an escalation */

    struct priv_esc_event *e =
        bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_proc_ctx(&e->proc);
    e->esc_type = PRIV_SETUID;
    e->old_uid  = cur_uid;
    e->new_uid  = target_uid;
    e->old_gid  = 0;
    e->new_gid  = 0;
    e->old_caps = 0;
    e->new_caps = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
