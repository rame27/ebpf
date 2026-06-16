// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * proc_exec.bpf.c - Process Execution Tracer (eBPF kernel program)
 *
 * Attaches to:
 *   tracepoint/syscalls/sys_enter_execve
 *   tracepoint/syscalls/sys_exit_execve
 *
 * On execve entry, captures:
 *   - PID/TGID/UID/comm of the calling process
 *   - Parent PID
 *   - Full pathname of the executed binary
 *   - First 256 bytes of concatenated argv
 *
 * A per-CPU scratch map is used to avoid large stack allocations,
 * which the BPF verifier would reject.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "maps.h"
#include "helpers.h"
#include "events.h"

/* ── Tracepoint context structs ─────────────────────────────────────── */

struct execve_entry_args {
    __u64  __pad;            /* unused - common tracepoint fields     */
    int    __syscall_nr;
    const char __user *filename;
    const char __user *const __user *argv;
    const char __user *const __user *envp;
};

/* ── Entry hook: capture filename + argv ────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct execve_entry_args *ctx)
{
    __u32 key = 0;
    struct proc_exec_event *e =
        bpf_map_lookup_elem(&exec_scratch, &key);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_proc_ctx(&e->proc);

    /* Parent PID via task_struct */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    /* Executable path */
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), ctx->filename);

    /* Concatenate first few argv entries */
    const char __user *argp = NULL;
    int pos = 0;

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (bpf_probe_read_user(&argp, sizeof(argp),
                                 &ctx->argv[i]) || !argp)
            break;

        int remaining = MAX_ARGS_SIZE - pos - 1;
        if (remaining <= 0)
            break;

        int len = bpf_probe_read_user_str(e->args + pos,
                                           remaining, argp);
        if (len <= 1)
            break;

        pos += len - 1;   /* overwrite NUL with space separator */
        if (pos < MAX_ARGS_SIZE - 1)
            e->args[pos++] = ' ';
    }
    if (pos > 0 && pos < MAX_ARGS_SIZE)
        e->args[pos] = '\0';

    /* Submit to ring buffer */
    struct proc_exec_event *out =
        bpf_ringbuf_reserve(&events_rb, sizeof(*out), 0);
    if (!out)
        return 0;

    __builtin_memcpy(out, e, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
