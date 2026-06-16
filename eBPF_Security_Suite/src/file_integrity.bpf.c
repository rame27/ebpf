// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * file_integrity.bpf.c - File Integrity Monitor (eBPF kernel program)
 *
 * Attaches to:
 *   tracepoint/syscalls/sys_enter_openat   - file open
 *   tracepoint/syscalls/sys_exit_openat    - capture return value
 *   tracepoint/syscalls/sys_enter_unlinkat - file delete
 *   tracepoint/syscalls/sys_enter_renameat2- file rename
 *   kprobe/vfs_write                       - file write
 *   kprobe/security_inode_setattr          - chmod/chown
 *
 * The watched_paths BPF hash map is pre-populated by userspace with
 * the directory/file prefixes to monitor.  Only events touching a
 * watched path are emitted to the ring buffer.
 *
 * Design note:
 *   Path matching in BPF is necessarily simple (prefix byte compare).
 *   For production use, combine with LSM hooks for richer policy.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "maps.h"
#include "helpers.h"
#include "events.h"

/* ── Helper: check if path starts with any watched prefix ───────────── */

static __always_inline int is_watched(const char *path, int len)
{
    /* Watched paths map uses full key – simple exact lookup.
     * For prefix matching, userspace normalises paths before inserting. */
    __u8 *val = bpf_map_lookup_elem(&watched_paths, path);
    return val != NULL;
}

/* ── openat entry: capture path ─────────────────────────────────────── */

struct openat_enter_args {
    __u64 __pad;
    int   __syscall_nr;
    int   dfd;
    const char __user *filename;
    int   flags;
    short mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct openat_enter_args *ctx)
{
    char path[MAX_FILENAME] = {};
    bpf_probe_read_user_str(path, sizeof(path), ctx->filename);

    if (!is_watched(path, sizeof(path)))
        return 0;

    struct file_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_proc_ctx(&e->proc);
    e->op  = FILE_OP_OPEN;
    e->ret = 0;  /* exit hook not wired here for brevity */
    __builtin_memcpy(e->path, path, MAX_FILENAME);
    __builtin_memset(e->new_path, 0, MAX_FILENAME);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── unlinkat entry: file delete ────────────────────────────────────── */

struct unlinkat_enter_args {
    __u64 __pad;
    int   __syscall_nr;
    int   dfd;
    const char __user *pathname;
    int   flag;
};

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat_enter(struct unlinkat_enter_args *ctx)
{
    char path[MAX_FILENAME] = {};
    bpf_probe_read_user_str(path, sizeof(path), ctx->pathname);

    if (!is_watched(path, sizeof(path)))
        return 0;

    struct file_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_proc_ctx(&e->proc);
    e->op  = FILE_OP_UNLINK;
    e->ret = 0;
    __builtin_memcpy(e->path, path, MAX_FILENAME);
    __builtin_memset(e->new_path, 0, MAX_FILENAME);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── renameat2 entry: file rename ───────────────────────────────────── */

struct renameat2_enter_args {
    __u64 __pad;
    int   __syscall_nr;
    int   olddfd;
    const char __user *oldname;
    int   newdfd;
    const char __user *newname;
    unsigned int flags;
};

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2_enter(struct renameat2_enter_args *ctx)
{
    char old_path[128] = {};

    bpf_probe_read_user_str(old_path, sizeof(old_path), ctx->oldname);

    if (!is_watched(old_path, sizeof(old_path)))
        return 0;

    struct file_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_proc_ctx(&e->proc);
    e->op  = FILE_OP_RENAME;
    e->ret = 0;
    __builtin_memcpy(e->path, old_path, 128);
    __builtin_memset(e->new_path, 0, MAX_FILENAME);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── vfs_write kprobe: detect writes to watched inodes ─────────────── */

SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx)
{
    struct file *filp = (struct file *)PT_REGS_PARM1(ctx);
    char path[MAX_FILENAME] = {};

    /* Read dentry name – not full path but sufficient for many cases */
    struct dentry *dentry = BPF_CORE_READ(filp, f_path.dentry);
    struct qstr   name    = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(path, sizeof(path), name.name);

    if (!is_watched(path, sizeof(path)))
        return 0;

    struct file_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_proc_ctx(&e->proc);
    e->op  = FILE_OP_WRITE;
    e->ret = 0;
    __builtin_memcpy(e->path, path, MAX_FILENAME);
    __builtin_memset(e->new_path, 0, MAX_FILENAME);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── security_inode_setattr: chmod/chown ────────────────────────────── */

SEC("kprobe/security_inode_setattr")
int kprobe_setattr(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM1(ctx);
    char path[MAX_FILENAME] = {};

    struct qstr name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(path, sizeof(path), name.name);

    if (!is_watched(path, sizeof(path)))
        return 0;

    struct file_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_proc_ctx(&e->proc);
    e->op  = FILE_OP_CHMOD;
    e->ret = 0;
    __builtin_memcpy(e->path, path, MAX_FILENAME);
    __builtin_memset(e->new_path, 0, MAX_FILENAME);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
