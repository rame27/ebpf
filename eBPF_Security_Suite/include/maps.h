/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * maps.h - BPF map definitions shared across kernel programs.
 *
 * Each feature that needs to share state (e.g. per-socket tracking,
 * syscall counters) declares its maps here so that userspace loaders
 * can pin / inspect them consistently.
 *
 * Included ONLY in .bpf.c kernel programs – not in userspace C files
 * (userspace opens maps by name via bpf_map__fd()).
 */

#ifndef __MAPS_H
#define __MAPS_H

#include <bpf/bpf_helpers.h>
#include "events.h"

/* ── Ring buffer – one shared output channel for all features ──────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE_BYTES);
} events_rb SEC(".maps");

/* ── Per-CPU array for temporary scratch space ─────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct proc_exec_event);
} exec_scratch SEC(".maps");

/* ── TCP connection start-time tracking (socket → ktime_ns) ────────── */

struct tcp_conn_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct tcp_conn_val {
    __u64 start_ns;
    __u32 bytes_sent;
    __u32 bytes_recv;
    __u32 retrans;
    __u32 pid;
    __u32 tgid;
    char  comm[TASK_COMM_LEN];
};

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,         struct tcp_conn_key);
    __type(value,       struct tcp_conn_val);
} tcp_conns SEC(".maps");

/* ── Syscall frequency counters  pid → (syscall_nr → count) ────────── */

struct syscall_key {
    __u32 pid;
    __u32 syscall_nr;
};

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key,         struct syscall_key);
    __type(value,       __u64);
} syscall_counts SEC(".maps");

/* ── Watched file paths (hash set – value unused) ───────────────────── */

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,         char[MAX_FILENAME]);
    __type(value,       __u8);
} watched_paths SEC(".maps");

/* ── Process baseline UIDs for privilege-escalation detection ───────── */

struct proc_uid_key {
    __u32 pid;
};

struct proc_uid_val {
    __u32 uid;
    __u32 gid;
    __u64 caps;
};

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,         struct proc_uid_key);
    __type(value,       struct proc_uid_val);
} proc_baselines SEC(".maps");

/* ── Threat Detection: Suspicious process tracking ─────────────────────── */

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,        __u32);
    __type(value,      __u32);
} suspicious_parents SEC(".maps");

/* ── Zero-Trust: Port allowlist ─────────────────────────────────────── */

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,         __u16);
    __type(value,       __u8);
} port_allowlist SEC(".maps");

/* ── Zero-Trust: Policy rules ─────────────────────────────────────── */

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,         __u32);
    __type(value,       __u32);
} policy_rules SEC(".maps");

/* ── Infrastructure Health: Service tracking ─────────────────────── */

struct service_key {
    __u32 dip;
    __u16 dport;
};

struct service_health {
    __u32 total_reqs;
    __u32 successes;
    __u32 errors;
    __u32 timeouts;
    __u32 circuit_open;
    __u64 lat_sum_us;
    __u64 lat_max_us;
    __u64 last_success_ns;
    __u64 last_failure_ns;
};

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key,         struct service_key);
    __type(value,       struct service_health);
} service_health_map SEC(".maps");

#endif /* __MAPS_H */
