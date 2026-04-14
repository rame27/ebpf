// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * tcp_tracker.bpf.c - TCP Connection Tracker (eBPF kernel program)
 *
 * Attaches to:
 *   kprobe/tcp_connect         – outbound connect (SYN sent)
 *   kretprobe/inet_csk_accept  – inbound accept (connection accepted)
 *   kprobe/tcp_close           – connection close
 *   tracepoint/tcp/tcp_retransmit_skb – retransmission events
 *
 * For each TCP event, the relevant 4-tuple (saddr:sport→daddr:dport) is
 * used as the key in tcp_conns LRU hash map to track start time, bytes
 * (approximated via sk_wmem_alloc/sk_rmem_alloc) and retransmit count.
 *
 * On close, a tcp_event with duration_ns is emitted.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#include "helpers.h"
#include "events.h"

/* ── Helper: build a tcp_conn_key from a sock ────────────────────────── */

static __always_inline void sock_to_key(struct sock *sk,
                                         struct tcp_conn_key *key)
{
    key->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key->sport = BPF_CORE_READ(sk, __sk_common.skc_num);   /* host order */
    key->dport = bpf_ntohs(
        BPF_CORE_READ(sk, __sk_common.skc_dport));
}

/* ── Helper: emit tcp_event to ring buffer ───────────────────────────── */

static __always_inline void emit_tcp_event(struct sock *sk,
                                            enum tcp_evt_type evt,
                                            struct tcp_conn_val *val)
{
    struct tcp_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return;

    fill_proc_ctx(&e->proc);

    struct tcp_conn_key key = {};
    sock_to_key(sk, &key);

    e->saddr     = key.saddr;
    e->daddr     = key.daddr;
    e->sport     = key.sport;
    e->dport     = key.dport;
    e->tcp_evt   = evt;
    e->tcp_state = BPF_CORE_READ(sk, __sk_common.skc_state);

    if (val) {
        __u64 now       = bpf_ktime_get_ns();
        e->duration_ns  = now - val->start_ns;
        e->bytes_sent   = val->bytes_sent;
        e->bytes_recv   = val->bytes_recv;
        e->retrans      = val->retrans;
    } else {
        e->duration_ns = 0;
        e->bytes_sent  = 0;
        e->bytes_recv  = 0;
        e->retrans     = 0;
    }
    e->_pad = 0;

    bpf_ringbuf_submit(e, 0);
}

/* ── tcp_connect: outbound SYN ───────────────────────────────────────── */

SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    struct tcp_conn_key key = {};
    sock_to_key(sk, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct tcp_conn_val val = {
        .start_ns   = bpf_ktime_get_ns(),
        .bytes_sent = 0,
        .bytes_recv = 0,
        .retrans    = 0,
        .pid        = (__u32)(pid_tgid & 0xFFFFFFFF),
        .tgid       = (__u32)(pid_tgid >> 32),
    };
    bpf_get_current_comm(&val.comm, sizeof(val.comm));

    bpf_map_update_elem(&tcp_conns, &key, &val, BPF_ANY);

    emit_tcp_event(sk, TCP_EVT_CONNECT, NULL);
    return 0;
}

/* ── inet_csk_accept: inbound accept ────────────────────────────────── */

SEC("kretprobe/inet_csk_accept")
int kretprobe_inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk)
        return 0;

    struct tcp_conn_key key = {};
    sock_to_key(sk, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct tcp_conn_val val = {
        .start_ns   = bpf_ktime_get_ns(),
        .bytes_sent = 0,
        .bytes_recv = 0,
        .retrans    = 0,
        .pid        = (__u32)(pid_tgid & 0xFFFFFFFF),
        .tgid       = (__u32)(pid_tgid >> 32),
    };
    bpf_get_current_comm(&val.comm, sizeof(val.comm));

    bpf_map_update_elem(&tcp_conns, &key, &val, BPF_ANY);

    emit_tcp_event(sk, TCP_EVT_ACCEPT, NULL);
    return 0;
}

/* ── tcp_close: connection close ─────────────────────────────────────── */

SEC("kprobe/tcp_close")
int kprobe_tcp_close(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    struct tcp_conn_key key = {};
    sock_to_key(sk, &key);

    struct tcp_conn_val *val = bpf_map_lookup_elem(&tcp_conns, &key);
    if (val) {
        val->bytes_sent = 0;
        val->bytes_recv = 0;
    }

    emit_tcp_event(sk, TCP_EVT_CLOSE, val);

    if (val)
        bpf_map_delete_elem(&tcp_conns, &key);

    return 0;
}

/* ── tcp_retransmit_skb tracepoint ───────────────────────────────────── */

struct tcp_retransmit_args {
    __u64 __pad;
    const void *skbaddr;
    const void *skaddr;
    int  state;
    __u16 sport;
    __u16 dport;
    __u8  saddr[4];
    __u8  daddr[4];
};

SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit(struct tcp_retransmit_args *ctx)
{
    struct tcp_conn_key key = {};
    __builtin_memcpy(&key.saddr, ctx->saddr, 4);
    __builtin_memcpy(&key.daddr, ctx->daddr, 4);
    key.sport = ctx->sport;
    key.dport = ctx->dport;

    struct tcp_conn_val *val = bpf_map_lookup_elem(&tcp_conns, &key);
    if (val)
        val->retrans++;

    /* Emit retrans event */
    struct tcp_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_proc_ctx(&e->proc);
    e->saddr     = key.saddr;
    e->daddr     = key.daddr;
    e->sport     = key.sport;
    e->dport     = key.dport;
    e->tcp_evt   = TCP_EVT_RETRANS;
    e->tcp_state = ctx->state;
    e->duration_ns = 0;
    e->bytes_sent  = 0;
    e->bytes_recv  = 0;
    e->retrans     = val ? val->retrans : 1;
    e->_pad        = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
