/* SPDX-License-Identifier: GPL-2.0 */
/* eBPF TC egress program for Kubernetes pod traffic interception.
 *
 * Intercepts outgoing packets, checks destination IP:port against
 * a hash map of known chatgpt.com / openai.com IPs, and rewrites
 * the destination to a proxy address.
 *
 * Logs original and final destinations via ring buffer.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

/* TC action codes (from linux/pkt_cls.h) */
#ifndef TC_ACT_OK
#define TC_ACT_OK        0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT      2
#endif
#ifndef TC_ACT_REDIRECT
#define TC_ACT_REDIRECT  7
#endif
#ifndef ETH_P_IP
#define ETH_P_IP         0x0800
#endif

/* ---------- Map: Rewrite rules (populated from userspace) ---------- */

struct rewrite_key {
    __u32 dst_ip;      /* original dest IP (network byte order) */
    __u16 dst_port;    /* original dest port (network byte order) */
    __u8  protocol;    /* IPPROTO_TCP (6) or IPPROTO_UDP (17) */
    __u8  _pad;
} __attribute__((packed));

struct rewrite_val {
    __u32 new_dst_ip;   /* proxy IP (network byte order) */
    __u16 new_dst_port; /* proxy port (network byte order) */
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rewrite_key);
    __type(value, struct rewrite_val);
} rewrite_rules SEC(".maps");

/* ---------- Map: Connection tracking (optional, for observability) ---------- */

struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key);
    __type(value, __u64); /* packet count */
} connections SEC(".maps");

/* ---------- Map: Event ring buffer for logging ---------- */

struct event {
    __u32 src_ip;          /* original source IP */
    __u32 orig_dst_ip;     /* original destination IP */
    __u32 new_dst_ip;      /* rewritten destination IP (0 if no match) */
    __u16 orig_dst_port;   /* original destination port */
    __u16 new_dst_port;    /* rewritten destination port (0 if no match) */
    __u8  protocol;        /* IPPROTO_TCP / IPPROTO_UDP */
    __u8  matched;         /* 1 = redirected, 0 = passed through */
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); /* 64 KB ring buffer */
} events SEC(".maps");

/* ---------- Helper: rewrite destination IP and port ---------- */

static __always_inline int
rewrite_dest(struct __sk_buff *skb,
             __u32 new_dst_ip,
             __u16 new_dst_port,
             __u32 ip_hdr_off,
             __u32 l4_hdr_off)
{
    /* Rewrite destination IP (offset 16 in IP header) */
    if (bpf_skb_store_bytes(skb, ip_hdr_off + 16, &new_dst_ip,
                            sizeof(new_dst_ip), BPF_F_RECOMPUTE_CSUM) < 0)
        return -1;

    /* Rewrite destination port (offset 2 in TCP/UDP header) */
    if (bpf_skb_store_bytes(skb, l4_hdr_off + 2, &new_dst_port,
                            sizeof(new_dst_port), BPF_F_RECOMPUTE_CSUM) < 0)
        return -1;

    return 0;
}

/* ---------- Main TC egress handler ---------- */

SEC("tc")
int tc_egress_handler(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long)skb->data_end;
    void *data     = (void *)(unsigned long)skb->data;
    struct ethhdr *eth;
    struct iphdr  *ip;
    __u32 ip_hdr_off, l4_hdr_off;
    __u16 dest_port;
    struct rewrite_key key = {};

    /* ---- Parse Ethernet header ---- */
    eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    /* Only IPv4 */
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    /* ---- Parse IP header ---- */
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    ip_hdr_off = (__u32)((void *)ip - (void *)eth);

    /* Only TCP or UDP */
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    l4_hdr_off = ip_hdr_off + (ip->ihl * 4);

    /* ---- Parse L4 header ---- */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        dest_port = tcp->dest;
    } else {
        struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        dest_port = udp->dest;
    }

    /* ---- Look up rewrite rule ---- */
    key.dst_ip   = ip->daddr;
    key.dst_port = dest_port;
    key.protocol = ip->protocol;

    struct rewrite_val *rule = bpf_map_lookup_elem(&rewrite_rules, &key);

    /* ---- Prepare log event (always log, matched or not) ---- */
    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (evt) {
        evt->src_ip        = ip->saddr;
        evt->orig_dst_ip   = ip->daddr;
        evt->orig_dst_port = dest_port;
        evt->protocol      = ip->protocol;

        if (rule) {
            /* Apply rewrite */
            if (rewrite_dest(skb, rule->new_dst_ip, rule->new_dst_port,
                             ip_hdr_off, l4_hdr_off) == 0) {
                evt->new_dst_ip   = rule->new_dst_ip;
                evt->new_dst_port = rule->new_dst_port;
                evt->matched      = 1;
            }
        }

        bpf_ringbuf_submit(evt, 0);
    }

    /* ---- Track connection in LRU ---- */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        struct conn_key ck = {
            .src_ip   = ip->saddr,
            .dst_ip   = ip->daddr,
            .src_port = tcp->source,
            .dst_port = dest_port,
            .protocol = ip->protocol,
        };
        __u64 *count = bpf_map_lookup_elem(&connections, &ck);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            __u64 one = 1;
            bpf_map_update_elem(&connections, &ck, &one, BPF_ANY);
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
