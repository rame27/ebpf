// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * net_traffic.bpf.c - Network Traffic Monitor (eBPF kernel program)
 *
 * Attaches to:
 *   TC (Traffic Control) ingress/egress hooks on a target interface.
 *
 * For each IPv4 packet it emits a net_traffic_event to the ring buffer
 * containing: process context, src/dst IP+port, protocol, packet length,
 * and direction.
 *
 * Notes:
 *   - IPv6 packets are noted but not decoded in detail (extend as needed).
 *   - The prog is a BPF_PROG_TYPE_SCHED_CLS (tc filter); direction is
 *     determined by the section name chosen at load time.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#include "helpers.h"
#include "events.h"

/* ── Ethernet + IPv4 + TCP/UDP header offsets ────────────────────────── */

#define ETH_HLEN_BYTES  14
#define IP_PROTO_OFF    (ETH_HLEN_BYTES + 9)
#define IP_SRC_OFF      (ETH_HLEN_BYTES + 12)
#define IP_DST_OFF      (ETH_HLEN_BYTES + 16)
#define IP_IHL_OFF      ETH_HLEN_BYTES          /* IHL is in low nibble   */

/* ── Helper: parse packet and emit event ────────────────────────────── */

static __always_inline int handle_packet(struct __sk_buff *skb,
                                          enum net_direction dir)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Bounds check: Ethernet header */
    if (data + ETH_HLEN_BYTES > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    /* Bounds check: IP header (minimum 20 bytes) */
    struct iphdr *ip = data + ETH_HLEN_BYTES;
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u8  ihl    = (ip->ihl & 0x0F) * 4;
    __u8  proto  = ip->protocol;
    __u32 saddr  = ip->saddr;
    __u32 daddr  = ip->daddr;
    __u16 sport  = 0, dport = 0;

    /* Extract ports for TCP/UDP */
    void *l4 = (void *)ip + ihl;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        sport = tcp->source;
        dport = tcp->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        sport = udp->source;
        dport = udp->dest;
    }

    /* Reserve ring buffer slot */
    struct net_traffic_event *e =
        bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

    fill_proc_ctx(&e->proc);
    e->saddr     = saddr;
    e->daddr     = daddr;
    e->sport     = sport;
    e->dport     = dport;
    e->proto     = proto;
    e->pkt_len   = skb->len;
    e->direction = dir;
    e->_pad      = 0;

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}

/* ── TC hooks ────────────────────────────────────────────────────────── */

SEC("tc/ingress")
int net_traffic_ingress(struct __sk_buff *skb)
{
    return handle_packet(skb, NET_INGRESS);
}

SEC("tc/egress")
int net_traffic_egress(struct __sk_buff *skb)
{
    return handle_packet(skb, NET_EGRESS);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
