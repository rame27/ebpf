// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * dns_monitor.bpf.c - DNS Query Monitor (eBPF kernel program)
 *
 * Attaches to:
 *   socket filter on AF_INET/SOCK_DGRAM  – or –
 *   kprobe/udp_sendmsg                   – intercepts outbound UDP
 *
 * Strategy: Hook udp_sendmsg so we can read the user buffer before it
 * is passed to the kernel network stack, then parse the DNS wire format
 * to extract the query name and type.
 *
 * DNS wire-format parsing (first question section only):
 *   - Skip 12-byte DNS header
 *   - Walk label-encoded QNAME
 *   - Read 2-byte QTYPE
 *
 * We only observe the QUESTION section (queries); response parsing is
 * left as a follow-on exercise.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "maps.h"
#include "helpers.h"
#include "events.h"

/* ── DNS header constants ────────────────────────────────────────────── */

#define DNS_HDR_LEN      12
#define DNS_PORT_NET     __bpf_htons(53)
#define DNS_MAX_LABELS   32

/* ── Parse DNS QNAME from a flat byte buffer ─────────────────────────── */

static __always_inline int parse_qname(const __u8 *buf, int buf_len,
                                        int offset, char *out, int out_len)
{
    int written = 0;

    #pragma unroll
    for (int i = 0; i < DNS_MAX_LABELS; i++) {
        if (offset >= buf_len || offset >= 512)
            break;

        __u8 label_len = 0;
        if (bpf_probe_read_kernel(&label_len, 1, buf + offset))
            break;

        offset++;

        if (label_len == 0)
            break;  /* root label */

        /* Dot separator between labels */
        if (written > 0 && written < out_len - 1)
            out[written++] = '.';

        /* Copy label bytes */
        if (label_len > 63) break;  /* sanity / pointer check */

        #pragma unroll
        for (int j = 0; j < 63; j++) {
            if (j >= label_len) break;
            if (offset >= buf_len || written >= out_len - 1)
                break;

            __u8 c = 0;
            bpf_probe_read_kernel(&c, 1, buf + offset);
            out[written++] = (char)c;
            offset++;
        }
        offset += label_len;  /* will wrap if label_len was not fully walked */
    }

    if (written < out_len)
        out[written] = '\0';

    return offset;
}

/* ── kprobe/udp_sendmsg ──────────────────────────────────────────────── */

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx)
{
    struct sock    *sk  = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr  *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    /* Check destination port == 53 */
    __be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (dport != DNS_PORT_NET)
        return 0;

    /* Read minimum DNS header bytes (12 bytes) */
    __u8 dns_buf[64] = {};
    struct iov_iter *iter = &msg->msg_iter;
    const __u8 __user *ubase = NULL;

    /* Access first iovec base pointer */
    const struct iovec *iov = iter->iov;
    if (bpf_probe_read_kernel(&ubase, sizeof(ubase), &iov->iov_base))
        return 0;

    bpf_probe_read_user(dns_buf, 12, ubase);

    /* Validate minimum DNS message length */
    if (dns_buf[2] & 0x80)   /* QR bit = 1 means response, skip */
        return 0;

    /* Extract transaction ID */
    __u16 txid = ((__u16)dns_buf[0] << 8) | dns_buf[1];

    /* Skip to question section (byte 12) */
    int offset = DNS_HDR_LEN;

    /* Parse QNAME */
    struct dns_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_proc_ctx(&e->proc);
    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->txid  = txid;

    /* Walk QNAME – returns offset pointing past QNAME */
    offset = parse_qname(dns_buf, sizeof(dns_buf),
                          offset, e->qname, MAX_DNS_NAME);

    /* QTYPE: 2 bytes after QNAME */
    if (offset + 2 <= 512) {
        __u16 qtype = ((__u16)dns_buf[offset] << 8) | dns_buf[offset + 1];
        e->qtype = qtype;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
