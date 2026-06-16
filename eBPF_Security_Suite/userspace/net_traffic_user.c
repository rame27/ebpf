// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * net_traffic_user.c - Userspace loader for the Network Traffic Monitor.
 *
 * Workflow:
 *   1. Load & verify net_traffic.bpf.o via libbpf.
 *   2. Attach BPF programs to TC ingress+egress on the target interface.
 *   3. Poll the ring buffer and print JSON events to stdout.
 *
 * Build dependency: libbpf >= 1.0, iproute2 (for TC qdisc setup).
 *
 * Usage:
 *   sudo ./net_traffic <interface>          # e.g. eth0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <linux/pkt_cls.h>

#include "../include/events.h"

/* ── Graceful shutdown ──────────────────────────────────────────────── */

static volatile int running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* ── JSON helpers ───────────────────────────────────────────────────── */

static void ip_to_str(unsigned int addr, char *buf, size_t len)
{
    struct in_addr ia = { .s_addr = addr };
    snprintf(buf, len, "%s", inet_ntoa(ia));
}

static const char *proto_name(unsigned int proto)
{
    switch (proto) {
    case IPPROTO_TCP:  return "TCP";
    case IPPROTO_UDP:  return "UDP";
    case IPPROTO_ICMP: return "ICMP";
    default:           return "OTHER";
    }
}

/* ── Ring buffer callback ────────────────────────────────────────────── */

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct net_traffic_event))
        return 0;

    const struct net_traffic_event *e = data;
    char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];
    ip_to_str(e->saddr, saddr, sizeof(saddr));
    ip_to_str(e->daddr, daddr, sizeof(daddr));

    printf("{"
           "\"event\":\"net_traffic\","
           "\"ts_ns\":%llu,"
           "\"pid\":%u,"
           "\"tgid\":%u,"
           "\"uid\":%u,"
           "\"comm\":\"%s\","
           "\"direction\":\"%s\","
           "\"proto\":\"%s\","
           "\"src\":\"%s\","
           "\"sport\":%u,"
           "\"dst\":\"%s\","
           "\"dport\":%u,"
           "\"pkt_len\":%u"
           "}\n",
           (unsigned long long)e->proc.ts_ns,
           e->proc.pid, e->proc.tgid, e->proc.uid, e->proc.comm,
           e->direction == NET_INGRESS ? "ingress" : "egress",
           proto_name(e->proto),
           saddr, ntohs(e->sport),
           daddr, ntohs(e->dport),
           e->pkt_len);

    fflush(stdout);
    return 0;
}

/* ── Main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Interface '%s' not found: %s\n",
                iface, strerror(errno));
        return EXIT_FAILURE;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load BPF object */
    struct bpf_object *obj = bpf_object__open("net_traffic.bpf.o");
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    /* Attach TC ingress */
    struct bpf_program *prog_in =
        bpf_object__find_program_by_name(obj, "net_traffic_ingress");
    struct bpf_program *prog_eg =
        bpf_object__find_program_by_name(obj, "net_traffic_egress");

    if (!prog_in || !prog_eg) {
        fprintf(stderr, "Programs not found in BPF object\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    /* Use tc_bpf helpers: create clsact qdisc + attach filters */
    /* In production, prefer bpf_tc_hook_create() / bpf_tc_attach() from
     * libbpf >= 0.6.  Shown here as TC hook API calls. */
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex   = ifindex,
        .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_in,
        .prog_fd = bpf_program__fd(prog_in));
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_eg,
        .prog_fd = bpf_program__fd(prog_eg));

    bpf_tc_hook_create(&hook);   /* ignore EEXIST */

    hook.attach_point = BPF_TC_INGRESS;
    if (bpf_tc_attach(&hook, &opts_in)) {
        fprintf(stderr, "Failed to attach TC ingress: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    hook.attach_point = BPF_TC_EGRESS;
    if (bpf_tc_attach(&hook, &opts_eg)) {
        fprintf(stderr, "Failed to attach TC egress: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    /* Open ring buffer */
    int map_fd = bpf_object__find_map_fd_by_name(obj, "events_rb");
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "net_traffic: monitoring interface '%s' — Ctrl-C to stop\n",
            iface);

    while (running) {
        int err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

    /* Cleanup */
    ring_buffer__free(rb);

    hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
    bpf_tc_hook_destroy(&hook);

    bpf_object__close(obj);
    fprintf(stderr, "\nnet_traffic: stopped.\n");
    return EXIT_SUCCESS;
}
