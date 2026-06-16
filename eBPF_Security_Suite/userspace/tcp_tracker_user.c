// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * tcp_tracker_user.c - Userspace loader for the TCP Connection Tracker.
 *
 * Usage:
 *   sudo ./tcp_tracker
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../include/events.h"

static volatile int running = 1;
static void sig_handler(int sig) { (void)sig; running = 0; }

static void ip_to_str(unsigned int addr, char *buf, size_t len)
{
    /* addr is already in host byte order from BPF skc_rcv_saddr */
    struct in_addr ia = { .s_addr = htonl(addr) };
    snprintf(buf, len, "%s", inet_ntoa(ia));
}

static const char *tcp_evt_name(unsigned int evt)
{
    switch (evt) {
    case TCP_EVT_CONNECT: return "connect";
    case TCP_EVT_ACCEPT:  return "accept";
    case TCP_EVT_CLOSE:   return "close";
    case TCP_EVT_RETRANS: return "retransmit";
    default:              return "unknown";
    }
}

/* TCP state names (linux/tcp.h) */
static const char *tcp_state_name(unsigned int state)
{
    static const char *names[] = {
        [1]  = "ESTABLISHED", [2]  = "SYN_SENT",    [3]  = "SYN_RECV",
        [4]  = "FIN_WAIT1",   [5]  = "FIN_WAIT2",   [6]  = "TIME_WAIT",
        [7]  = "CLOSE",       [8]  = "CLOSE_WAIT",  [9]  = "LAST_ACK",
        [10] = "LISTEN",      [11] = "CLOSING",      [12] = "NEW_SYN_RECV",
    };
    if (state < sizeof(names)/sizeof(names[0]) && names[state])
        return names[state];
    return "UNKNOWN";
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct tcp_event))
        return 0;

    const struct tcp_event *e = data;
    char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];
    ip_to_str(e->saddr, saddr, sizeof(saddr));
    ip_to_str(e->daddr, daddr, sizeof(daddr));

    printf("{"
           "\"event\":\"tcp_conn\","
           "\"ts_ns\":%llu,"
           "\"pid\":%u,"
           "\"tgid\":%u,"
           "\"uid\":%u,"
           "\"comm\":\"%s\","
           "\"tcp_evt\":\"%s\","
           "\"tcp_state\":\"%s\","
           "\"src\":\"%s\","
           "\"sport\":%u,"
           "\"dst\":\"%s\","
           "\"dport\":%u,"
           "\"duration_ns\":%llu,"
           "\"bytes_sent\":%u,"
           "\"bytes_recv\":%u,"
           "\"retrans\":%u"
           "}\n",
           (unsigned long long)e->proc.ts_ns,
           e->proc.pid, e->proc.tgid, e->proc.uid, e->proc.comm,
           tcp_evt_name(e->tcp_evt),
           tcp_state_name(e->tcp_state),
           saddr, e->sport,
           daddr, e->dport,
           (unsigned long long)e->duration_ns,
           e->bytes_sent, e->bytes_recv,
           e->retrans);
    fflush(stdout);
    return 0;
}

int main(void)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct bpf_object *obj = bpf_object__open("tcp_tracker.bpf.o");
    if (!obj) {
        fprintf(stderr, "bpf_object__open: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "Failed to attach '%s': %s\n",
                    bpf_program__name(prog), strerror(errno));
            bpf_object__close(obj);
            return EXIT_FAILURE;
        }
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "events_rb");
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    fprintf(stderr,
            "tcp_tracker: tracking TCP connections — Ctrl-C to stop\n");

    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    fprintf(stderr, "\ntcp_tracker: stopped.\n");
    return EXIT_SUCCESS;
}
