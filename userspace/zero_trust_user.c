// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * zero_trust_user.c - Zero-Trust Networking Userspace Loader
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "../include/events.h"

static volatile int running = 1;

static void sig_handler(int sig)
{
    running = 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct ring_buffer *rb;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("zero_trust: zero-trust policy enforcement — Ctrl-C to stop\n");

    obj = bpf_object__open("zero_trust.bpf.o");
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    bpf_object__for_each_program(prog, obj) {
        bpf_program__attach(prog);
    }

    rb = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(obj, "events_rb")), NULL, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    while (running) {
        err = ring_buffer__poll(rb, 1000);
        if (err < 0)
            break;
    }

    printf("zero_trust: stopped.\n");
    return 0;
}