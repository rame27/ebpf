// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * syscall_anomaly_user.c - Userspace loader for the Syscall Anomaly Detector.
 *
 * Usage:
 *   sudo ./syscall_anomaly
 *
 * Output: JSON lines on stdout, one per anomaly event.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../include/events.h"

static volatile int running = 1;
static void sig_handler(int sig) { (void)sig; running = 0; }

/* Minimal syscall name table for common x86-64 syscalls */
static const char *syscall_name(__u64 nr)
{
    static const char *names[] = {
        [0]  = "read",      [1]  = "write",    [2]  = "open",
        [3]  = "close",     [4]  = "stat",     [5]  = "fstat",
        [6]  = "lstat",     [7]  = "poll",     [8]  = "lseek",
        [9]  = "mmap",      [10] = "mprotect", [11] = "munmap",
        [12] = "brk",       [20] = "writev",   [39] = "getpid",
        [41] = "socket",    [42] = "connect",  [43] = "accept",
        [44] = "sendto",    [45] = "recvfrom", [56] = "clone",
        [57] = "fork",      [59] = "execve",   [60] = "exit",
        [62] = "kill",      [257]= "openat",
    };
    if (nr < sizeof(names)/sizeof(names[0]) && names[nr])
        return names[nr];
    return "unknown";
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct syscall_event))
        return 0;

    const struct syscall_event *e = data;

    printf("{"
           "\"event\":\"syscall_anomaly\","
           "\"ts_ns\":%llu,"
           "\"pid\":%u,"
           "\"tgid\":%u,"
           "\"uid\":%u,"
           "\"comm\":\"%s\","
           "\"syscall_nr\":%llu,"
           "\"syscall_name\":\"%s\","
           "\"count\":%u,"
           "\"anomaly_score\":%u,"
           "\"arg0\":\"0x%llx\","
           "\"arg1\":\"0x%llx\","
           "\"arg2\":\"0x%llx\""
           "}\n",
           (unsigned long long)e->proc.ts_ns,
           e->proc.pid, e->proc.tgid, e->proc.uid, e->proc.comm,
           (unsigned long long)e->syscall_nr,
           syscall_name(e->syscall_nr),
           e->count,
           e->anomaly_score,
           (unsigned long long)e->args[0],
           (unsigned long long)e->args[1],
           (unsigned long long)e->args[2]);
    fflush(stdout);
    return 0;
}

int main(void)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct bpf_object *obj = bpf_object__open("syscall_anomaly.bpf.o");
    if (!obj) {
        fprintf(stderr, "bpf_object__open: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "detect_syscall_anomaly");
    if (!prog) {
        fprintf(stderr, "Program 'detect_syscall_anomaly' not found\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "events_rb");
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    fprintf(stderr,
            "syscall_anomaly: detecting anomalies (threshold=200/s) — "
            "Ctrl-C to stop\n");

    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    fprintf(stderr, "\nsyscall_anomaly: stopped.\n");
    return EXIT_SUCCESS;
}
