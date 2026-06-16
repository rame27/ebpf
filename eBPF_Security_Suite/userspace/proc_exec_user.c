// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * proc_exec_user.c - Userspace loader for the Process Execution Tracer.
 *
 * Attaches to tracepoint/syscalls/sys_enter_execve and prints every
 * exec event as a JSON line on stdout.
 *
 * Usage:
 *   sudo ./proc_exec
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

/* Escape double-quotes in strings for safe JSON embedding */
static void json_escape(const char *src, char *dst, size_t dst_len)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < dst_len; i++) {
        if (src[i] == '"' || src[i] == '\\')
            dst[j++] = '\\';
        dst[j++] = src[i];
    }
    dst[j] = '\0';
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct proc_exec_event))
        return 0;

    const struct proc_exec_event *e = data;
    char fname[MAX_FILENAME * 2];
    char args[MAX_ARGS_SIZE * 2];

    json_escape(e->filename, fname, sizeof(fname));
    json_escape(e->args,     args,  sizeof(args));

    printf("{"
           "\"event\":\"proc_exec\","
           "\"ts_ns\":%llu,"
           "\"pid\":%u,"
           "\"tgid\":%u,"
           "\"ppid\":%u,"
           "\"uid\":%u,"
           "\"comm\":\"%s\","
           "\"filename\":\"%s\","
           "\"args\":\"%s\""
           "}\n",
           (unsigned long long)e->proc.ts_ns,
           e->proc.pid, e->proc.tgid, e->ppid, e->proc.uid,
           e->proc.comm, fname, args);
    fflush(stdout);
    return 0;
}

int main(void)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct bpf_object *obj = bpf_object__open("proc_exec.bpf.o");
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "trace_execve_enter");
    if (!prog) {
        fprintf(stderr, "Program 'trace_execve_enter' not found\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach program: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "events_rb");
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "proc_exec: tracing execve — Ctrl-C to stop\n");

    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    fprintf(stderr, "\nproc_exec: stopped.\n");
    return EXIT_SUCCESS;
}
