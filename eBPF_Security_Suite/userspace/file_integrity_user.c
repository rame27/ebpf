// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * file_integrity_user.c - Userspace loader for the File Integrity Monitor.
 *
 * Before attaching the BPF program, this loader populates the
 * `watched_paths` BPF map with paths supplied via CLI arguments.
 * It then polls the ring buffer and emits JSON events.
 *
 * Usage:
 *   sudo ./file_integrity /etc /var/log /usr/bin
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
#include "../include/common.h"

static volatile int running = 1;
static void sig_handler(int sig) { (void)sig; running = 0; }

static const char *op_name(unsigned int op)
{
    switch (op) {
    case FILE_OP_OPEN:   return "open";
    case FILE_OP_WRITE:  return "write";
    case FILE_OP_UNLINK: return "unlink";
    case FILE_OP_RENAME: return "rename";
    case FILE_OP_CHMOD:  return "chmod";
    default:             return "unknown";
    }
}

static void json_escape(const char *src, char *dst, size_t len)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < len; i++) {
        if (src[i] == '"' || src[i] == '\\') dst[j++] = '\\';
        dst[j++] = src[i];
    }
    dst[j] = '\0';
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct file_event))
        return 0;

    const struct file_event *e = data;
    char path[MAX_FILENAME * 2], new_path[MAX_FILENAME * 2];
    json_escape(e->path,     path,     sizeof(path));
    json_escape(e->new_path, new_path, sizeof(new_path));

    printf("{"
           "\"event\":\"file_integrity\","
           "\"ts_ns\":%llu,"
           "\"pid\":%u,"
           "\"tgid\":%u,"
           "\"uid\":%u,"
           "\"comm\":\"%s\","
           "\"op\":\"%s\","
           "\"path\":\"%s\","
           "\"new_path\":\"%s\","
           "\"ret\":%d"
           "}\n",
           (unsigned long long)e->proc.ts_ns,
           e->proc.pid, e->proc.tgid, e->proc.uid, e->proc.comm,
           op_name(e->op), path, new_path, e->ret);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <path1> [path2 ...]\n"
                "  e.g. %s /etc /var/log\n",
                argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct bpf_object *obj = bpf_object__open("file_integrity.bpf.o");
    if (!obj) {
        fprintf(stderr, "bpf_object__open: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    /* Populate watched_paths map */
    int paths_fd = bpf_object__find_map_fd_by_name(obj, "watched_paths");
    if (paths_fd < 0) {
        fprintf(stderr, "Map 'watched_paths' not found\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; i++) {
        char key[MAX_FILENAME] = {};
        strncpy(key, argv[i], MAX_FILENAME - 1);
        unsigned char val = 1;
        if (bpf_map_update_elem(paths_fd, key, &val, BPF_ANY) < 0)
            fprintf(stderr, "Warning: could not add '%s' to watched_paths\n",
                    argv[i]);
        else
            fprintf(stderr, "Watching path: %s\n", argv[i]);
    }

    /* Attach all programs */
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

    fprintf(stderr, "file_integrity: monitoring %d path(s) — Ctrl-C to stop\n",
            argc - 1);

    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    fprintf(stderr, "\nfile_integrity: stopped.\n");
    return EXIT_SUCCESS;
}
