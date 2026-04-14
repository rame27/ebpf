// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * priv_esc_user.c - Userspace loader for the Privilege Escalation Detector.
 *
 * Usage:
 *   sudo ./priv_esc
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

static const char *esc_type_name(unsigned int t)
{
    switch (t) {
    case PRIV_SETUID:   return "setuid_to_root";
    case PRIV_SETGID:   return "setgid_to_root";
    case PRIV_CAP_SET:  return "capability_gain";
    case PRIV_NS_ENTER: return "namespace_enter";
    default:            return "unknown";
    }
}

/* Decode Linux capability bits into a comma-separated string */
static void caps_to_str(unsigned long long caps, char *buf, size_t len)
{
    static const char *cap_names[] = {
        "CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_DAC_READ_SEARCH",
        "CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_SETGID",
        "CAP_SETUID","CAP_SETPCAP","CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE","CAP_NET_BROADCAST","CAP_NET_ADMIN",
        "CAP_NET_RAW","CAP_IPC_LOCK","CAP_IPC_OWNER","CAP_SYS_MODULE",
        "CAP_SYS_RAWIO","CAP_SYS_CHROOT","CAP_SYS_PTRACE","CAP_SYS_PACCT",
        "CAP_SYS_ADMIN","CAP_SYS_BOOT","CAP_SYS_NICE","CAP_SYS_RESOURCE",
        "CAP_SYS_TIME","CAP_SYS_TTY_CONFIG","CAP_MKNOD","CAP_LEASE",
        "CAP_AUDIT_WRITE","CAP_AUDIT_CONTROL","CAP_SETFCAP",
        "CAP_MAC_OVERRIDE","CAP_MAC_ADMIN","CAP_SYSLOG","CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND","CAP_AUDIT_READ","CAP_PERFMON","CAP_BPF",
        "CAP_CHECKPOINT_RESTORE",
    };
    size_t pos = 0;
    buf[0] = '\0';
    for (int i = 0; i < 41 && i < 64; i++) {
        if (!(caps & (1ULL << i))) continue;
        if (pos > 0 && pos < len - 1) buf[pos++] = ',';
        size_t name_len = strlen(cap_names[i]);
        if (pos + name_len >= len) break;
        memcpy(buf + pos, cap_names[i], name_len);
        pos += name_len;
    }
    buf[pos] = '\0';
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct priv_esc_event))
        return 0;

    const struct priv_esc_event *e = data;
    char old_caps[512], new_caps[512];
    caps_to_str(e->old_caps, old_caps, sizeof(old_caps));
    caps_to_str(e->new_caps, new_caps, sizeof(new_caps));

    printf("{"
           "\"event\":\"priv_esc\","
           "\"ts_ns\":%llu,"
           "\"pid\":%u,"
           "\"tgid\":%u,"
           "\"uid\":%u,"
           "\"comm\":\"%s\","
           "\"esc_type\":\"%s\","
           "\"old_uid\":%u,"
           "\"new_uid\":%u,"
           "\"old_gid\":%u,"
           "\"new_gid\":%u,"
           "\"old_caps\":\"%s\","
           "\"new_caps\":\"%s\""
           "}\n",
           (unsigned long long)e->proc.ts_ns,
           e->proc.pid, e->proc.tgid, e->proc.uid, e->proc.comm,
           esc_type_name(e->esc_type),
           e->old_uid, e->new_uid,
           e->old_gid, e->new_gid,
           old_caps, new_caps);
    fflush(stdout);
    return 0;
}

int main(void)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct bpf_object *obj = bpf_object__open("priv_esc.bpf.o");
    if (!obj) {
        fprintf(stderr, "bpf_object__open: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    /* Attach all programs in the object */
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
            "priv_esc: monitoring privilege escalation — Ctrl-C to stop\n");

    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    fprintf(stderr, "\npriv_esc: stopped.\n");
    return EXIT_SUCCESS;
}
