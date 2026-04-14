// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * threat_detect.bpf.c - Threat Detection - XDP stub
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

SEC("xdp")
int filter_threat(struct xdp_md *ctx)
{
    return XDP_PASS;
}

static const char *_LICENSE SEC("license") = "GPL";
static int _VERSION SEC("version") = 1;