/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * events.h - All event structures shared between eBPF kernel programs
 *            and their userspace counterparts.
 *
 * Each event carries a `proc_ctx` (pid, comm, ts_ns …) plus feature-
 * specific fields.  The userspace loader serialises these structs to
 * JSON and writes them to stdout.
 *
 * Layout rules
 *   - Every struct must be a multiple of 8 bytes (pad explicitly).
 *   - No pointers – only fixed-size scalars and char arrays.
 *   - Shared between BPF (kernel) and C userspace; no kernel-only types.
 */

#ifndef __EVENTS_H
#define __EVENTS_H

#include "common.h"

/* ═══════════════════════════════════════════════════════════════════════
 * 1. Network Traffic Monitor
 * ═══════════════════════════════════════════════════════════════════════ */

enum net_direction {
    NET_INGRESS = 0,
    NET_EGRESS  = 1,
};

struct net_traffic_event {
    struct proc_ctx proc;
    unsigned int    saddr;          /* IPv4 source      (network byte order) */
    unsigned int    daddr;          /* IPv4 destination (network byte order) */
    unsigned short  sport;          /* source port      (network byte order) */
    unsigned short  dport;          /* destination port (network byte order) */
    unsigned int    proto;          /* IPPROTO_TCP / UDP / ICMP              */
    unsigned int    pkt_len;        /* total packet bytes                    */
    unsigned int    direction;      /* net_direction                         */
    unsigned int    _pad;
};

/* ═══════════════════════════════════════════════════════════════════════
 * 2. Process Execution Tracer
 * ═══════════════════════════════════════════════════════════════════════ */

struct proc_exec_event {
    struct proc_ctx proc;
    unsigned int    ppid;
    unsigned int    _pad;
    char            filename[MAX_FILENAME];
    char            args[MAX_ARGS_SIZE];
};

/* ═══════════════════════════════════════════════════════════════════════
 * 3. File Integrity Monitor
 * ═══════════════════════════════════════════════════════════════════════ */

enum file_op {
    FILE_OP_OPEN   = 0,
    FILE_OP_WRITE  = 1,
    FILE_OP_UNLINK = 2,
    FILE_OP_RENAME = 3,
    FILE_OP_CHMOD  = 4,
};

struct file_event {
    struct proc_ctx proc;
    unsigned int    op;             /* file_op                          */
    int             ret;            /* syscall return value             */
    char            path[MAX_FILENAME];
    char            new_path[MAX_FILENAME]; /* used for rename          */
};

/* ═══════════════════════════════════════════════════════════════════════
 * 4. Syscall Anomaly Detector
 * ═══════════════════════════════════════════════════════════════════════ */

struct syscall_event {
    struct proc_ctx proc;
    unsigned long long syscall_nr;
    unsigned long long args[3];     /* first three syscall arguments    */
    unsigned int    count;          /* times this syscall fired in window */
    unsigned int    anomaly_score;  /* 0–100 heuristic score            */
};

/* ═══════════════════════════════════════════════════════════════════════
 * 5. DNS Query Monitor
 * ═══════════════════════════════════════════════════════════════════════ */

struct dns_event {
    struct proc_ctx proc;
    unsigned int    saddr;
    unsigned int    daddr;
    unsigned short  txid;
    unsigned short  qtype;          /* A=1, AAAA=28, MX=15, TXT=16 …   */
    char            qname[MAX_DNS_NAME];
};

/* ═══════════════════════════════════════════════════════════════════════
 * 6. Privilege Escalation Detector
 * ═══════════════════════════════════════════════════════════════════════ */

enum priv_esc_type {
    PRIV_SETUID   = 0,
    PRIV_SETGID   = 1,
    PRIV_CAP_SET  = 2,
    PRIV_NS_ENTER = 3,
};

struct priv_esc_event {
    struct proc_ctx      proc;
    unsigned int         esc_type;      /* priv_esc_type                */
    unsigned int         old_uid;
    unsigned int         new_uid;
    unsigned int         old_gid;
    unsigned int         new_gid;
    unsigned long long   old_caps;      /* effective capability bitmask */
    unsigned long long   new_caps;
};

/* ═══════════════════════════════════════════════════════════════════════
 * 7. TCP Connection Tracker
 * ═══════════════════════════════════════════════════════════════════════ */

enum tcp_evt_type {
    TCP_EVT_CONNECT  = 0,
    TCP_EVT_ACCEPT   = 1,
    TCP_EVT_CLOSE    = 2,
    TCP_EVT_RETRANS  = 3,
};

struct tcp_event {
    struct proc_ctx proc;
    unsigned int    saddr;
    unsigned int    daddr;
    unsigned short  sport;
    unsigned short  dport;
    unsigned int    tcp_evt;        /* tcp_evt_type                     */
    unsigned int    tcp_state;      /* TCP_ESTABLISHED etc.             */
    unsigned long long duration_ns; /* connection lifetime (on close)   */
    unsigned int    bytes_sent;
    unsigned int    bytes_recv;
    unsigned int    retrans;
    unsigned int    _pad;
};

/* ═══════════════════════════════════════════════════════════════════════
 * 8. Threat Detection
 * ═══════════════════════════════════════════════════════════════════════ */

enum threat_type {
    THREAT_SHELL_SPAWN     = 0,
    THREAT_PRIV_ESC       = 1,
    THREAT_MEMORY_EXEC   = 2,
    THREAT_REVERSE_SHELL = 3,
    THREAT_CRYPTO_MINER  = 4,
    THREAT_EXPLOIT       = 5,
    THREAT_SUSPICIOUS_PORTS = 6,
    THREAT_DATA_EXFIL    = 7,
};

struct threat_event {
    struct proc_ctx proc;
    unsigned int    threat_type;    /* threat_type                     */
    unsigned int    score;          /* 0-100 severity score          */
    unsigned int    pid;
    char            description[128];
};

/* ═══════════════════════════════════════════════════════════════════════
 * 9. Zero-Trust Network Policy
 * ═══════════════════════════════════════════════════════════════════════ */

enum policy_action {
    POLICY_ALLOW      = 0,
    POLICY_DENY       = 1,
    POLICY_LOG        = 2,
    POLICY_QUARANTINE = 3,
};

struct network_policy_event {
    struct proc_ctx proc;
    unsigned int    saddr;
    unsigned int    daddr;
    unsigned short  sport;
    unsigned short  dport;
    unsigned int    proto;
    unsigned int    policy_action;  /* policy_action               */
    unsigned int    rule_id;
    char            policy_name[64];
};

/* ═══════════════════════════════════════════════════════════════════════
 * 10. Infrastructure Health - Netflix/conductor-style
 * ═══════════════════════════════════════════════════════════════════════ */

enum health_status {
    HEALTH_OK       = 0,
    HEALTH_DEGRADED = 1,
    HEALTH_DOWN    = 2,
    HEALTH_UNKNOWN = 3,
};

struct health_check_event {
    struct proc_ctx proc;
    unsigned int    latency_us;
    unsigned int    status;         /* health_status               */
    unsigned int    error_count;
    unsigned int    timeout_count;
    unsigned long  last_success_ns;
    unsigned long  last_failure_ns;
    char            service_name[64];
    char            endpoint[128];
};

/* ═══════════════════════════════════════════════════════════════════════
 * 11. DNS Security - Blocklist/Allowlist
 * ═══════════════════════════════════════════════════════════════════════ */

struct dns_policy_event {
    struct proc_ctx proc;
    unsigned int    saddr;
    unsigned short  qtype;
    unsigned short  action;         /* POLICY_ALLOW/DENY           */
    unsigned int    blocked_cat;    /* malware/phishing/crypto etc  */
    char            qname[MAX_DNS_NAME];
    char            category[32];
};

/* ═══════════════════════════════════════════════════════════════════════
 * 12. Container/Sandbox Escapes
 * ═══════════════════════════════════════════════════════════════════════ */

enum escape_type {
    ESCAPE_NAMESPACE  = 0,
    ESCAPE_CGROUP    = 1,
    ESCAPE_SYSCTL     = 2,
    ESCAPE_DEV       = 3,
    ESCAPE_PROC      = 4,
};

struct escape_event {
    struct proc_ctx proc;
    unsigned int    escape_type;
    unsigned int    indicator;
    char           syscall_name[32];
    unsigned long  arg0;
    unsigned long  arg1;
};

#endif /* __EVENTS_H */
