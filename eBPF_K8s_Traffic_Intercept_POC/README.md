# eBPF K8s Traffic Intercept POC

Intercept Kubernetes pod traffic destined for **chatgpt.com** / **openai.com** and redirect it to a proxy using **eBPF** and **Go**.

## Architecture

```
Pod ──► [TC Egress Hook] ──► eBPF Program ──► Check dst IP:port
                                                     │
                                              ┌──────┴──────┐
                                              ▼              ▼
                                         Match           No Match
                                              │              │
                                     ┌───────┴───────┐      │
                                     ▼               ▼      │
                              Rewrite IP:port    Log event  │
                              → proxy address    to ringbuf │
                                     │              │      │
                                     ▼              ▼      ▼
                               TC_ACT_OK ──► Packet forwarded (rewritten or original)
```

## How It Works

Three layers cooperate:

| Layer | Component | Role |
|-------|-----------|------|
| **eBPF** (kernel) | `bpf/tc_prog.c` | TC egress hook inspects every outgoing packet, matches IP:port against a hash map, rewrites destination + recomputes checksums, logs events via ring buffer |
| **Go** (userspace) | `main.go` | Loads eBPF program, resolves `chatgpt.com`/`openai.com` IPs via DNS every 60s, populates the rewrite map, reads ring buffer events and logs them |
| **K8s** (orchestration) | `deploy/daemonset.yaml` | DaemonSet runs on every node with `hostNetwork: true`, privileged access, and `CAP_BPF`/`CAP_NET_ADMIN` capabilities |

### Domain Detection Strategy

Rather than expensive deep packet inspection (DPI) inside eBPF, the Go agent periodically resolves target domains to IP addresses via DNS and stores them in a BPF hash map. The eBPF program performs a simple O(1) IP:port lookup — this keeps the kernel code minimal and verifier-friendly.

## Project Structure

```
.
├── bpf/
│   ├── tc_prog.c        # eBPF TC egress C program
│   └── vmlinux.h         # Auto-generated kernel type definitions (from BTF)
├── main.go               # Go userspace agent
├── gen.go                # bpf2go code generation directive
├── deploy/
│   ├── daemonset.yaml    # Kubernetes DaemonSet manifest
│   └── Dockerfile        # Multi-stage container build
├── Makefile              # Build automation
├── go.mod / go.sum       # Go module dependencies
└── README.md
```

## Prerequisites

- **Go 1.24+** (for cilium/ebpf dependency)
- **clang + llvm** (for compiling C → BPF bytecode)
- **Linux kernel 6.6+** with BPF support and TCX hook (or 5.x with legacy fallback)
- **root access** (required for loading eBPF programs)
- **libbpf-dev** (for BPF helper headers)
- **bpftool** (generates `vmlinux.h` from kernel BTF)

## Quick Start

```bash
# 1. Generate BTF type definitions
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# 2. Generate eBPF Go scaffolding (compiles C → BPF → Go)
make generate

# 3. Build the agent binary
make build

# 4. Run (requires root)
sudo ./ebpf-agent
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EBPF_IFACE` | `eth0` | Network interface to attach TC program to |
| `PROXY_IP` | `10.0.0.50` | Target proxy IP for rewritten traffic |
| `PROXY_PORT` | `8080` | Target proxy port |

## Output

The agent logs all traffic events. When a match is found:

```
[ebpf-agent] 2026/06/10 [REDIRECT] 10.42.0.5 -> 104.18.2.161:443  =>  10.0.0.50:8080 (was going to 104.18.2.161:443)
```

- `src` = originating pod IP
- `orig_dst:orig_port` = where the packet was originally heading
- `new_dst:new_port` = where it was redirected (the proxy)

Non-matching traffic also logs:

```
[ebpf-agent] 2026/06/10 [PASS] 10.42.0.5 -> 142.250.80.46:443 (no match)
```

## Kubernetes Deployment

```bash
# Build the container image
make docker

# Load into your cluster (kind / minikube)
kind load docker-image ebpf-agent:latest
# or
minikube image load ebpf-agent:latest

# Deploy
kubectl apply -f deploy/daemonset.yaml
```

The DaemonSet runs with:
- `hostNetwork: true` — access node network interfaces
- `privileged: true` — required for `bpf()` syscall
- `seccomp: Unconfined` — BPF syscall filtering
- `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE`
- Tolerations for all nodes (system-node-critical priority)

## Design Decisions

1. **TC egress vs ingress**: Egress hooks outgoing traffic where outbound connections to chatgpt.com/openai.com are visible. Ingress would see response traffic with reversed IPs.

2. **Direct packet access** (`data`/`data_end` pointers): Faster than `bpf_skb_load_bytes`, with explicit bounds checks to pass the verifier.

3. **DNS-based IP resolution**: The Go agent resolves domains → IPs periodically. Production should also intercept DNS events for real-time discovery of new IPs.

4. **Hash map for rules**: O(1) lookup for each packet. The map is keyed by `(dst_ip, dst_port, protocol)` — the proxy destination is the value.

5. **Ring buffer for events**: BPF_MAP_TYPE_RINGBUF provides ordered, zero-copy event delivery from kernel to userspace.

6. **vmlinux.h**: Using BTF-generated kernel headers avoids fragile kernel header dependencies and clang compatibility issues.

## Production Considerations

- [ ] Dynamic DNS interception (intercept DNS responses for domain→IP mapping)
- [ ] IPv6 support
- [ ] TLS SNI inspection for domain matching (requires more complex eBPF)
- [ ] Health checks and metrics (Prometheus endpoints)
- [ ] Graceful map cleanup on agent restart
- [ ] eBPF CO-RE (Compile Once, Run Everywhere) with BTF relocation
- [ ] Proper CNI integration instead of DaemonSet-level interception
