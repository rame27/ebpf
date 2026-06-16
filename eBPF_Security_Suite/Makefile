# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#
# Makefile — eBPF Security Suite
#
# Targets:
#   make all             Build all BPF objects + userspace loaders
#   make <feature>       Build a single feature (e.g. make net_traffic)
#   make clean           Remove all build artefacts
#   make vmlinux         Generate vmlinux.h from running kernel (needs bpftool)
#
# Requirements:
#   clang >= 12, llvm, libbpf-dev (>= 1.0), linux-headers, bpftool
#
# Directory layout:
#   include/   Shared headers (common.h, events.h, maps.h, helpers.h)
#   src/       eBPF kernel programs  (*.bpf.c  →  *.bpf.o)
#   userspace/ Userspace C loaders   (*_user.c →  bin/<name>)
#   vmlinux.h  BTF-based kernel type header (generated)

# ── Toolchain ──────────────────────────────────────────────────────────
CLANG     ?= clang
LLC       ?= llc
CC        ?= gcc
BPFTOOL   ?= bpftool
STRIP     ?= llvm-strip

ARCH      := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# ── Directories ────────────────────────────────────────────────────────
SRC_DIR   := src
US_DIR    := userspace
INC_DIR   := include
BIN_DIR   := bin

# ── Flags ──────────────────────────────────────────────────────────────

# BPF compilation flags
BPF_CFLAGS := \
    -g -O2 -target bpf \
    -D__TARGET_ARCH_$(ARCH) \
    -I$(INC_DIR) \
    -I/usr/include/$(shell uname -m)-linux-gnu \
    -I/usr/include \
    $(shell [ -f vmlinux.h ] && echo "" || echo "-DBPF_NO_VMLINUX")

# Userspace compilation flags
US_CFLAGS  := \
    -g -O2 -Wall -Wextra \
    -I$(INC_DIR) \
    -I/usr/include

US_LDFLAGS := -lbpf -lelf -lz

# ── Feature list ───────────────────────────────────────────────────────
FEATURES := \
    net_traffic \
    proc_exec \
    file_integrity \
    syscall_anomaly \
    dns_monitor \
    priv_esc \
    tcp_tracker \
    threat_detect \
    zero_trust \
    infra_health

# ── Derived file lists ─────────────────────────────────────────────────
BPF_OBJS  := $(patsubst %,$(BIN_DIR)/%.bpf.o,$(FEATURES))
US_BINS   := $(patsubst %,$(BIN_DIR)/%,$(FEATURES))

# ── Default target ─────────────────────────────────────────────────────
.PHONY: all clean vmlinux $(FEATURES)

all: dirs $(BPF_OBJS) $(US_BINS)
	@echo ""
	@echo "Build complete.  Binaries in $(BIN_DIR)/  BPF objects in $(OBJ_DIR)/"

# ── Create output directories ──────────────────────────────────────────
dirs:
	@mkdir -p $(BIN_DIR)

# ── Generate vmlinux.h from the running kernel ─────────────────────────
vmlinux: vmlinux.h

vmlinux.h:
	@echo "[GEN]  vmlinux.h"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# ── BPF kernel program compilation ─────────────────────────────────────
$(BIN_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c $(INC_DIR)/*.h vmlinux.h
	@echo "[BPF]  $<"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(STRIP) -g $@

# ── Userspace loader compilation ───────────────────────────────────────
$(BIN_DIR)/%: $(US_DIR)/%_user.c $(INC_DIR)/*.h
	@echo "[CC]   $<"
	$(CC) $(US_CFLAGS) $< $(US_LDFLAGS) -o $@

# ── Per-feature convenience targets ────────────────────────────────────
$(FEATURES): %: dirs $(BIN_DIR)/%.bpf.o $(BIN_DIR)/%
	@echo "Built feature: $@"

# ── Phony helpers ──────────────────────────────────────────────────────
install: all
	@echo "Installing to /usr/lib/ebpf-suite/ ..."
	install -d /usr/lib/ebpf-suite
	install -m 644 $(BIN_DIR)/*.bpf.o /usr/lib/ebpf-suite/
	install -d /usr/local/bin
	install -m 755 $(BIN_DIR)/* /usr/local/bin/

clean:
	@rm -rf $(BIN_DIR)
	@echo "Cleaned."

# ── Dependency: vmlinux.h must exist before BPF sources compile ────────
$(BPF_OBJS): vmlinux.h
