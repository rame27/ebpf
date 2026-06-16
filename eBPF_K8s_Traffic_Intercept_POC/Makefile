# eBPF K8s Traffic Intercept POC
#
# Targets:
#   generate  - Run bpf2go to compile C eBPF → Go scaffolding
#   build     - Build the Go agent binary
#   run       - Run locally (requires root)
#   docker    - Build Docker image for DaemonSet deployment
#   clean     - Remove generated files

BPF_C   := bpf/tc_prog.c
BPF_GO  := bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
BINARY  := ebpf-agent
IMAGE   := ebpf-agent:latest

.PHONY: all generate build run docker clean

all: generate build

# Generate Go scaffolding from eBPF C program
generate:
	go generate ./...

# Build the Go agent binary
build: generate
	go build -o $(BINARY) -ldflags="-s -w" .

# Run locally (requires root for eBPF)
run: build
	sudo ./$(BINARY)

# Build Docker image for Kubernetes DaemonSet deployment
docker: generate
	docker build -t $(IMAGE) -f deploy/Dockerfile .

# Clean generated files
clean:
	rm -f $(BINARY) $(BPF_GO)
	go clean -cache
