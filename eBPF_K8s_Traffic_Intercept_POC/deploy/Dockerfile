# Stage 1: Build the eBPF agent
FROM golang:1.22-bookworm AS builder

WORKDIR /build

# Install LLVM/clang for bpf2go compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-amd64 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Cache module downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Generate eBPF Go scaffolding and build
RUN go generate ./... && \
    CGO_ENABLED=0 go build -o /ebpf-agent -ldflags="-s -w" .

# Stage 2: Minimal runtime image
FROM gcr.io/distroless/base-debian12:latest

COPY --from=builder /ebpf-agent /ebpf-agent

ENTRYPOINT ["/ebpf-agent"]
