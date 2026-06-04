# syntax=docker/dockerfile:1
#
# Multi-stage build. The eBPF toolchain (clang/llvm/libbpf) lives only in the
# bpf-builder stage, so neither the binary build nor a developer's `go build`
# ever needs clang — the generated BPF artifacts are committed.
#
#   make bpf-generate   # regenerate internal/ebpf/trace_bpfel.{go,o} from the .c
#   make docker-build   # produce dist/jailgraph (static linux binary)

# --- BPF artifact generation (clang toolchain) -----------------------------
# Recompiles the BPF object from trace.bpf.c + the committed vmlinux.h. Needs no
# BTF/privilege (vmlinux.h is committed; regenerate it separately on a kernel
# change via: bpftool btf dump file /sys/kernel/btf/vmlinux format c).
FROM golang:1.26 AS bpf-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN go generate ./internal/ebpf/

# Export just the regenerated artifacts: `docker build --target bpf-artifacts -o internal/ebpf .`
FROM scratch AS bpf-artifacts
COPY --from=bpf-builder /src/internal/ebpf/trace_bpfel.go /
COPY --from=bpf-builder /src/internal/ebpf/trace_bpfel.o /

# --- Binary build (no clang; uses committed BPF artifacts) ------------------
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/jailgraph ./cmd/jailgraph

# Export the binary: `docker build --target export -o dist .`
FROM scratch AS export
COPY --from=build /out/jailgraph /jailgraph
