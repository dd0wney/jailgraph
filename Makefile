.PHONY: build test integration vet lint cross clean bpf-generate docker-build ebpf-test

build:
	go build ./...

# Cross-platform unit tests (run anywhere, including macOS).
test:
	go test ./... -count=1 -short

# Full-pipeline test against a real local graphdb. Requires JAILGRAPH_GRAPHDB_URL.
integration:
	go test ./... -count=1 -run Integration

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# Verify the Linux-only backends build for both supported arches.
cross:
	GOOS=linux GOARCH=amd64 go build ./...
	GOOS=linux GOARCH=arm64 go build ./...

# Regenerate the committed BPF artifacts (trace_bpfel.{go,o}) from trace.bpf.c +
# vmlinux.h using the multi-stage build's clang toolchain. Needs no clang on the
# host and no privilege (vmlinux.h is committed). Run after editing the BPF C.
bpf-generate:
	docker build --target bpf-artifacts --output internal/ebpf .

# Regenerate vmlinux.h from the running kernel's BTF (rarely; on kernel change).
# Requires a privileged container with access to /sys/kernel/btf.
vmlinux-generate:
	docker run --rm --privileged -v "$$PWD":/src -w /src golang:1.26 bash -c '\
	  apt-get update -qq && apt-get install -y -qq bpftool >/dev/null && \
	  bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/bpf/vmlinux.h'

# Build a static linux jailgraph binary via the multi-stage build (no clang on host).
docker-build:
	docker build --target export --output dist .

# Run the Linux-only integration tests (seccomp + eBPF) on a real kernel.
# --pid=host so eBPF root-namespace PIDs match (as on a real host); --privileged
# for CAP_BPF + seccomp filter install.
ebpf-test:
	docker run --rm --privileged --pid=host -v "$$PWD":/src -w /src golang:1.26 \
	  go test ./internal/ebpf/ ./internal/seccomp/ -tags linux_integration -count=1

clean:
	go clean ./...
