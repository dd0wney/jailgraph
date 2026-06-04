#!/usr/bin/env bash
# Validate the jailgraph × stór reproducibility convergence.
#
# Traces a stór sandboxed build (`stor realise <recipe>`) under jailgraph's eBPF
# backend twice, then runs the reproducibility audit over the two behavior
# graphs. A deterministic build must show no stable-dimension (syscall/binary)
# drift. This exercises descendant-following THROUGH stór's namespace sandbox
# (user/mount/pid unshare + pivot_root) — the build's syscalls are captured
# though only `stor` was launched.
#
# Requires: Docker on a Linux kernel with BTF; sibling repos ../stor-core and
# ../graphdb (graphdb is mounted read-only only because stór's go.mod has a
# `replace => ../graphdb` directive — we never write to it). Runs --privileged
# --pid=host so eBPF root-namespace tgids match (as on a real host).
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)" # jailgraph repo root
siblings="$(cd "$here/.." && pwd)"
stor="$siblings/stor-core"
graphdb="$siblings/graphdb"
recipe="${1:-/stor/examples/hello.star}"

[ -d "$stor" ] || { echo "missing sibling repo: $stor" >&2; exit 1; }
[ -d "$graphdb" ] || { echo "missing sibling repo: $graphdb (stór's replace directive needs it)" >&2; exit 1; }

exec docker run --rm --privileged --pid=host \
	-v jailgraph-gomod:/go/pkg/mod \
	-v "$here":/src \
	-v "$stor":/stor \
	-v "$graphdb":/graphdb:ro \
	-w /src golang:1.26 bash -c '
		set -e
		go -C /stor build -o /tmp/stor ./cmd/stor
		STOR_BIN=/tmp/stor STOR_RECIPE='"$recipe"' \
			go test ./internal/ebpf/ -tags stor_integration -run TestStor -v -count=1
	'
