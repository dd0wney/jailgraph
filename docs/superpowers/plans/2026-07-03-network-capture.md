# Network Capture (Phase 1 — C2 Signal) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give jailgraph its first network visibility — egress connections (`:Endpoint`) and DNS resolutions (`:Domain`), process-attributed — flowing through the existing capture → graph → consumer pipeline, unlocking the C2 threat class for `malware` and `anomaly`.

**Architecture:** A new eBPF `fentry/security_socket_connect` hook folds per-`(tgid, dest)` connects in an in-kernel map (mirroring `write_stats`/`seen`), materialized to `EventConnect` at teardown. A new `fentry/udp_sendmsg` hook (dport 53) streams the DNS query payload over the existing ringbuf (mirroring `rename`/`unlink`); userspace parses the qname and folds to `EventDNS`. The collector's decode/parse logic lives in platform-neutral files (like `fold.go`) so it is unit-tested without a kernel. `model.EventToGraph` maps the new events to `:Endpoint`/`CONNECTED` and `:Domain`/`RESOLVED`. `profile.Collect` surfaces both on `Behavior`, from which `malware` (a network category) and `anomaly` (an endpoints dimension) consume them.

**Tech Stack:** Go 1.26, cilium/ebpf (bpf2go-generated bindings, committed), CO-RE eBPF C (clang via `make bpf-generate` docker toolchain), graphdb client. Linux-only backend; darwin builds via `stub_other.go`.

## Global Constraints

- **TDD always:** failing test first, watch it fail, minimal implementation, watch it pass, commit. Copied verbatim from the repo/user rules.
- **Table-driven tests** for Go (repo Go convention).
- **Return errors, don't panic** (except in tests); **no naked returns**; **explicit error handling, no silent failures** (repo Go rules).
- **`golangci-lint` must pass before committing** (repo Go rule).
- **Comments explain why, not what.** Match surrounding comment density/idiom.
- **Platform-neutral collector logic** stays in files with NO `//go:build linux` tag (so `internal/collector` and the decode/parse helpers build+test on darwin too). Kernel-touching glue stays in `//go:build linux` files.
- **eBPF bindings are committed:** after editing `internal/ebpf/bpf/trace.bpf.c`, regenerate and commit `trace_bpfel.go` + `trace_bpfel.o`. `go build` never invokes clang. Regenerate with `podman build --target bpf-artifacts --output internal/ebpf .` (this environment: docker daemon is down but podman 5.8 reproduces the artifacts byte-for-byte; `make bpf-generate` is the docker equivalent). Only the actual kernel-load runtime validation needs a privileged host — compile + unit tests verify here.
- **Ports/addresses are network byte order in the kernel:** convert with `ntohs`/big-endian reads at the userspace boundary, never store raw `__be16`/`__be32`.
- **Scope (phase 1):** AF_INET + AF_INET6 only (skip AF_UNIX); connect *attempts* (not success); no byte-volume accounting; no bind/listen/accept. macOS esf + seccomp backends report the network dimension absent.
- **Honesty discipline:** every consumer reports the network dimension "not observable on this backend" when `NetCapture` is false, and excludes it from any "clean" verdict (absence of observability ≠ absence of signal).

---

## Task Ordering Rationale

The spec lists consumers (N3) before DNS (N4), but notes the malware raw-IP heuristic is "dormant" until DNS data exists. Implementing consumers last removes that noisy intermediate window entirely. Order: **connect capture → connect model → DNS capture → DNS model → consumers → run-flag + CLI + validation.** Tasks 1 and 3 touch the kernel (regen-gated); all their decode/parse logic is extracted into pure Go tested without a kernel. Tasks 2, 4, 5, 6 are pure Go, fully TDD-able on any platform.

---

## Task 1: eBPF connect capture

Add the `security_socket_connect` hook and its in-kernel fold map to the BPF program, plus the platform-neutral Go decode helper (TDD'd without a kernel). The kernel-side map read-out is wired in Task 1c after regeneration.

**Files:**
- Create: `internal/ebpf/net.go` (platform-neutral: connect key/stat types + decode)
- Create: `internal/ebpf/net_test.go`
- Modify: `internal/ebpf/bpf/trace.bpf.c` (add hook + `conn_stats` map)
- Modify: `internal/ebpf/collector_linux.go` (attach hook, drain map at teardown)
- Regenerate: `internal/ebpf/trace_bpfel.go`, `internal/ebpf/trace_bpfel.o` (via `make bpf-generate`)

**Interfaces:**
- Consumes: `collector.BehaviorEvent`, `collector.EventConnect` (defined in Task 2 — this task references the kind constant; **do Task 2's `collector.go` edit first if building standalone**, or land Tasks 1–2 together. See Step 0.)
- Produces:
  - `type connKey struct { TGID uint32; Family uint32; Port uint16; Addr [16]byte }`
  - `type connStat struct { Count uint64; Proto uint32 }`
  - `func connToBehavior(k connKey, s connStat) collector.BehaviorEvent` — returns an `EventConnect` with `PID=int32(k.TGID)`, `DstIP`, `DstPort`, `Proto` ("tcp"/"udp"/"proto-N"), `ConnCount=int64(s.Count)`.
  - `func decodeIP(family uint32, addr [16]byte) string` — dotted-quad for AF_INET (first 4 bytes), RFC 5952 for AF_INET6.

- [ ] **Step 0: Sequencing note (read, no action)**

`net.go` references `collector.EventConnect` and the new `BehaviorEvent` network fields, which Task 2 adds to `internal/collector/collector.go`. Either (a) implement Task 2 Steps 1–4 (the `collector.go` additions) before this task, or (b) land Tasks 1 and 2 in the same branch. The plan is written assuming the `collector` additions from Task 2 exist. If building Task 1 standalone fails to compile with "EventConnect undefined", apply Task 2 Step 3 first.

- [ ] **Step 1: Write the failing test for `decodeIP` and `connToBehavior`**

Create `internal/ebpf/net_test.go`:

```go
// This file is platform-neutral (no build tag): the connect-decode logic is
// unit-tested without a kernel, mirroring fold_test.go / entropy_test.go.
package ebpf

import (
	"testing"

	"github.com/dd0wney/jailgraph/internal/collector"
)

func TestDecodeIP(t *testing.T) {
	tests := []struct {
		name   string
		family uint32
		addr   [16]byte
		want   string
	}{
		{"ipv4 loopback", afInet, [16]byte{127, 0, 0, 1}, "127.0.0.1"},
		{"ipv4 public", afInet, [16]byte{93, 184, 216, 34}, "93.184.216.34"},
		{"ipv6 loopback", afInet6, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "::1"},
		{"ipv6 full", afInet6, [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}, "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeIP(tt.family, tt.addr); got != tt.want {
				t.Errorf("decodeIP(%d, %v) = %q, want %q", tt.family, tt.addr, got, tt.want)
			}
		})
	}
}

func TestConnToBehavior(t *testing.T) {
	k := connKey{TGID: 4242, Family: afInet, Port: 443, Addr: [16]byte{93, 184, 216, 34}}
	s := connStat{Count: 7, Proto: ipProtoTCP}
	be := connToBehavior(k, s)
	if be.Kind != collector.EventConnect {
		t.Fatalf("Kind = %v, want EventConnect", be.Kind)
	}
	if be.PID != 4242 {
		t.Errorf("PID = %d, want 4242", be.PID)
	}
	if be.DstIP != "93.184.216.34" || be.DstPort != 443 {
		t.Errorf("dst = %s:%d, want 93.184.216.34:443", be.DstIP, be.DstPort)
	}
	if be.Proto != "tcp" {
		t.Errorf("Proto = %q, want tcp", be.Proto)
	}
	if be.ConnCount != 7 {
		t.Errorf("ConnCount = %d, want 7", be.ConnCount)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/ebpf/ -run 'TestDecodeIP|TestConnToBehavior' -v`
Expected: FAIL — `undefined: decodeIP`, `undefined: connToBehavior`, `undefined: afInet`, etc.

- [ ] **Step 3: Write `internal/ebpf/net.go`**

```go
// This file is platform-neutral (no build tag) so the connect-decode logic is
// unit-testable without a kernel; the kernel-touching map drain lives in
// collector_linux.go, mirroring fold.go vs collector_linux.go.
package ebpf

import (
	"net/netip"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// Address family + protocol constants, matching the values read from the kernel
// sockaddr (uapi #defines, stable across arches).
const (
	afInet     uint32 = 2  // AF_INET
	afInet6    uint32 = 10 // AF_INET6
	ipProtoTCP uint32 = 6  // IPPROTO_TCP
	ipProtoUDP uint32 = 17 // IPPROTO_UDP
)

// connKey mirrors `struct conn_key` in trace.bpf.c: the in-kernel fold key for a
// distinct (process, destination) egress connection. Addr holds a v4 address in
// its first 4 bytes (rest zero) or a full v6 address.
type connKey struct {
	TGID   uint32
	Family uint32
	Port   uint16
	_      uint16 // explicit pad to match C struct alignment (u32,u32,u16,pad,u8[16])
	Addr   [16]byte
}

// connStat mirrors `struct conn_stat` in trace.bpf.c: the folded attempt count
// and socket protocol for one (process, destination).
type connStat struct {
	Count uint64
	Proto uint32
	_     uint32 // pad to 8-byte alignment
}

// decodeIP renders a destination address as text. AF_INET reads the first 4
// bytes; AF_INET6 reads all 16. netip gives canonical RFC 5952 v6 formatting.
func decodeIP(family uint32, addr [16]byte) string {
	switch family {
	case afInet:
		return netip.AddrFrom4([4]byte{addr[0], addr[1], addr[2], addr[3]}).String()
	case afInet6:
		return netip.AddrFrom16(addr).String()
	default:
		return ""
	}
}

// protoName maps a socket protocol number to a short name, never failing (an
// unknown protocol is rendered by number rather than dropped).
func protoName(p uint32) string {
	switch p {
	case ipProtoTCP:
		return "tcp"
	case ipProtoUDP:
		return "udp"
	default:
		return "proto-" + itoa(p)
	}
}

func itoa(u uint32) string {
	if u == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

// connToBehavior converts one folded connect record into a decoded BehaviorEvent.
func connToBehavior(k connKey, s connStat) collector.BehaviorEvent {
	return collector.BehaviorEvent{
		Kind:      collector.EventConnect,
		PID:       int32(k.TGID),
		DstIP:     decodeIP(k.Family, k.Addr),
		DstPort:   k.Port,
		Proto:     protoName(s.Proto),
		ConnCount: int64(s.Count),
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/ebpf/ -run 'TestDecodeIP|TestConnToBehavior' -v`
Expected: PASS. (Requires Task 2 Step 3's `collector` fields; see Step 0.)

- [ ] **Step 5: Add the eBPF hook + map to `internal/ebpf/bpf/trace.bpf.c`**

After the `write_stats` map block (around line 122), add the connect fold map:

```c
// conn_stats: (tgid, family, dport, daddr) -> attempt count + protocol. Egress
// connections are folded IN-KERNEL like write_stats/seen (never streamed): a
// beaconing loop must not flood the ringbuf. Read out at teardown. Phase 1 is
// AF_INET/AF_INET6 only (AF_UNIX is local IPC, skipped). Records connect
// ATTEMPTS (the hook fires pre-connect), which is the C2 signal regardless of
// success.
struct conn_key {
	__u32 tgid;
	__u32 family;
	__u16 dport;   // host-order? NO — stored network-order; userspace ntohs.
	__u16 _pad;
	__u8  daddr[16]; // v4 in first 4 bytes, or full v6
};
struct conn_stat {
	__u64 count;
	__u32 proto;
	__u32 _pad;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 12);
	__type(key, struct conn_key);
	__type(value, struct conn_stat);
} conn_stats SEC(".maps");

#define AF_INET  2
#define AF_INET6 10
```

Then, before the `char LICENSE[]` line, add the hook. Signature:
`security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)`.

```c
// handle_connect folds one egress connect attempt per (tgid, destination). The
// port is stored network-order and byte-swapped in userspace (bpf has no htons
// on a __be16 field without pulling in extra headers; the raw bytes round-trip).
SEC("fentry/security_socket_connect")
int BPF_PROG(handle_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;

	__u16 family = 0;
	bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
	if (family != AF_INET && family != AF_INET6)
		return 0; // AF_UNIX and others are out of phase-1 scope

	struct conn_key k = {};
	k.tgid = tgid;
	k.family = family;
	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)address;
		bpf_probe_read_kernel(&k.dport, sizeof(k.dport), &sin->sin_port);
		bpf_probe_read_kernel(&k.daddr, 4, &sin->sin_addr.s_addr);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
		bpf_probe_read_kernel(&k.dport, sizeof(k.dport), &sin6->sin6_port);
		bpf_probe_read_kernel(&k.daddr, 16, &sin6->sin6_addr);
	}

	__u32 proto = 0;
	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (sk)
		proto = BPF_CORE_READ(sk, sk_protocol);

	struct conn_stat *st = bpf_map_lookup_elem(&conn_stats, &k);
	if (st) {
		st->count += 1;
	} else {
		struct conn_stat init = {};
		init.count = 1;
		init.proto = proto;
		bpf_map_update_elem(&conn_stats, &k, &init, BPF_ANY);
	}
	return 0;
}
```

- [ ] **Step 6: Regenerate the committed bindings**

Run: `podman build --target bpf-artifacts --output internal/ebpf .`  (docker daemon down here; podman reproduces artifacts byte-for-byte)
Expected: `internal/ebpf/trace_bpfel.go` and `trace_bpfel.o` change; `traceObjects` now has `HandleConnect *ebpf.Program` and `ConnStats *ebpf.Map`; generated `traceConnKey`/`traceConnStat` structs appear.
If docker/clang is unavailable in this environment, STOP and flag: this step and the two that follow require the toolchain (see Task 7 hardware runbook). Confirm the C compiles clean before proceeding.

- [ ] **Step 7: Attach the hook in `internal/ebpf/collector_linux.go`**

In `Start`, in the `for _, h := range []struct{...}` block that attaches the vfs_write/rename/unlink fentries (around line 158), add a row:

```go
		{"security_socket_connect", c.objs.HandleConnect},
```

- [ ] **Step 8: Drain the conn_stats map at teardown in `finalize`**

In `finalize` (`internal/ebpf/collector_linux.go`), after the `write_stats` fold loop (around line 381, after the `foldFileActivity` emit), add:

```go
	// Materialize folded egress connects: one EventConnect per (process,
	// destination). Like write_stats, the hot connect path was folded in-kernel;
	// we read the count out here. Safe to touch after <-ringbufDone.
	var ck traceConnKey
	var cs traceConnStat
	cit2 := c.objs.ConnStats.Iterate()
	for cit2.Next(&ck, &cs) {
		be := connToBehavior(
			connKey{TGID: ck.Tgid, Family: ck.Family, Port: ntohs(ck.Dport), Addr: ck.Daddr},
			connStat{Count: cs.Count, Proto: cs.Proto},
		)
		be.Timestamp = time.Now()
		c.emit(be)
	}
	if err := cit2.Err(); err != nil {
		c.emitErr(fmt.Errorf("iterate conn_stats map: %w", err))
	}
```

Add the `ntohs` helper to `net.go` (network-order `__be16` → host `uint16`):

```go
// ntohs converts a network-byte-order 16-bit value (as read raw from the kernel
// sockaddr) to host order. The kernel stores the port big-endian regardless of
// host endianness.
func ntohs(be uint16) uint16 {
	return be<<8 | be>>8
}
```

> Note: the generated field names (`traceConnKey.Tgid`, `.Family`, `.Dport`, `.Daddr`) are produced by bpf2go from the C struct; verify exact casing in the regenerated `trace_bpfel.go` and adjust if bpf2go emits e.g. `Pad`. The `_pad` C fields become exported padding fields — ignore them.

- [ ] **Step 9: Build and run the neutral tests + integration build**

Run: `go build ./... && go test ./internal/ebpf/ -run 'TestDecodeIP|TestConnToBehavior|TestNtohs' -v`
Expected: PASS. (Add a small `TestNtohs` table asserting `ntohs(0x01BB) == 443` if you want the swap covered.)
Run: `go vet ./internal/ebpf/`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add internal/ebpf/net.go internal/ebpf/net_test.go internal/ebpf/bpf/trace.bpf.c \
        internal/ebpf/collector_linux.go internal/ebpf/trace_bpfel.go internal/ebpf/trace_bpfel.o
git commit -m "feat(ebpf): capture egress connects via security_socket_connect (N1)"
```

---

## Task 2: collector kind + Endpoint model + profile surfacing

Add `EventConnect` to the collector contract, map it to an `:Endpoint` node with a `CONNECTED` edge, and surface endpoints on `profile.Behavior` (the shared read path both consumers use).

**Files:**
- Modify: `internal/collector/collector.go` (new kind + BehaviorEvent fields)
- Modify: `internal/collector/collector_test.go` or `internal/collector/fake_test.go` (String() coverage)
- Modify: `internal/model/keys.go` (labels/edges/key)
- Modify: `internal/model/graph.go` (EventConnect case)
- Modify: `internal/model/graph_test.go` (node/edge assertion)
- Modify: `internal/profile/profile.go` (Behavior.Endpoints field)
- Modify: `internal/profile/collect.go` (bucket Endpoint neighbors)
- Modify: `internal/profile/collect_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `collector.EventConnect EventKind` (next iota after `EventFileActivity`).
  - `BehaviorEvent` fields: `DstIP string`, `DstPort uint16`, `Proto string`, `ConnCount int64`.
  - `model.LabelEndpoint = "Endpoint"`, `model.EdgeConnected = "CONNECTED"`, `func model.EndpointKey(ip string, port uint16) string`.
  - `profile.Behavior.Endpoints []string` — each formatted `"<ip>:<port>"`.

- [ ] **Step 1: Write the failing test for `EventKind.String()` and the new kind**

In `internal/collector/collector_test.go` (create if absent; a `fake_test.go` already exercises `String()`), add a case asserting `EventConnect.String() == "connect"`:

```go
func TestEventConnectString(t *testing.T) {
	if got := EventConnect.String(); got != "connect" {
		t.Errorf("EventConnect.String() = %q, want %q", got, "connect")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/collector/ -run TestEventConnectString -v`
Expected: FAIL — `undefined: EventConnect`.

- [ ] **Step 3: Add the kind + fields to `internal/collector/collector.go`**

Add the constant after `EventFileActivity` in the `const` block:

```go
	// EventConnect is an egress connect() to an AF_INET/AF_INET6 address. Maps to
	// a CONNECTED edge (Process -> Endpoint). Folded per (process, destination) by
	// the backend, so ConnCount carries the attempt count (beaconing signal).
	// eBPF (Linux) only; seccomp and macOS esf do not observe it.
	EventConnect
```

Add to `String()`:

```go
	case EventConnect:
		return "connect"
```

Add the fields to `BehaviorEvent` (after the File I/O aggregate block, before `Lossy`):

```go
	// Network (EventConnect). DstIP is the decoded destination address (dotted
	// quad or RFC 5952 v6); DstPort is host-order; Proto is "tcp"/"udp"/"proto-N".
	// ConnCount is the per-(process,destination) attempt count folded by the
	// backend. Populated only for EventConnect; empty on backends without network
	// capture.
	DstIP     string
	DstPort   uint16
	Proto     string
	ConnCount int64
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/collector/ -run TestEventConnectString -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test for `EndpointKey` + the EventConnect graph mapping**

In `internal/model/graph_test.go`, add:

```go
func TestEventToGraph_Connect(t *testing.T) {
	e := collector.BehaviorEvent{
		Kind: collector.EventConnect, PID: 100, PPID: 1, Exe: "/usr/bin/curl",
		DstIP: "93.184.216.34", DstPort: 443, Proto: "tcp", ConnCount: 3,
	}
	nodes, edges := EventToGraph("run1", e)

	epKey := EndpointKey("93.184.216.34", 443)
	var ep *Node
	for i := range nodes {
		if nodes[i].Key == epKey {
			ep = &nodes[i]
		}
	}
	if ep == nil {
		t.Fatalf("no Endpoint node with key %q; nodes=%v", epKey, nodes)
	}
	if ep.Labels[0] != LabelEndpoint {
		t.Errorf("label = %v, want %s", ep.Labels, LabelEndpoint)
	}
	if ep.Properties["ip"] != "93.184.216.34" || ep.Properties["port"] != uint16(443) || ep.Properties["proto"] != "tcp" {
		t.Errorf("endpoint props = %v", ep.Properties)
	}

	found := false
	for _, ed := range edges {
		if ed.Type == EdgeConnected && ed.FromKey == ProcessKey("run1", 100) && ed.ToKey == epKey {
			found = true
			if ed.Properties["count"] != int64(3) {
				t.Errorf("CONNECTED count = %v, want 3", ed.Properties["count"])
			}
		}
	}
	if !found {
		t.Errorf("no CONNECTED edge proc->endpoint; edges=%v", edges)
	}
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/model/ -run TestEventToGraph_Connect -v`
Expected: FAIL — `undefined: EndpointKey`, `undefined: LabelEndpoint`, `undefined: EdgeConnected`.

- [ ] **Step 7: Add label/edge/key to `internal/model/keys.go`**

In the label const block add `LabelEndpoint = "Endpoint"`; in the edge block add `EdgeConnected = "CONNECTED"`. Add the key constructor near `FileKey`:

```go
// EndpointKey identifies a network destination by IP and port. Content-keyed
// (shared across runs like File/Binary) — cross-run endpoint identity is the
// point (the same C2 host contacted by two runs is one node).
func EndpointKey(ip string, port uint16) string {
	return "endpoint:" + ip + ":" + strconv.Itoa(int(port))
}
```

- [ ] **Step 8: Add the EventConnect case to `internal/model/graph.go`**

In the `switch e.Kind` in `EventToGraph`, before the `case collector.EventSpawn, collector.EventSyscall:` no-op, add:

```go
	case collector.EventConnect:
		epKey := EndpointKey(e.DstIP, e.DstPort)
		nodes = append(nodes, Node{
			Key:    epKey,
			Labels: []string{LabelEndpoint},
			Properties: map[string]any{
				"ip": e.DstIP, "port": e.DstPort, "proto": e.Proto, PropKey: epKey,
			},
		})
		count := e.ConnCount
		if count == 0 {
			count = 1
		}
		edges = append(edges, Edge{
			Type: EdgeConnected, FromKey: procKey, ToKey: epKey,
			Properties: map[string]any{"count": count},
		})
```

> The connect is pre-folded per (process, destination) by the collector, so exactly one CONNECTED edge exists per pair with the full count — the aggregator's non-INVOKED dedup preserves it as-is (no summation needed), matching how FileActivity is pre-folded.

- [ ] **Step 9: Run test to verify it passes**

Run: `go test ./internal/model/ -run TestEventToGraph_Connect -v`
Expected: PASS.

- [ ] **Step 10: Write the failing test for `profile.Collect` bucketing Endpoint neighbors**

In `internal/profile/collect_test.go`, extend the fake graph used by the existing collect test with an Endpoint node reachable from a process, and assert it lands in `Behavior.Endpoints`. Follow the existing test's fake-client shape; the new assertion:

```go
func TestCollect_Endpoints(t *testing.T) {
	// fake: run "r1" with one process proc:r1:100 traversing to an Endpoint node.
	client := newFakeGraph(t)
	client.addRun("r1", "curl", "full", false)
	proc := client.addProcess("r1", 100)
	client.addNeighbor(proc, &graphdb.NodeResponse{
		Labels: []string{model.LabelEndpoint},
		Properties: map[string]any{"ip": "93.184.216.34", "port": float64(443), "proto": "tcp"},
	})

	b, err := Collect(context.Background(), client, "r1", 100)
	if err != nil {
		t.Fatal(err)
	}
	want := "93.184.216.34:443"
	if len(b.Endpoints) != 1 || b.Endpoints[0] != want {
		t.Errorf("Endpoints = %v, want [%s]", b.Endpoints, want)
	}
}
```

> Match the actual fake-client helpers in `collect_test.go`. If the existing test builds its fake inline (not via helpers), mirror that structure instead — the key point is an Endpoint neighbor with `ip`/`port` (port arrives as `float64` from JSON read-back) yields `"ip:port"`.

- [ ] **Step 11: Run test to verify it fails**

Run: `go test ./internal/profile/ -run TestCollect_Endpoints -v`
Expected: FAIL — `b.Endpoints` undefined / empty.

- [ ] **Step 12: Add `Endpoints` to `Behavior` and bucket it**

In `internal/profile/profile.go`, add to `Behavior` (after `Namespaces`):

```go
	Endpoints  []string // network destinations "ip:port" contacted (eBPF only)
```

In `Union`, add endpoint unioning: declare `eps := map[string]struct{}{}` alongside the others, `addAll(eps, b.Endpoints)` in the loop, and `u.Endpoints = sortedKeys(eps)` after.

In `internal/profile/collect.go`, extend `bucket`'s signature and the `Collect` call site to pass an `endpoints map[string]struct{}`, and add the case:

```go
	case model.LabelEndpoint:
		ip, _ := n.Properties["ip"].(string)
		port := toPort(n.Properties["port"])
		if ip != "" {
			endpoints[ip+":"+strconv.Itoa(int(port))] = struct{}{}
		}
```

Add a `toPort` helper (JSON numbers read back as float64):

```go
// toPort coerces a graph port property (float64 from JSON, or a native int) to
// uint16.
func toPort(v any) uint16 {
	switch x := v.(type) {
	case float64:
		return uint16(x)
	case int:
		return uint16(x)
	case uint16:
		return x
	default:
		return 0
	}
}
```

Wire `endpoints` through `Collect`: declare `endpointSet := map[string]struct{}{}`, pass it to `bucket`, and set `b.Endpoints = sortedKeys(endpointSet)` before returning. Add `"strconv"` to the imports.

- [ ] **Step 13: Run test to verify it passes**

Run: `go test ./internal/profile/ ./internal/model/ ./internal/collector/ -v`
Expected: PASS (all, including pre-existing tests).

- [ ] **Step 14: Commit**

```bash
git add internal/collector/ internal/model/ internal/profile/
git commit -m "feat(model): Endpoint node + CONNECTED edge; surface endpoints on profile.Behavior (N2)"
```

---

## Task 3: eBPF DNS capture

Add the `udp_sendmsg` hook (dport 53) that streams the DNS query payload over the existing ringbuf, plus the platform-neutral qname parser (TDD'd + fuzzed without a kernel).

**Files:**
- Create: `internal/ebpf/dns.go` (platform-neutral qname parser)
- Create: `internal/ebpf/dns_test.go`
- Create: `internal/ebpf/dns_fuzz_test.go`
- Modify: `internal/ebpf/bpf/trace.bpf.c` (add `handle_dns_send` hook + `EVENT_DNS`)
- Modify: `internal/ebpf/collector_linux.go` (decode EVENT_DNS, fold, emit EventDNS)
- Regenerate: `internal/ebpf/trace_bpfel.go`, `trace_bpfel.o`

**Interfaces:**
- Consumes: `collector.EventDNS` (defined in Task 4; same Step-0 sequencing caveat as Task 1).
- Produces:
  - `func parseDNSQName(payload []byte) (string, error)` — parses the first question's QNAME from a DNS query message (12-byte header + question). Returns the dotted name lowercased (`"example.com"`), or an error for malformed/empty input. Rejects compression pointers in a query (queries never legitimately use them) rather than following them.
  - `const evDNS uint32 = 7` (matches `EVENT_DNS` in C).

- [ ] **Step 1: Write the failing test for `parseDNSQName`**

Create `internal/ebpf/dns_test.go`:

```go
package ebpf

import "testing"

// dnsQuery builds a minimal DNS query message: header + one question with the
// given labels, QTYPE=A, QCLASS=IN.
func dnsQuery(labels ...string) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0} // header, QDCOUNT=1
	for _, l := range labels {
		msg = append(msg, byte(len(l)))
		msg = append(msg, []byte(l)...)
	}
	msg = append(msg, 0x00)             // root label terminator
	msg = append(msg, 0x00, 0x01)       // QTYPE A
	msg = append(msg, 0x00, 0x01)       // QCLASS IN
	return msg
}

func TestParseDNSQName(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
		wantErr bool
	}{
		{"example.com", dnsQuery("example", "com"), "example.com", false},
		{"uppercase normalized", dnsQuery("Example", "COM"), "example.com", false},
		{"single label", dnsQuery("localhost"), "localhost", false},
		{"root only", dnsQuery(), "", true},
		{"too short", []byte{0x12, 0x34}, "", true},
		{"empty", nil, "", true},
		{"label overruns buffer", []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x3f, 'a'}, "", true},
		{"compression pointer rejected", append(dnsHeader(), 0xc0, 0x0c), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDNSQName(tt.payload)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parseDNSQName = %q, want %q", got, tt.want)
			}
		})
	}
}

func dnsHeader() []byte {
	return []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/ebpf/ -run TestParseDNSQName -v`
Expected: FAIL — `undefined: parseDNSQName`.

- [ ] **Step 3: Write `internal/ebpf/dns.go`**

```go
// This file is platform-neutral (no build tag): DNS qname parsing runs in
// userspace, never in the verifier (label decompression and validation are not
// verifier-friendly and don't need to be). Kernel-side we only sample raw bytes.
package ebpf

import (
	"errors"
	"strings"
)

const evDNS uint32 = 7 // matches EVENT_DNS in trace.bpf.c

// dnsHeaderLen is the fixed DNS message header (ID, flags, 4 count fields).
const dnsHeaderLen = 12

var errBadDNS = errors.New("malformed DNS query")

// parseDNSQName extracts the first question's QNAME from a DNS query message and
// returns it as a lowercased dotted name. It parses only what a query contains
// (a header + at least one question) and deliberately does NOT follow
// compression pointers: a legitimate *query* question never uses them, so a
// pointer signals a malformed or hostile payload and is rejected. Bounds are
// checked at every step; a label that overruns the sample is an error, never a
// panic or a partial read.
func parseDNSQName(payload []byte) (string, error) {
	if len(payload) < dnsHeaderLen+1 {
		return "", errBadDNS
	}
	pos := dnsHeaderLen
	var labels []string
	for {
		if pos >= len(payload) {
			return "", errBadDNS
		}
		n := int(payload[pos])
		pos++
		if n == 0 { // root label: end of name
			break
		}
		if n&0xc0 != 0 { // compression pointer or reserved bits — reject
			return "", errBadDNS
		}
		if pos+n > len(payload) {
			return "", errBadDNS
		}
		labels = append(labels, string(payload[pos:pos+n]))
		pos += n
	}
	if len(labels) == 0 {
		return "", errBadDNS
	}
	return strings.ToLower(strings.Join(labels, ".")), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/ebpf/ -run TestParseDNSQName -v`
Expected: PASS.

- [ ] **Step 5: Add a fuzz target**

Create `internal/ebpf/dns_fuzz_test.go`:

```go
package ebpf

import "testing"

// FuzzParseDNSQName asserts the parser never panics on arbitrary input — the
// hard requirement for parsing attacker-influenced payloads off the wire.
func FuzzParseDNSQName(f *testing.F) {
	f.Add(dnsQuery("example", "com"))
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0x0c})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseDNSQName(data) // must not panic
	})
}
```

- [ ] **Step 6: Run the fuzzer briefly**

Run: `go test ./internal/ebpf/ -run FuzzParseDNSQName -fuzz FuzzParseDNSQName -fuzztime 15s`
Expected: PASS, no crashers.

- [ ] **Step 7: Add the DNS hook to `internal/ebpf/bpf/trace.bpf.c`**

Add the event-kind define near the others (line ~24): `#define EVENT_DNS 7`.

Add the hook before `char LICENSE[]`. `udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)`. We filter on destination port 53 and sample up to 256 bytes of the message into the existing `struct event.path` buffer, carrying the sampled length in `flags`:

```c
#define DNS_PORT 53
#define DNS_SAMPLE_LEN 256

// handle_dns_send samples outbound UDP payloads to port 53 (DNS queries). Like
// rename/unlink it STREAMS raw bytes over the ringbuf; userspace parses the
// qname (label decompression is not verifier-friendly). Connected and
// unconnected resolvers both traverse udp_sendmsg. DoT/DoH/DNS-over-TCP are NOT
// captured (documented blind spot) — DoH looks like ordinary TLS egress.
SEC("fentry/udp_sendmsg")
int BPF_PROG(handle_dns_send, struct sock *sk, struct msghdr *msg, size_t len)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;

	// Destination port: for a connected socket it is sk->sk_dport (network
	// order); unconnected sends carry it in msg->msg_name. Cover the common
	// connected-resolver path via sk_dport.
	__u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
	__u16 dport = (dport_be << 8) | (dport_be >> 8);
	if (dport != DNS_PORT)
		return 0;

	// Copy up to DNS_SAMPLE_LEN bytes from the first iovec. msg_iter carries the
	// user buffer; read its base ptr and length defensively.
	struct iov_iter *iter = &msg->msg_iter;
	const struct iovec *iov = BPF_CORE_READ(iter, __iov);
	if (!iov)
		return 0;
	void *base = BPF_CORE_READ(iov, iov_base);
	__u64 iov_len = BPF_CORE_READ(iov, iov_len);
	if (!base || iov_len == 0)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->kind = EVENT_DNS;
	e->pid = tgid;
	e->ppid = 0;
	e->path[0] = 0;
	__u32 n = iov_len < DNS_SAMPLE_LEN ? (__u32)iov_len : DNS_SAMPLE_LEN;
	if (bpf_probe_read_user(e->path, DNS_SAMPLE_LEN, base) != 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	e->flags = n; // sampled length; userspace parses path[:flags]
	bpf_ringbuf_submit(e, 0);
	return 0;
}
```

> The exact CO-RE field path for the iovec (`msg_iter.__iov` vs `.iov`) varies by kernel version. If `make bpf-generate` / the verifier rejects the field, consult `vmlinux.h` for the `struct iov_iter` layout on the target kernel and adjust; the hardware-validation step (Task 7) is where this is confirmed. Keep the read bounded to `DNS_SAMPLE_LEN` (fixed size → verifier-friendly).

- [ ] **Step 8: Regenerate bindings**

Run: `podman build --target bpf-artifacts --output internal/ebpf .`  (docker daemon down here; podman reproduces artifacts byte-for-byte)
Expected: `traceObjects` gains `HandleDnsSend *ebpf.Program`. Confirm clean compile.

- [ ] **Step 9: Attach + decode EVENT_DNS in `internal/ebpf/collector_linux.go`**

Add the attach row in the fentry loop (alongside connect from Task 1):

```go
		{"udp_sendmsg", c.objs.HandleDnsSend},
```

Add the `evDNS` handling in `toBehaviors` (the ringbuf decoder), alongside `evRename`/`evUnlink`:

```go
	case evDNS:
		n := int(ev.Flags)
		if n > len(ev.Path) {
			n = len(ev.Path)
		}
		name, err := parseDNSQName(ev.Path[:n])
		if err != nil {
			c.emitErr(fmt.Errorf("parse dns query (pid %d): %w", ev.Pid, err))
			return nil
		}
		c.bumpDNS(int32(ev.Pid), name)
		return nil // folded; emitted as EventDNS at teardown
```

Add a per-(pid,name) DNS aggregate. Add a field to `ebpfCollector`:

```go
	// dnsAgg folds DNS queries per (pid, name). Written only by the ringbuf
	// goroutine; read in finalize after <-ringbufDone (no lock needed).
	dnsAgg map[dnsKey]int64
```

with `type dnsKey struct{ pid int32; name string }`, initialize `c.dnsAgg = make(map[dnsKey]int64)` in `Start` (next to `c.fileAgg`), and:

```go
func (c *ebpfCollector) bumpDNS(pid int32, name string) {
	if name == "" {
		return
	}
	c.dnsAgg[dnsKey{pid, name}]++
}
```

In `finalize`, after the conn_stats drain (Task 1 Step 8), emit one EventDNS per folded query:

```go
	// Emit folded DNS queries: one EventDNS per (process, name) with its count.
	for k, count := range c.dnsAgg {
		c.emit(collector.BehaviorEvent{
			Kind: collector.EventDNS, PID: k.pid, Domain: k.name,
			ResolveCount: count, Timestamp: time.Now(),
		})
	}
```

> `collector.EventDNS`, `BehaviorEvent.Domain`, and `ResolveCount` come from Task 4 Step 3. Land Tasks 3 and 4 together, or apply Task 4 Step 3 first (Step-0 caveat).

- [ ] **Step 10: Build + test**

Run: `go build ./... && go test ./internal/ebpf/ -run 'TestParseDNSQName|TestDecodeIP|TestConnToBehavior' -v`
Expected: PASS. `go vet ./internal/ebpf/` clean.

- [ ] **Step 11: Commit**

```bash
git add internal/ebpf/dns.go internal/ebpf/dns_test.go internal/ebpf/dns_fuzz_test.go \
        internal/ebpf/bpf/trace.bpf.c internal/ebpf/collector_linux.go \
        internal/ebpf/trace_bpfel.go internal/ebpf/trace_bpfel.o
git commit -m "feat(ebpf): capture DNS queries via udp_sendmsg; userspace qname parse (N4 capture)"
```

---

## Task 4: collector kind + Domain model + profile surfacing

Mirror Task 2 for DNS: add `EventDNS`, map it to a `:Domain` node with a `RESOLVED` edge, surface domains on `profile.Behavior`.

**Files:**
- Modify: `internal/collector/collector.go`
- Modify: `internal/collector/collector_test.go`
- Modify: `internal/model/keys.go`
- Modify: `internal/model/graph.go`
- Modify: `internal/model/graph_test.go`
- Modify: `internal/profile/profile.go`, `internal/profile/collect.go`, `internal/profile/collect_test.go`

**Interfaces:**
- Produces:
  - `collector.EventDNS EventKind` (iota after `EventConnect`); `EventDNS.String() == "dns"`.
  - `BehaviorEvent` fields `Domain string`, `ResolveCount int64`.
  - `model.LabelDomain = "Domain"`, `model.EdgeResolved = "RESOLVED"`, `func model.DomainKey(name string) string`.
  - `profile.Behavior.Domains []string`.

- [ ] **Step 1: Write the failing test**

In `internal/collector/collector_test.go`:

```go
func TestEventDNSString(t *testing.T) {
	if got := EventDNS.String(); got != "dns" {
		t.Errorf("EventDNS.String() = %q, want %q", got, "dns")
	}
}
```

In `internal/model/graph_test.go`:

```go
func TestEventToGraph_DNS(t *testing.T) {
	e := collector.BehaviorEvent{
		Kind: collector.EventDNS, PID: 100, Domain: "example.com", ResolveCount: 2,
	}
	nodes, edges := EventToGraph("run1", e)
	dk := DomainKey("example.com")
	var dn *Node
	for i := range nodes {
		if nodes[i].Key == dk {
			dn = &nodes[i]
		}
	}
	if dn == nil || dn.Labels[0] != LabelDomain || dn.Properties["name"] != "example.com" {
		t.Fatalf("Domain node wrong: %v", nodes)
	}
	found := false
	for _, ed := range edges {
		if ed.Type == EdgeResolved && ed.FromKey == ProcessKey("run1", 100) && ed.ToKey == dk {
			found = true
			if ed.Properties["count"] != int64(2) {
				t.Errorf("RESOLVED count = %v, want 2", ed.Properties["count"])
			}
		}
	}
	if !found {
		t.Errorf("no RESOLVED edge; edges=%v", edges)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/collector/ ./internal/model/ -run 'TestEventDNSString|TestEventToGraph_DNS' -v`
Expected: FAIL — `undefined: EventDNS`, `undefined: DomainKey`.

- [ ] **Step 3: Add the kind + fields to `internal/collector/collector.go`**

Constant after `EventConnect`:

```go
	// EventDNS is a DNS query (outbound UDP to port 53). Maps to a RESOLVED edge
	// (Process -> Domain). Records that a name was queried, not what it resolved
	// to. eBPF (Linux) only. DNS-over-TLS/HTTPS/TCP are not observed.
	EventDNS
```

`String()`: `case EventDNS: return "dns"`.

Fields on `BehaviorEvent` (after the network block from Task 2):

```go
	// DNS (EventDNS). Domain is the queried name (lowercased); ResolveCount is the
	// per-(process,name) query count folded by the backend.
	Domain       string
	ResolveCount int64
```

- [ ] **Step 4: Add label/edge/key to `internal/model/keys.go`**

`LabelDomain = "Domain"`; `EdgeResolved = "RESOLVED"`. Key:

```go
// DomainKey identifies a queried DNS name. Content-keyed (shared across runs):
// the same name queried by two runs is one node.
func DomainKey(name string) string { return "domain:" + name }
```

- [ ] **Step 5: Add the EventDNS case to `internal/model/graph.go`**

In the `switch`, after the EventConnect case:

```go
	case collector.EventDNS:
		dk := DomainKey(e.Domain)
		nodes = append(nodes, Node{
			Key:    dk,
			Labels: []string{LabelDomain},
			Properties: map[string]any{"name": e.Domain, PropKey: dk},
		})
		count := e.ResolveCount
		if count == 0 {
			count = 1
		}
		edges = append(edges, Edge{
			Type: EdgeResolved, FromKey: procKey, ToKey: dk,
			Properties: map[string]any{"count": count},
		})
```

- [ ] **Step 6: Surface `Domains` on `profile.Behavior`**

`internal/profile/profile.go`: add `Domains []string` to `Behavior` (after `Endpoints`); union it in `Union` (mirror the `Endpoints` handling: `doms := map[string]struct{}{}`, `addAll(doms, b.Domains)`, `u.Domains = sortedKeys(doms)`).

`internal/profile/collect.go`: extend `bucket` with a `domains map[string]struct{}` param and the case:

```go
	case model.LabelDomain:
		if name, _ := n.Properties["name"].(string); name != "" {
			domains[name] = struct{}{}
		}
```

Wire a `domainSet` through `Collect` and set `b.Domains = sortedKeys(domainSet)`.

- [ ] **Step 7: Write the profile collect test for domains**

In `internal/profile/collect_test.go`, mirror `TestCollect_Endpoints` with a `model.LabelDomain` neighbor (`Properties: {"name": "example.com"}`) asserting `b.Domains == ["example.com"]`.

- [ ] **Step 8: Run all tests to verify they pass**

Run: `go test ./internal/collector/ ./internal/model/ ./internal/profile/ -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/collector/ internal/model/ internal/profile/
git commit -m "feat(model): Domain node + RESOLVED edge; surface domains on profile.Behavior (N4 model)"
```

---

## Task 5: malware network axis

Add network signals to the malware analyzer: a fifth observable category that fires on public egress with no DNS resolution (the LOTL / no-name C2 pattern), which combines with suspicious lineage to escalate (emergent dropper→C2).

**Files:**
- Modify: `internal/malware/malware.go` (Signals fields)
- Modify: `internal/malware/collect.go` (read endpoints/domains/net-capture)
- Modify: `internal/malware/analyze.go` (network category + rule)
- Modify: `internal/malware/analyze_test.go`, `internal/malware/collect_test.go`

**Interfaces:**
- Consumes: `profile.Behavior.Endpoints`, `profile.Behavior.Domains`; a per-run `NetCapture` flag (Task 7 adds `net_capture` to the Run node; until then derive it as `FullCoverage`, i.e. eBPF runs have network capture).
- Produces: `Signals.Connects []NetEndpoint`, `Signals.Domains []string`, `Signals.NetCapture bool`; `type NetEndpoint struct { IP string; Port uint16 }`; a `"network"` category finding.

- [ ] **Step 1: Write the failing test for the network rule**

In `internal/malware/analyze_test.go`:

```go
func TestAnalyze_NetworkNoDNS(t *testing.T) {
	s := Signals{
		RunID: "r1", Target: "curl", Coverage: "full (eBPF)",
		WriteCapture: true, FullCoverage: true, NetCapture: true,
		Connects: []NetEndpoint{{IP: "93.184.216.34", Port: 443}},
		Domains:  nil, // no DNS in the run
	}
	r := Analyze(s)
	if !hasCategory(r, "network") {
		t.Fatalf("expected a network finding; got %v", r.Findings)
	}
}

func TestAnalyze_NetworkWithDNSDoesNotFire(t *testing.T) {
	s := Signals{
		RunID: "r1", Target: "curl", Coverage: "full (eBPF)",
		WriteCapture: true, FullCoverage: true, NetCapture: true,
		Connects: []NetEndpoint{{IP: "93.184.216.34", Port: 443}},
		Domains:  []string{"example.com"},
	}
	r := Analyze(s)
	if firedNetwork(r) {
		t.Errorf("network must not fire when the run resolved DNS; got %v", r.Findings)
	}
}

func TestAnalyze_PrivateEgressDoesNotFire(t *testing.T) {
	s := Signals{
		RunID: "r1", Target: "curl", NetCapture: true, FullCoverage: true, WriteCapture: true,
		Connects: []NetEndpoint{{IP: "127.0.0.1", Port: 8080}, {IP: "10.0.0.5", Port: 53}},
	}
	if firedNetwork(Analyze(s)) {
		t.Errorf("private/loopback egress must not fire network")
	}
}

// hasCategory / firedNetwork are test helpers; add them to the test file.
func hasCategory(r Report, cat string) bool {
	for _, f := range r.Findings {
		if f.Category == cat {
			return true
		}
	}
	return false
}
func firedNetwork(r Report) bool {
	for _, f := range r.Findings {
		if f.Category == "network" && f.Severity != SevInfo {
			return true
		}
	}
	// the "fired" info finding is added only when the category fires
	return hasFiredNetworkInfo(r)
}
func hasFiredNetworkInfo(r Report) bool {
	for _, f := range r.Findings {
		if f.Category == "network" && f.Title == "public egress with no DNS resolution" {
			return true
		}
	}
	return false
}
```

> Adjust the helper expectations to the exact titles you emit in Step 3. The intent: `network` fires (a non-coverage finding is added) for public egress + no DNS, and does not for DNS-resolved or private-only egress.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/malware/ -run TestAnalyze_Network -v`
Expected: FAIL — `undefined: NetEndpoint`, `Signals.Connects` undefined.

- [ ] **Step 3: Add Signals fields + the network rule**

In `internal/malware/malware.go`, add the type and fields:

```go
// NetEndpoint is one contacted network destination (from Endpoint nodes; eBPF
// only).
type NetEndpoint struct {
	IP   string
	Port uint16
}
```

Add to `Signals` (after `Binaries`):

```go
	NetCapture bool          // network egress observed (eBPF); false on seccomp/esf
	Connects   []NetEndpoint // network-egress axis
	Domains    []string      // DNS names resolved in the run
```

In `internal/malware/analyze.go`, add the rule. After the `credFired` block, compute the network signal:

```go
	netFired, netEv := publicEgressNoDNS(s)
```

Add it to the `cats` slice as a fifth category:

```go
		{"network", "public egress with no DNS resolution", netFired, s.NetCapture, netEv},
```

Add the helper (private/loopback/link-local ranges excluded):

```go
// publicEgressNoDNS fires when the run connected out to a PUBLIC address but
// resolved no DNS name — the living-off-the-land / hardcoded-C2 pattern (normal
// clients resolve a name first). Private, loopback, and link-local destinations
// are excluded (RFC 1918 / RFC 4193 / loopback). Combined with suspicious
// lineage it escalates the verdict emergently (two categories fire → High).
func publicEgressNoDNS(s Signals) (bool, string) {
	if len(s.Domains) > 0 {
		return false, "" // the run performed name resolution — ordinary egress
	}
	for _, c := range s.Connects {
		if isPublicIP(c.IP) {
			return true, fmt.Sprintf("connected to %s:%d with no DNS resolution in this run", c.IP, c.Port)
		}
	}
	return false, ""
}

// isPublicIP reports whether ip is a routable, non-private address. Unparseable
// or private/loopback/link-local addresses return false (not egress signal).
func isPublicIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return !(addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast())
}
```

Add `"net/netip"` (and confirm `"fmt"` is imported) to `analyze.go`.

> The combination verdict switch already counts FIRED observable categories, so adding `network` as a fifth category means lineage+network → `firedCount==2` → High with no extra wiring. The per-category "observed" info finding and the "not observable on this backend" coverage finding are emitted by the existing loop over `cats`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/malware/ -run TestAnalyze -v`
Expected: PASS (new + existing).

- [ ] **Step 5: Wire endpoints/domains into `malware.Collect`**

In `internal/malware/collect.go`, after the `profile.Collect` block (which already yields `b`), add:

```go
	s.Domains = b.Domains
	s.NetCapture = b.FullCoverage // eBPF runs have network capture (Task 7 refines to a Run flag)
	for _, ep := range b.Endpoints {
		ip, port := splitEndpoint(ep)
		if ip != "" {
			s.Connects = append(s.Connects, NetEndpoint{IP: ip, Port: port})
		}
	}
```

Add a `splitEndpoint("ip:port") (string, uint16)` helper (split on the LAST colon to tolerate v6):

```go
// splitEndpoint parses an "ip:port" endpoint string, splitting on the final
// colon so IPv6 addresses (which contain colons) parse correctly.
func splitEndpoint(ep string) (string, uint16) {
	i := strings.LastIndexByte(ep, ':')
	if i < 0 {
		return "", 0
	}
	port, err := strconv.Atoi(ep[i+1:])
	if err != nil {
		return "", 0
	}
	return ep[:i], uint16(port)
}
```

Add `"strconv"` to the imports (`"strings"` is already imported).

- [ ] **Step 6: Test the collect wiring**

Add a case to `internal/malware/collect_test.go` asserting a run whose Behavior has `Endpoints: ["1.2.3.4:443"]` and `Domains: nil` yields `Signals.Connects == [{1.2.3.4, 443}]` and `NetCapture` true for a full-coverage run. Follow the file's existing fake-client pattern.

Run: `go test ./internal/malware/ -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/malware/
git commit -m "feat(malware): network axis — public egress with no DNS fires as a threat category (N3)"
```

---

## Task 6: anomaly endpoints dimension

Add an endpoints dimension to the population anomaly detector: novel destinations vs the baseline, using the existing frequency scorer + comparable-N machinery.

**Files:**
- Modify: `internal/anomaly/anomaly.go` (Baseline gains an `Endpoints DimBaseline`)
- Modify: `internal/anomaly/collect.go` (build the endpoints dimension)
- Modify: `internal/anomaly/scorer_freq.go` (score the endpoints dimension)
- Modify: `internal/anomaly/collect_test.go`, `internal/anomaly/analyze_test.go`

**Interfaces:**
- Consumes: `profile.Behavior.Endpoints`.
- Produces: `Baseline.Endpoints DimBaseline`; a scorer that emits `"endpoint"`-category novelty findings (Medium, capped on low-N — endpoints are like binaries: a new destination is Medium, not High).

- [ ] **Step 1: Write the failing scorer test**

In `internal/anomaly/analyze_test.go` (or a scorer test), assert a candidate contacting a never-before-seen endpoint yields a novel-endpoint finding:

```go
func TestScore_NovelEndpoint(t *testing.T) {
	base := Baseline{
		Target:    "curl",
		Endpoints: DimBaseline{Support: map[string]float64{"1.1.1.1:443": 1.0}, N: 6},
	}
	cand := profile.Behavior{RunID: "r1", Endpoints: []string{"6.6.6.6:443"}}
	got := FrequencyScorer{}.Score(base, cand)
	if !hasFinding(got, "endpoint", "novel endpoint: 6.6.6.6:443") {
		t.Fatalf("expected novel-endpoint finding; got %v", got)
	}
}

// hasFinding is a test helper matching category+title substring.
func hasFinding(fs []Finding, cat, titleContains string) bool {
	for _, f := range fs {
		if f.Category == cat && strings.Contains(f.Title, titleContains) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/anomaly/ -run TestScore_NovelEndpoint -v`
Expected: FAIL — `Baseline.Endpoints` undefined.

- [ ] **Step 3: Add the dimension to `Baseline` and the scorer**

In `internal/anomaly/anomaly.go`, add `Endpoints` to the `Baseline` struct's DimBaseline group:

```go
	Syscalls, Binaries, Files, Caps, Endpoints DimBaseline
```

Update the doc comment on `Finding` category enum to include `endpoint`.

In `internal/anomaly/scorer_freq.go`, add the endpoints dimension to the `dims` slice (Medium novelty, like binary):

```go
		{"endpoint", base.Endpoints, cand.Endpoints, SevMedium},
```

> The existing `for _, d := range dims` loop handles N==0 (not comparable → coverage info finding), low-N capping, and novel/rare emission uniformly. Endpoints need no special-casing beyond membership in the slice. They are NOT part of the file/binary de-dup (an endpoint is neither a file nor an exec'd binary), so no change to the `filterOut`/`splitSyscalls` logic.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/anomaly/ -run TestScore_NovelEndpoint -v`
Expected: PASS.

- [ ] **Step 5: Build the endpoints dimension in `Collect`**

In `internal/anomaly/collect.go`, `buildBaseline`, add the endpoints dimension. Endpoints are observed only on network-capable (eBPF/full-coverage) runs, so build the dimension from the same-coverage-class runs (like syscalls), NOT all runs — otherwise a seccomp baseline run (which never observes endpoints) would make every endpoint look novel:

```go
	// Endpoints are observed only on network-capable (full-coverage/eBPF) runs.
	// Compare only within that class, mirroring syscalls/caps, so a network-blind
	// baseline run never manufactures false endpoint novelty.
	var netRuns []profile.Behavior
	if candFull {
		netRuns = filterBeh(pop, func(b profile.Behavior) bool { return b.FullCoverage })
	}
```

and in the returned `Baseline{...}`:

```go
		Endpoints: buildDim(netRuns, func(b profile.Behavior) []string { return b.Endpoints }),
```

- [ ] **Step 6: Test the collect comparable-N behavior**

In `internal/anomaly/collect_test.go`, add a case: a full-coverage candidate with endpoints, a baseline of full-coverage runs → `base.Endpoints.N > 0`; a seccomp (partial) candidate → `base.Endpoints.N == 0` (not comparable). Mirror the existing syscall/caps comparable-N tests in that file.

Run: `go test ./internal/anomaly/ -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/anomaly/
git commit -m "feat(anomaly): endpoints dimension — novel network destinations vs population baseline (N3)"
```

---

## Task 7: Run net-capture flag, CLI coverage string, and hardware validation runbook

Record network capture on the Run node (so consumers read a real flag, not a `FullCoverage` proxy), reflect it in the detect/malware coverage string, and write the on-hardware validation runbook.

**Files:**
- Modify: `internal/run/run.go` (`NetCapture` field)
- Modify: `internal/ingest/worker.go` (write `net_capture` property)
- Modify: `internal/profile/collect.go` (read `net_capture` into `Behavior`)
- Modify: `internal/profile/profile.go` (`Behavior.NetCapture bool`)
- Modify: `internal/malware/collect.go` (use `b.NetCapture` instead of the `FullCoverage` proxy)
- Modify: the eBPF `learn` wiring in `cmd/jailgraph/main.go` or `internal/run` caller (set `NetCapture=true` for the eBPF backend)
- Create: `docs/superpowers/plans/2026-07-03-network-capture-validation.md` (runbook)

**Interfaces:**
- Consumes: everything above.
- Produces: `run.Session.NetCapture bool`; Run node property `net_capture`; `profile.Behavior.NetCapture bool`.

- [ ] **Step 1: Write the failing test for the Run node net_capture property**

In `internal/ingest/worker_test.go` (follow the existing createRunNode test), assert a session with `NetCapture: true` writes a Run node whose properties include `"net_capture": true`. If no such test exists, add a focused one using the package's fake graph client.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/ingest/ -run TestCreateRunNode -v`
Expected: FAIL — `net_capture` not present / `Session.NetCapture` undefined.

- [ ] **Step 3: Add `NetCapture` to `run.Session` and write it**

In `internal/run/run.go`, add after `WriteCapture`:

```go
	// NetCapture records whether the collector observed network egress
	// (connects + DNS). Only the eBPF backend sets it; seccomp and macOS esf do
	// not observe the network dimension. Distinct from WriteCapture/Coverage.
	NetCapture bool
```

In `internal/ingest/worker.go` `createRunNode`, add to `props`:

```go
		"net_capture":   sess.NetCapture,
```

- [ ] **Step 4: Read it into `Behavior` and use it**

`internal/profile/profile.go`: add `NetCapture bool` to `Behavior`.
`internal/profile/collect.go`: in the Run-node read block, add `b.NetCapture, _ = r.Properties["net_capture"].(bool)`.
`internal/malware/collect.go`: replace `s.NetCapture = b.FullCoverage` with `s.NetCapture = b.NetCapture`.

- [ ] **Step 5: Set NetCapture=true for the eBPF backend**

Find where the eBPF collector's `run.Session` is constructed (grep `WriteCapture = true` / `Coverage = CoverageFull` in `cmd/jailgraph/main.go` `runLearn` and the collector-selection block). Wherever the eBPF backend sets `WriteCapture`/`CoverageFull`, also set `sess.NetCapture = true`. Leave seccomp and esf paths untouched (they remain network-blind).

Run: `grep -rn "WriteCapture\s*=\|CoverageFull\|Coverage =" cmd/jailgraph/main.go internal/run internal/collector`
Expected: locates the eBPF session setup; add the `NetCapture = true` assignment there.

- [ ] **Step 6: Run the full suite**

Run: `go build ./... && go test ./... && go vet ./...`
Expected: PASS, clean. Run `golangci-lint run` — must pass.

- [ ] **Step 7: Write the hardware validation runbook**

Create `docs/superpowers/plans/2026-07-03-network-capture-validation.md` with the exact steps from the spec's Testing section, parameterized for the Fedora box:

```markdown
# Network capture — on-hardware validation runbook

Box: 10.10.2.243 (ddowney), YubiKey sudo for privileged eBPF. Staging: /tmp/jgws
(graphdb on :8080, key in smoke.key, jailgraph-bin). Rebuild:
`/tmp/go/bin/go build -o /tmp/jgws/jailgraph-bin ./cmd/jailgraph`.

Regenerate eBPF bindings first if trace.bpf.c changed (needs docker/clang):
`make bpf-generate` then rebuild. Confirm the verifier accepts all hooks
(no load error from Start) before trusting any result.

## 1. Connect + DNS end-to-end
- Run: `sudo /tmp/jgws/jailgraph-bin learn --collector ebpf -- curl -s https://example.com`
- Then: `jailgraph anomaly --run <id>` / `jailgraph malware --run <id>`
- Expect in graphdb: an :Endpoint node (example.com's IP, port 443, proto tcp),
  a :Domain node (example.com), a RESOLVED edge and a CONNECTED edge from the
  curl process. `jailgraph profile --run <id>` lists the endpoint.

## 2. Beacon dedup
- Run a target that connects to the same host in a loop
  (`while true; do curl -s https://example.com >/dev/null; sleep 5; done`) for ~1 min under learn.
- Expect: ONE :Endpoint node; CONNECTED.count climbs with the loop count; the
  ringbuf is not flooded (no drop counter on the Run for connects — they fold
  in-kernel).

## 3. Raw-IP egress → malware no-DNS signal
- Run: `sudo /tmp/jgws/jailgraph-bin learn --collector ebpf -- curl -s http://93.184.216.34/`
  (a public IP literal; no DNS).
- Then: `jailgraph malware --run <id>`
- Expect: an :Endpoint node, NO :Domain node, and a `network` category finding
  ("public egress with no DNS resolution"). If the target was launched by a
  suspicious lineage (e.g. a curl-named binary spawning sh), the combination
  verdict escalates to High.

## 4. seccomp backend → dimension absent
- Run the same target under `--collector seccomp`.
- Then: `jailgraph anomaly --run <id>` against the eBPF baseline.
- Expect: the endpoints dimension reports "cannot score endpoints — no
  comparable baseline" (NetCapture false → not comparable), NO false endpoint
  novelty, exit 0.

## Honest caveats confirmed here
- ≥High escalation paths are unit-tested; these runs validate capture + graph
  shape + the no-DNS/absent-dimension behavior, not headline verdicts at N>=5.
- DoH/DoT/DNS-over-TCP are not captured (step 1 uses plaintext DNS via the
  system resolver). A DoH client would show an :Endpoint with no :Domain.
```

- [ ] **Step 8: Commit**

```bash
git add internal/run/ internal/ingest/ internal/profile/ internal/malware/ \
        cmd/jailgraph/main.go docs/superpowers/plans/2026-07-03-network-capture-validation.md
git commit -m "feat(run): record net_capture on Run node; validation runbook (N3/N4 wrap)"
```

---

## Self-Review

**Spec coverage:**

| Spec item | Task |
|---|---|
| N1 eBPF connect capture (security_socket_connect, AF_INET/6 filter, in-kernel dedup by (tgid,daddr,dport)+count) | Task 1 |
| N2 collector.EventConnect + :Endpoint node + CONNECTED edge (count) + profile lists endpoints | Task 2 |
| N3 malware network axis (suspicious-lineage+connect, raw-IP no-DNS) | Task 5 |
| N3 anomaly endpoints dimension (comparable-N, low-N cap) | Task 6 |
| N4 DNS capture (udp_sendmsg dport 53, bounded user sample, userspace qname parse, :Domain + RESOLVED) | Tasks 3, 4 |
| Error handling: hook attach = hard error | Existing `c.cleanup(); return err` pattern reused in Tasks 1/3 attach steps |
| Error handling: malformed DNS skipped + counted, never panic (fuzzed) | Task 3 Steps 5–6, 9 (emitErr + return nil) |
| Backends without capture report dimension absent (comparable-N) | Task 6 Step 5 (netRuns), Task 5 (NetCapture observable flag), Task 7 (net_capture flag) |
| macOS/seccomp parity absent | Tasks 5/6/7 gate on NetCapture/FullCoverage; esf & seccomp untouched |
| Caveat: connect attempts not successes | Task 1 Step 5 C comment |
| Caveat: DoH/DoT/TCP not captured | Task 3 Step 7 comment + runbook |
| Hardware validation runbook | Task 7 Step 7 |

No spec requirement is unmapped.

**Placeholder scan:** No "TBD"/"handle appropriately"/"similar to Task N" — every code step shows complete code. The two "adjust to the exact fake-client shape" notes (Task 2 Step 10, Task 4 Step 7) point at existing test helpers whose exact names the implementer must read from the file; the assertion logic is fully specified.

**Type consistency:**
- `connKey`/`connStat` (neutral, Task 1) vs generated `traceConnKey`/`traceConnStat` (Task 1 Step 8) — decode bridges them; padding fields flagged.
- `EndpointKey(ip string, port uint16)` used consistently in Tasks 2 (model) and matched by `splitEndpoint`→`NetEndpoint{IP,Port uint16}` in Task 5.
- `profile.Behavior.Endpoints []string` (`"ip:port"`) produced in Task 2, consumed in Tasks 5 (`splitEndpoint`) and 6 (`buildDim`).
- `collector.EventConnect`/`EventDNS` + fields `DstIP/DstPort/Proto/ConnCount` and `Domain/ResolveCount` defined once (Tasks 2, 4), referenced by ebpf (Tasks 1, 3) and model (Tasks 2, 4).
- `NetCapture` flows `run.Session` → Run node `net_capture` → `profile.Behavior.NetCapture` → `malware.Signals.NetCapture` (Task 7), with the `FullCoverage` proxy used only in the interim (Task 5 Step 5, replaced in Task 7 Step 4).

**Known cross-task build coupling (flagged in Step 0 of Tasks 1 and 3):** the ebpf decode files reference collector kinds/fields added in the paired model task. Land Tasks 1+2 together and 3+4 together (or apply the `collector.go` edits first). This is inherent to keeping the neutral decode logic testable in `internal/ebpf`.
