# Network capture (phase 1 — C2 signal)

**Date**: 2026-07-03
**Status**: approved (design review 2026-07-03)
**Scope**: Linux eBPF backend only. macOS eslogger and seccomp backends report the
network dimension as absent.

## Problem

jailgraph has no network visibility. The 2026-06-07 handoff names this as the
gating signal for the entire C2/exfiltration threat class: `malware` and
`anomaly` cannot see command-and-control traffic at all today. This spec adds
the first network capture axis — egress connections and DNS resolution —
attributed to processes, flowing through the existing
`BehaviorEvent → EventToGraph → graphdb` pipeline.

**Explicitly out of scope (phase 2 and later):**

- Byte-volume accounting (sendmsg/recvmsg stats) — required for exfiltration
  detection; deferred to keep the new kernel surface small.
- Inbound lifecycle (bind/listen/accept) — reverse/bind-shell visibility;
  deferred because no consumer heuristic exists for it yet.
- AF_UNIX sockets — local IPC noise, not a C2 vector.
- macOS parity — eslogger network events are a separate investigation.

## Approaches considered

1. **Connect + DNS via eBPF fentry hooks (chosen)** — mirrors how every prior
   capture axis landed (structural detect first, entropy second). Smallest
   verified-on-hardware step that produces a usable C2 signal; both existing
   consumers can use it immediately.
2. **Full socket lifecycle** — adds bind-shell visibility, but is capture
   without a consumer: the malware analyzer has no inbound heuristics yet.
3. **Connect + volume in one phase** — unlocks exfil immediately but doubles
   the new kernel code, and a per-socket stats map is the riskiest verifier
   territory. Contradicts the land-small-validate-on-hardware discipline.
4. **Packet capture (AF_PACKET/pcap)** — ruled out: wrong layer. jailgraph's
   identity is process-attributed behaviour; socket hooks give attribution for
   free, pcap does not.

## Design

Four milestones (N1–N4), same shape as the anomaly M1–M4 series. Each lands as
its own reviewable commit(s); hardware validation on the Fedora box closes the
phase.

### N1 — eBPF connect capture

New hook in `internal/ebpf/bpf/trace.bpf.c`:

- `fentry/security_socket_connect` — fires once per connect attempt with the
  socket and userspace `sockaddr` in kernel-readable form.
- Filter: `AF_INET` and `AF_INET6` only. Read family, destination address,
  destination port, and socket protocol (TCP/UDP).
- **In-kernel dedup**: a hash map keyed `(tgid, daddr, dport)` (same pattern as
  the existing `seen` map) with a per-key count. First occurrence emits a ring
  buffer event; repeats increment the count in place. A beaconing loop must
  not flood the ring buffer; the count is drained at collector shutdown like
  `write_stats`.
- Event payload: `{family, protocol, daddr (16 bytes, v4-mapped ok), dport,
  count}` plus the standard pid/ppid/exe preamble.

### N2 — collector + model

- New `collector.EventConnect` kind on `BehaviorEvent`, carrying
  `Family`, `Proto`, `DstIP` (string, normalized), `DstPort`, `ConnCount`.
- `model.EventToGraph` maps it to:
  - `:Endpoint` node, natural key `endpoint:<ip>:<port>`, properties
    `ip`, `port`, `proto`.
  - `CONNECTED` edge Process→Endpoint with `count`, aggregated by the
    aggregator exactly like `INVOKED`.
- `jailgraph profile` output lists contacted endpoints.

### N3 — consumers

- **`malware` network axis**: connect events join threat combination.
  Heuristics, in order of confidence:
  - Outbound connect from a process with an already-suspicious lineage
    (dropper→C2 combo) — escalates the combination.
  - Connect to a raw IP with no preceding DNS resolution for that address
    (requires N4 data; before N4 this heuristic stays dormant, not
    false-firing).
- **`anomaly` endpoints dimension**: novel destination endpoint vs the
  population baseline, using the existing frequency scorer and per-dimension
  comparable-N. Runs captured by seccomp (or esf) carry no endpoint data →
  the dimension is not comparable for them → excluded from N, exactly as the
  mixed-backend design already handles. Confidence caps at low N as today.

### N4 — DNS resolution capture

- New hook `fentry/udp_sendmsg`, filtered to destination port 53.
- Samples the query payload with a bounded `bpf_probe_read_user` — the
  precedent is `WRITE_SAMPLE_LEN` entropy sampling. Sample length 128 bytes
  (a qname fits; over-long queries are truncated and counted, not parsed).
- **Qname parsing happens in userspace** (collector), never in eBPF: label
  decompression and validation are not verifier-friendly and don't need to be.
- Model: `:Domain` node (key `domain:<name>`, property `name`) with a
  `RESOLVED` edge Process→Domain (`count`). No answer/IP correlation in this
  phase — `RESOLVED` records that the name was queried, not what it returned.
  The malware raw-IP heuristic therefore keys on "this process performed no
  DNS at all before connecting", not per-address matching.

## Error handling

- Hook attach failure is a **hard error** — the run aborts rather than
  degrading silently to network-blind capture that looks complete.
- Ring buffer drops are counted and reported, as today.
- Malformed or truncated DNS payloads are skipped with a counted stat in the
  collector; never a parse panic (parser is fuzz-tested against garbage).
- Backends without network capture (seccomp, esf) report the dimension as
  absent; consumers already handle absent dimensions via comparable-N.

## Testing

- TDD throughout; table-driven unit tests per repo convention.
- Fake-collector tests for `EventConnect` and DNS events end-to-end through
  `EventToGraph` (node/edge shape, key format, count aggregation).
- Userspace DNS qname parser: table-driven tests incl. truncation,
  compression pointers, garbage input; a fuzz target.
- eBPF-side: build-and-load smoke via the existing `stor_integration_test.go`
  pattern where possible.
- **Hardware validation runbook** (Fedora `10.10.2.243`, `/tmp/jgws`, YubiKey
  sudo):
  1. `curl https://example.com` under capture → `:Endpoint` (443/tcp) and
     `:Domain` (example.com) nodes with edges in graphdb.
  2. Beacon loop (`while true; do curl …; sleep 5; done`, ~1 min) → one
     `:Endpoint` node, `CONNECTED.count` climbs; ring buffer not flooded.
  3. Raw-IP connect (`curl http://<ip>/`) → endpoint present, no `RESOLVED`
     edge → malware no-DNS signal fires.
  4. seccomp-backend run of the same target → anomaly reports endpoints
     dimension not comparable, no false novelty.

## Honest caveats (stated up front)

- Like every prior axis, ≥High escalation paths in `malware` get unit-test
  coverage; hardware runs validate capture and graph shape, not headline
  verdicts.
- `security_socket_connect` sees connect *attempts*, not successes. Phase 1
  does not distinguish — a C2 beacon that never connects is still signal.
- Connected-UDP resolvers are the common glibc/systemd-resolved path, but a
  resolver using unconnected `sendto` still hits `udp_sendmsg` (hooked);
  DNS-over-TCP and DoH/DoT are **not** captured — DoH looks like ordinary
  TLS egress (an `:Endpoint`, no `:Domain`).
