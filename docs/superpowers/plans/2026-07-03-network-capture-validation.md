# Network capture — on-hardware validation runbook

Box: 10.10.2.243 (ddowney), YubiKey sudo for privileged eBPF. Staging: /tmp/jgws
(graphdb on :8080, key in smoke.key, jailgraph-bin). Rebuild:
`/tmp/go/bin/go build -o /tmp/jgws/jailgraph-bin ./cmd/jailgraph`.

Regenerate eBPF bindings first if trace.bpf.c changed (needs docker/clang):
`make bpf-generate` then rebuild. Confirm the verifier accepts all hooks
(no load error from Start) before trusting any result.

## Why this document exists

The eBPF hooks added for network capture (`security_socket_connect`,
`udp_sendmsg`) cannot be compiled, loaded, or verifier-checked in the build
environment this feature was developed in (no docker/clang toolchain, no
privileged kernel access). Everything below THE RUNTIME RISKS section is
covered by unit tests that exercise the decode/parse logic without a kernel;
but whether the hooks actually fire, actually read the right memory, and
actually produce the data those decoders expect has **never been observed on
real hardware**. This runbook is the only place that gets checked. Do not
skip it and do not report the feature "done" without running it.

## eBPF runtime risks to verify FIRST on the box

These are known, specific ways the capture can silently produce nothing (or
wrong data) despite the verifier accepting the program and the run completing
with no errors. Check them in this order — #1 is the one most likely to make
DNS capture look "done" in this codebase but produce zero :Domain nodes on
real traffic.

### 1. ITER_UBUF may make DNS capture silently no-op (HIGHEST PRIORITY)

The `udp_sendmsg` hook reads the query payload via
`BPF_CORE_READ(iov, iov_base)` off `msg->msg_iter.__iov`. That code path
assumes the iterator is in the classic `ITER_IOVEC` state, where `__iov` is a
real `struct iovec *` pointing at kernel-visible iovec structs.

On modern kernels, the common single-buffer `sendto()`/`sendmsg()` fast path
uses **`ITER_UBUF`** instead. In that state the `__iov`/`__ubuf` union slot
does not hold an iovec pointer — it holds (or aliases) the **user buffer
address directly**. Reading it as `struct iovec` and then doing
`BPF_CORE_READ(iov, iov_base)` on the result reads *through* a user pointer
that was never a valid `iovec*`, so the hook either reads garbage, reads a
zero/null base (and bails via the `!base` check), or reads unrelated memory.
Either way: **no ringbuf submit, no EVENT_DNS, no :Domain node — and nothing
in the run's error log, because the hook returns 0 cleanly.** This is a
silent no-op, not a crash or a logged failure.

**Box step:**
1. Run step 1 below (`curl https://example.com`, which does a real
   plaintext DNS resolution via the system resolver).
2. Query graphdb for a `:Domain` node named `example.com` for that run.
3. **If it is absent**, this is not proof DNS didn't happen — it may be proof
   the hook silently no-op'd. Before concluding anything:
   - Inspect `msg->msg_iter.iter_type` (or the CO-RE equivalent field, check
     `vmlinux.h` for the running kernel) at hook entry to confirm which state
     the iterator was actually in.
   - If it reads `ITER_UBUF`, add a branch that reads the user address via
     the `__ubuf`/`ubuf` union member directly (`bpf_probe_read_user` against
     that address, not through a synthesized `iovec`), instead of assuming
     `ITER_IOVEC` layout unconditionally.
   - Re-run step 1 after the fix and re-confirm the :Domain node appears.
4. Do **not** report N4 (DNS capture) validated until this specific check has
   been done — a clean run with no errors and no :Domain node is exactly what
   this failure mode looks like, and is easy to misread as "the target just
   didn't do DNS."

### 2. Unconnected sendto() is not captured

The hook keys the destination port off the connected socket
(`sk->__sk_common.skc_dport`). A `connect()`ed UDP socket followed by `send()`
carries this correctly. An **unconnected** `sendto(sock, ..., dest_addr)` —
common in some resolver implementations that don't `connect()` their UDP
socket before sending each query — does not populate `skc_dport` with the
per-call destination, so the port filter never matches `DNS_PORT` and the
query is invisible to this hook.

**Box step:** identify which DNS path the box's resolver stack actually uses
(glibc `res_send`/`__res_context_send` vs `systemd-resolved` vs `nss-dns` vs
a stub resolver in a container) and note explicitly whether it uses a
connected or unconnected UDP socket per query. If the box runs
`systemd-resolved` (common on Fedora, which this box's OS suggests), queries
from user processes typically go over a local stub-resolver socket to
`127.0.0.53:53`, and `systemd-resolved` itself makes the upstream query —
confirm which process (the target, or `systemd-resolved`) is the one
`tracked` by the collector, since the hook only fires for tracked tgids.

### 3. Short-buffer over-read (low priority)

The hook always reads a fixed `DNS_SAMPLE_LEN` (256 bytes) from the user
buffer regardless of the actual `iov_len`. If `iov_len < 256` and the buffer
sits near a page boundary, `bpf_probe_read_user` reading past the end of the
mapped page fails and the event is discarded (`bpf_ringbuf_discard`) rather
than partially decoded — this is a silent drop of one query, not a crash.
Low priority: note whether this occurs in practice (small DNS queries are the
common case, so this may fire often), but a single dropped query is much
lower severity than DNS capture no-op'ing entirely (#1).

---

## Functional validation scenarios

Run these after confirming (or fixing) the risks above. Each targets one
piece of the spec (N1–N4, malware network axis, anomaly endpoints dimension).

### 1. Connect + DNS end-to-end
- Run: `sudo /tmp/jgws/jailgraph-bin learn --collector ebpf -- curl -s https://example.com`
- Then: `jailgraph anomaly --run <id>` / `jailgraph malware --run <id>`
- Expect in graphdb: an :Endpoint node (example.com's IP, port 443, proto tcp),
  a :Domain node (example.com), a RESOLVED edge and a CONNECTED edge from the
  curl process. `jailgraph profile --run <id>` lists the endpoint.
- This is also the check for runtime risk #1 above — if the :Domain node is
  missing, do not move on until that's resolved (or explicitly understood).

### 2. Beacon dedup
- Run a target that connects to the same host in a loop
  (`while true; do curl -s https://example.com >/dev/null; sleep 5; done`) for ~1 min under learn.
- Expect: ONE :Endpoint node; CONNECTED.count climbs with the loop count; the
  ringbuf is not flooded (no drop counter on the Run for connects — they fold
  in-kernel).

### 3. Raw-IP egress → malware no-DNS signal
- Run: `sudo /tmp/jgws/jailgraph-bin learn --collector ebpf -- curl -s http://93.184.216.34/`
  (a public IP literal; no DNS).
- Then: `jailgraph malware --run <id>`
- Expect: an :Endpoint node, NO :Domain node, and a `network` category finding
  ("public egress with no DNS resolution"). If the target was launched by a
  suspicious lineage (e.g. a curl-named binary spawning sh), the combination
  verdict escalates to High.
- Cross-check against risk #1: this scenario's absence of a :Domain node is
  *expected* (no DNS was performed at all), unlike scenario 1 where its
  absence would be suspicious.

### 4. seccomp backend → dimension absent
- Run the same target under `--collector seccomp`.
- Then: `jailgraph anomaly --run <id>` against the eBPF baseline.
- Expect: the endpoints dimension reports "cannot score endpoints — no
  comparable baseline" (NetCapture false → not comparable), NO false endpoint
  novelty, exit 0.
- Also confirm the Run node's `net_capture` property is `false` for this run
  (via the graphdb API or `jailgraph profile --run <id>`), and `true` for the
  eBPF runs in scenarios 1–3 — this is the flag this task (Task 7) adds, and
  it is what gates the "absent" behavior above.

## Honest caveats confirmed here

- ≥High escalation paths are unit-tested; these runs validate capture + graph
  shape + the no-DNS/absent-dimension behavior, not headline verdicts at N>=5.
- DoH/DoT/DNS-over-TCP are not captured (step 1 uses plaintext DNS via the
  system resolver). A DoH client would show an :Endpoint with no :Domain —
  indistinguishable in the graph from the raw-IP-no-DNS case in scenario 3.
  This is a known, accepted blind spot (documented in the network-capture
  plan), not a bug to chase on the box.
- If runtime risk #1 (ITER_UBUF) turns out to affect this kernel, DNS capture
  (N4) is not validated until the fix lands and scenario 1 is re-run
  end-to-end. Do not report N4 "validated on hardware" on the strength of a
  clean run alone — the :Domain node must actually be present.
