# jailgraph

Learn a Linux program's real sandbox behavior — the syscalls it makes, the files
it opens, the binaries it execs, its process tree — and store it as a graph in
[graphdb](https://github.com/dd0wney/graphdb). The behavior graph is the
substrate for two follow-on capabilities (not yet built): **generating** a
least-privilege seccomp + firejail profile, and **auditing** a running program
for drift from its learned baseline.

This repository implements **increment 1 (observe → store)**, **increment 2
(profile generator)**, **increment 3 (drift auditor)**, and **increment 4 (eBPF
collector backend)**.

### Collector backends

Two interchangeable backends satisfy the same `Collector` interface:

- **seccomp** (`--collector seccomp`, default) — seccomp user-notify. Watches a
  curated set of rare, security-relevant syscalls (never the hot path), so it is
  light but its syscall view is intentionally partial.
- **eBPF** (`--collector ebpf`, Linux + `CAP_BPF`) — a `raw_tracepoint/sys_enter`
  program sees the **full** syscall set, including the read/write/mmap hot path,
  recording each `(pid, syscall)` once in-kernel. This full coverage is what
  enables a genuinely tight (default-deny) seccomp profile rather than
  baseline+gating.
  - **v1.0 scope/limitations** (honest): it traces the **seeded target PID
    only** — descendant following via `sched_process_fork` is v1.1, so trace a
    process that does its own work (or wait for v1.1 for shell pipelines).
    There is a small **startup race** (a few syscalls before the PID is seeded).
    The `nr→name` table is partial (common + gateable syscalls named; others
    `sys_<nr>`). Inside a container, run with `--pid=host` so the BPF
    root-namespace PID matches (on a real host they always match).

## How it works

```
target program
      │  (seccomp user-notify: rare syscalls trap, observe-only, always CONTINUE)
      ▼
  Collector  ──►  ring buffer  ──►  ingest worker  ──►  graphdb (REST, batched)
 (seccomp /        (bounded,         (two-phase:
  eBPF later)       drop-newest)      dedup → nodes → edges)
```

- **Collector** (`internal/collector`) — the stable contract. It emits *decoded*
  `BehaviorEvent`s, so the seccomp backend (`internal/seccomp`, Linux-only) and a
  future eBPF backend are interchangeable. The capture path is observe-only: it
  answers every seccomp notification with `CONTINUE` and never blocks the target.
- **Ring buffer** (`internal/buffer`) — decouples the latency-critical capture
  path from ingestion. Non-blocking; on overflow it drops the *newest* event
  (preserving the structural backbone that bursts at process start) and accounts
  for every drop, marking the run lossy.
- **Ingest worker** (`internal/ingest`) — writes the graph in two phases (nodes,
  then edges) so edges can reference assigned node ids. Deduplicates shared nodes
  client-side (graphdb enforces no server-side uniqueness for these labels),
  reconciles graphdb's partial, out-of-order batch responses by an echoed key,
  and quarantines edges whose endpoints were dropped.

## Behavior-graph schema

Nodes: `Run`, `Process`, `Binary`, `Syscall`, `File`, `Capability`, `Namespace`.
Edges: `PART_OF`, `SPAWNED`, `EXEC`, `INVOKED` (with count), `OPENED` (with mode),
`HELD_CAP`, `JOINED_NS`. Shared nodes (`Binary`/`Syscall`/`File`/...) are
content-keyed and reused across runs; `Process`/`Run` are per-run.

## Usage

```sh
# Live trace (Linux only): learn what /bin/sh does running a command.
jailgraph learn --graphdb-url http://localhost:8080 --api-key "$KEY" \
  -- /bin/sh -c 'cat /etc/hostname'

# Replay recorded events through the same ingest pipeline (any platform).
jailgraph learn --replay testdata/events.json --api-key "$KEY"

# Full syscall coverage via eBPF (Linux + CAP_BPF; --collector ebpf).
jailgraph learn --collector ebpf -- /usr/bin/myapp

# Generate sandbox profiles from a learned run (prints the run id on completion).
jailgraph profile --run <run-id> --format both --out ./myapp

# Audit a candidate run for drift against a trusted (unioned) baseline.
# Exit codes: 0 = no drift, 1 = drift detected, 2 = could not audit.
jailgraph audit --baseline <run1>,<run2> --against <run3> --mode security
```

### Drift audit (`jailgraph audit`)

Compares a candidate run against a baseline (union of one or more trusted runs —
more runs = fewer false positives) and reports drift, **dimension-aware** because
the dimensions are not equally trustworthy:

- **Syscalls** (the rare watched set) — high signal; drives the verdict. A run
  suddenly calling `setns`/`execve` it never did is a real anomaly.
- **Binaries** exec'd — medium signal; drives the verdict.
- **Files** — *low confidence*. Programs open volatile paths (`/tmp/XXXX`,
  `/proc/<pid>/…`) every run, so paths are normalized (volatile prefixes
  bucketed, digit runs collapsed) and reported **separately, never driving the
  verdict**.

Two modes: **security** flags additive drift (candidate did something new — the
anomaly signal); **reproducibility** flags any symmetric stable-dimension drift
between runs of the same derivation. Note: reproducibility mode is impurity-
*signal* detection, **not** trace-equality — reproducible builds guarantee
deterministic output, not deterministic traces. Strong impurity signals like
network access or undeclared-input reads need the (later) eBPF backend. Lossy
runs are refused unless `--force`.

### Profile strength (read this before trusting a generated profile)

`jailgraph profile` emits a **firejail** profile and an **OCI seccomp** profile.
Be precise about what each is:

- The firejail **filesystem + exec whitelist is evidence-based** — exactly the
  files opened and binaries exec'd during the run. This is the real value-add.
- The **seccomp policy depends on coverage** (recorded on the run):
  - **Partial coverage (seccomp backend):** default-ALLOW minus the dangerous
    syscalls the run never used (`setns`, `unshare`, `capset`, legacy `open`,
    `fork`, …). NOT a least-privilege allowlist.
  - **Full coverage (eBPF backend):** a true **least-privilege allowlist**
    (default-deny). It permits the observed syscalls plus a small *safe runtime
    floor* (universal startup syscalls, excluding every dangerous one) and denies
    everything else. It defaults to **complain mode** (`SCMP_ACT_LOG`) — deploy
    it safely, it breaks nothing and logs would-be denials so you can confirm
    coverage. `--enforce` switches to `SCMP_ACT_ERRNO`, and is **refused** if the
    run was lossy or any observed syscall is recorded by number only (which would
    be wrongly denied). Build the baseline from a **union of representative runs**
    before enforcing — one run misses error/signal paths, and v1.0 eBPF traces
    only the seeded PID (not children).
- Capability/namespace policy is **not** emitted from observation yet; firejail
  output uses a conservative `caps.drop all` default, labeled as such.
- A **lossy** run (events were dropped) is refused by default — the profile would
  be over-restrictive and break the program. Override with `--force`.

graphdb connection: `--graphdb-url` (or `JAILGRAPH_GRAPHDB_URL`) and `--api-key`
(or `JAILGRAPH_API_KEY`). The API key is provisioned out of band via graphdb's
admin-only `POST /api/v1/apikeys`.

## Platform support & testing

The seccomp backend requires **Linux** (kernel ≥ 5.0 for user-notify). On other
platforms the collector returns `ErrUnsupportedPlatform`; the rest of the tool
builds and runs, and `--replay` exercises the full ingest pipeline.

- `make test` — cross-platform unit tests (the bulk: ring, model, aggregation,
  the ingest worker's reconciliation/dedup/quarantine, client retry/pagination).
  *Validated.*
- `make integration` — the full ingest pipeline against a **real local graphdb**
  (set `JAILGRAPH_GRAPHDB_URL`/`JAILGRAPH_API_KEY`); no Linux tracing required.
  *Validated* end-to-end against a real graphdb server, including cross-run dedup
  and persistence read-back.
- The Linux seccomp backend is *cross-compiled for amd64/arm64 with compile-time
  ABI struct-size assertions*, and its **runtime** behavior is validated by a
  build-tagged trace test (`-tags linux_integration`, traces `/bin/sh` and
  asserts the emitted `exec` + `/etc/hostname` open). *Validated* on linux/arm64
  via `docker run --security-opt seccomp=unconfined ... go test -tags
  linux_integration`; the same test runs on the Linux CI job.
- The eBPF backend's BPF object + bindings are generated by `bpf2go` and
  committed (`go build` needs no clang). `make bpf-generate` regenerates them via
  the multi-stage build's clang toolchain. Runtime validation: `make ebpf-test`
  (privileged, `--pid=host`) confirms full syscall coverage — *validated on
  linux/arm64* (observed 17 distinct syscalls for `cat`, including read/write/mmap).

## Positioning (related work)

- **vs. Lynis** — Lynis is a *static system-configuration auditor* (breadth-first
  hardening checks + compliance mappings). jailgraph is a *runtime behavioral
  profiler* of individual programs. Different axes; complementary. Where they
  touch — hardening advice — jailgraph aims to be *evidence-based* (a concrete
  per-program seccomp/firejail profile derived from observed behavior) rather
  than rule-based, and the graph enables fleet-scale queries a per-host report
  can't express. jailgraph does not do static config / package / compliance
  auditing.
- **vs. static AV (e.g. hash/YARA scanners)** — different axis again: static
  known-bad *file* identification vs. runtime confinement of trusted programs.
  Out of scope. *Behavioral* ransomware detection is a natural future analyzer
  over the auditor track, but it needs file-write/IO signals that favor the
  (later) eBPF backend.

## Status

Increments 1–4 are implemented and tested. The portable pipeline
(collect→buffer→aggregate→ingest), the profile generator, and the drift auditor
are validated by unit tests and end-to-end runs against a real graphdb. Both
Linux backends are validated at runtime on linux/arm64 (Docker): the seccomp
trace and the eBPF full-syscall-coverage test. The eBPF backend traces the
seeded target PID only (descendant following is v1.1).
