# jailgraph

Learn a Linux program's real sandbox behavior — the syscalls it makes, the files
it opens, the binaries it execs, its process tree — and store it as a graph in
[graphdb](https://github.com/dd0wney/graphdb). The behavior graph is the
substrate for two follow-on capabilities (not yet built): **generating** a
least-privilege seccomp + firejail profile, and **auditing** a running program
for drift from its learned baseline.

This repository implements **increment 1 (observe → store)** and **increment 2
(profile generator)**. The drift auditor and an eBPF collector backend are
separate, later increments.

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

# Generate sandbox profiles from a learned run (prints the run id on completion).
jailgraph profile --run <run-id> --format both --out ./myapp
```

### Profile strength (read this before trusting a generated profile)

`jailgraph profile` emits a **firejail** profile and an **OCI seccomp** profile.
Be precise about what each is:

- The firejail **filesystem + exec whitelist is evidence-based** — exactly the
  files opened and binaries exec'd during the run. This is the real value-add.
- The **seccomp policy is "permissive baseline minus dangerous-syscall gating,"
  not a least-privilege allowlist.** The collector watches only rare,
  security-relevant syscalls (not the hot path), so the profile *denies the
  dangerous syscalls the run never used* (`setns`, `unshare`, `capset`, legacy
  `open`, `fork`, …) over a default-allow baseline. A tight allowlist needs the
  eBPF backend's full coverage (a later increment).
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

Increments 1 and 2 are implemented and tested. The portable pipeline
(collect→buffer→aggregate→ingest) and the profile generator
(collect→render firejail/seccomp) are validated by unit tests and by end-to-end
runs against a real graphdb. The Linux seccomp backend is validated at runtime
on linux/arm64 (Docker) and on the Linux CI job (see Testing above).
