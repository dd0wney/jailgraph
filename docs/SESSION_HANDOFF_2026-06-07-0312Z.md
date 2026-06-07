# Session handoff — 2026-06-07 03:12 UTC

**Date**: 2026-06-07 (one long session)
**Outgoing model**: Claude Opus 4.8 (1M context)
**Repo**: `github.com/dd0wney/jailgraph` (all this session's work was here; another agent owns graphdb)

## TL;DR

jailgraph went from a capture+profile tool to a **validated detection suite**. `main`
now has the ransomware `detect` (structural **+ content entropy**), the `malware`
behavioural analyzer, the macOS **eslogger** capture backend, and the eBPF
write-capture — **all runtime-validated on real hardware** (Fedora kernel 7.0 and
this Mac). The one open thread is **PR #8 (`anomaly`)** — a population behavioural
anomaly detector — awaiting review/merge. The Fedora workstation (`10.10.2.243`) is
**up** and staged (`/tmp/jgws`: graphdb running, `jailgraph-bin`, `smoke.key`).

## What's done this session

| PR | Feature | State |
|---|---|---|
| #2 | `jailgraph report` — Lynis-style hardening analyzer | ✅ merged |
| #3 | ransomware `detect` — capture layer + structural detector | ✅ merged |
| #5 | macOS support — **eslogger (Endpoint Security)** capture backend | ✅ merged (superseded draft #4) |
| #6 | `jailgraph malware` — behavioural threat-combination (persistence/lineage/privesc/creds) | ✅ merged |
| #7 | ransomware **entropy** axis (phase 2) | ✅ merged |
| **#8** | `jailgraph anomaly` — **population behavioural anomaly** (LOTL) | **OPEN — review/merge** |

**Runtime validations (the session's backbone):**
- **eBPF write/rename/unlink capture** on kernel 7.0: loads (verifier ok), real paths (210/213), accurate churn → `detect` end-to-end. Closed the caveat carried since #3 merged.
- **eBPF entropy** (#7): encrypted writes measured **7.18** bits/byte vs plaintext **3.09**; caught a calibration bug (a 256-byte sample caps ~7.2, not 8.0 → recalibrated 6.8/4.5) and switched mean→**fraction** (dilution-robust) after review; 91% high-entropy → escalate.
- **macOS eslogger** on this Mac: captured a target's 40 writes/20 renames/40 unlinks under a pty; first end-to-end `FileActivity → detect`.
- **malware lineage** on box: a `curl`-named binary spawning `/bin/sh` → lineage + privesc → **High** on real graphdb data (validated the new Process-node `pid/ppid/exe` read).
- **anomaly** (#8) on box: scored one `/bin/sh` run vs the other → read the cross-run population, flagged genuine novelty (`head`/`yes`/`/dev/urandom`), correctly **capped all to Info at N=1** with explicit low-confidence findings → exit 0.

## Key decisions

- **"Build JEPA agents?" → No, build the *seam*.** The anomaly detector is statistical
  (frequency support, explainable, no black-box score) behind a pluggable `Scorer`
  interface; a learned `EmbeddingScorer` (JEPA) slots in **later** once there's data,
  reported alongside, not replacing. ~a dozen runs is far too little to train, and a
  score-without-explanation fights the project's discipline. "Self-improving" =
  baseline grows from confirmed-normal runs (incremental), not an autonomous agent
  (baseline-poisoning risk).
- **Anomaly honesty mechanisms:** per-dimension *comparable-N* (handles mixed seccomp/eBPF
  baselines); confidence scales with N; **syscall novelty scoped to the gateable set**
  (the full eBPF set drifts on hot-path jitter — `futex`/`sched_yield` — and would flap
  exit 1; advisor-caught).

## Current state

`main` @ `5c0082c` (clean): profile / audit / report / **detect (ransomware: structural+entropy)** /
**malware** / eBPF+seccomp+**esf(macOS)** backends. Builds darwin + linux, all tests green.
`feat/anomaly` (PR #8, 7 commits) adds `internal/anomaly` + `jailgraph anomaly` + exports
`audit.NormalizePath`.

## Honest caveats (carried forward)

- **PR #8 anomaly ≥High exit path is unit-test-only.** The box has only 2 `/bin/sh` runs, so
  N≥5 (confident) is unreachable there; the real-data run validated the cross-run read +
  novelty detection + the confidence cap, NOT the headline verdict. Stated in #8's body.
- **C2/exfil are out** of the anomaly/detection reach — jailgraph has **no network capture**
  (no socket/connect eBPF hooks). That's the gating signal for that whole threat class.

## Next steps (user's to direct)

1. **Merge PR #8** (anomaly) — clean, independent.
2. Detection-depth follow-ons (designed/deferred): a **network capture signal** (eBPF socket
   hooks) to unlock C2/exfil; a learned `EmbeddingScorer` once runs accumulate; `writev`/`mmap`
   write capture (the documented eBPF blind spot).
3. **Other "next-level" directions NOT taken** (offered, user chose anomaly): enforcement
   (observe→**prevent** — the seccomp user-notify backend can block but always CONTINUEs);
   fleet threat-hunting over the graph; a continuous-monitoring daemon.
4. **nasc Cutover B** (separate repo `github.com/nasc`): wire the approval plugin in front of
   sudo per its `CUTOVER_RUNBOOK.md` so future privileged runs are remote-approved (no desk-key
   tap). Brick-risk; keep a pkexec recovery shell open. (Still pending from the prior handoff.)

## Context to remember

- Workstation `10.10.2.243` (`ddowney`), sudo needs the **YubiKey** for privileged eBPF runs;
  `/tmp/jgws` has graphdb (`:8080`, key in `smoke.key`), `jailgraph-bin`. `/tmp/jgws/jailgraph`
  is the synced source — rebuild with `/tmp/go/bin/go build -o /tmp/jgws/jailgraph-bin ./cmd/jailgraph`.
- graphdb consumer contracts CC7-9 are pinned (regression-tested in graphdb PR #319); `Traverse`
  returns NODES not edges (drove the per-run-node designs); `NodesByLabel` returns full properties
  (enabled the malware lineage + anomaly cross-run reads).
- macOS esf: needs sudo + **Full Disk Access**; eslogger under a **pty** (block-buffering drops the
  tail otherwise); no write byte count, no syscalls/caps.
