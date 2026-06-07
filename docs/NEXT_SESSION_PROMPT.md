# Next-session prompt

> Singleton — overwritten by each session handoff. Read the latest
> `SESSION_HANDOFF_*.md` for full context.

```
jailgraph is now a validated detection suite. `main` has ransomware `detect`
(structural + entropy), `malware` behaviours, and macOS (esf) + eBPF + seccomp
capture — all runtime-validated on real hardware (Fedora kernel 7.0 + this Mac).

ONE open code thread:
- PR #8 (feat/anomaly): `jailgraph anomaly` — population behavioural anomaly
  detection (living-off-the-land). Clean, independent, advisor-reviewed. Caveat
  stated in the PR: its >=High exit path is unit-test-only (the box has only 2
  /bin/sh runs, so a confident N>=5 baseline is unreachable there). MERGE IT, or
  bank more runs of a binary first to exercise the >=High path on real data.

Workstation 10.10.2.243 is UP and staged (/tmp/jgws: graphdb on :8080, key in
smoke.key, jailgraph-bin). Privileged eBPF runs need the YubiKey.

Open directions, user's to pick (none pressing):
1. Network capture signal (eBPF socket/connect hooks) → unlocks C2/exfil, the one
   threat class jailgraph currently CANNOT see.
2. Learned EmbeddingScorer (JEPA) behind the anomaly Scorer seam — once enough
   runs accumulate to train; reported alongside, not replacing, the statistical
   verdict.
3. Enforcement (observe -> PREVENT): the seccomp user-notify backend can block a
   syscall but always CONTINUEs today — turn a High verdict into an actual block.
4. Fleet threat-hunting / continuous-monitoring daemon over the graph.

Separate repos (NOT jailgraph): nasc Cutover B (wire approval plugin in front of
sudo per CUTOVER_RUNBOOK.md — brick-risk, keep a pkexec recovery shell). stór
70c6231 is already runtime-confirmed.
```
