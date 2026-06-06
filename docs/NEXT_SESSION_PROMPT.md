# Next-session prompt

> Singleton — overwritten by each session handoff. Read the latest
> `SESSION_HANDOFF_*.md` for full context.

```
jailgraph has no open code threads — it is feature-complete and the amd64 stór
convergence is now VALIDATED.

DONE 2026-06-06: amd64 jailgraph×stór reproducibility convergence validated on the
Fedora workstation (kernel 7.0.10-201.fc44, native, BTF). Privileged
TestStor_ReproducibilityConvergence → PASS: two genuine builds (built=2 cached=0
each), 68 distinct syscalls, 3 binaries, no structural drift (tolerated hot-path
noise +tgkill/-sched_yield). This also runtime-confirmed stór's read-only-store
remount fix (70c6231) on a 7.0 kernel — its first real exercise. README's
"stór reproducibility convergence" section now records both arch legs.

No jailgraph work is queued. Two threads, both the USER's to direct:

1. stór side: relay that 70c6231 is runtime-confirmed (separate repo — do NOT edit
   it from jailgraph).
2. nasc Cutover B (separate repo, github.com/nasc): wire the approval plugin +
   eligibility hook in front of sudo per nasc's CUTOVER_RUNBOOK.md so future
   privileged jailgraph runs can be remote-approved instead of needing a local
   desk-key tap. Brick-risk; follow the runbook with an independent pkexec
   recovery shell open.

Open question for the user (from the prior handoff): wind jailgraph down to
maintenance, or pull a deferred analyzer (behavioral-ransomware detection /
Lynis-style hardening report over the auditor) onto the active queue?
```
