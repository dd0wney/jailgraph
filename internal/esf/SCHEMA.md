# eslogger JSON schema (pinned from real capture, macOS 26.5)

The macOS backend decodes `eslogger --format json` output. Each line is one
Endpoint Security event as a JSON object. The decoder dispatches on the single
key inside `event` (e.g. `event.exec`), **not** the numeric `event_type` (which
is stable but undocumented) — keying on the payload name is self-documenting and
robust across OS versions.

Pinned field paths (observed live; `unlink` confirmed by the ES C API
`es_event_unlink_t{ es_file_t *target }`, mirroring `write`/`rename`):

| `event.<key>` | type# (obs.) | acting PID | path field |
|---|---|---|---|
| `exec`   | 9  | `process.audit_token.pid` | `event.exec.target.executable.path` (the new image) |
| `open`   | 10 | `process.audit_token.pid` | `event.open.file.path` (+ `event.open.fflag`, int) |
| `fork`   | 11 | `process.audit_token.pid` (parent) | child PID `event.fork.child.audit_token.pid` |
| `exit`   | 15 | `process.audit_token.pid` | `event.exit.stat` (int) |
| `rename` | 25 | `process.audit_token.pid` | `event.rename.source.path` (the victim/old path) |
| `write`  | 33 | `process.audit_token.pid` | `event.write.target.path` |
| `unlink` | —  | `process.audit_token.pid` | `event.unlink.target.path` (by ES C-API analogy; confirm in the M2 live smoke) |

Common envelope on every event: `process.audit_token.pid`, `process.ppid`,
`process.executable.path`.

Notes / known gaps:
- **No byte count.** `es_event_write_t` carries no size, so `write` events give a
  count only — `FileActivity.Bytes` is always 0 on macOS (detect grades
  bytes-adaptively; see internal/detect).
- **System-wide stream.** eslogger reports every process; the backend filters to
  the target's process subtree in userspace (see tracker).
- **Buffering.** eslogger block-buffers stdout to a pipe; the live collector runs
  it under a **pty** so events flush per line (a plain pipe loses the unflushed
  tail on teardown).
