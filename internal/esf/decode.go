// Package esf is the macOS capture backend: it traces a target by spawning
// Apple's `eslogger` CLI (Endpoint Security, no entitlement needed — eslogger is
// Apple-signed) and decoding its JSON event stream into collector.BehaviorEvents.
//
// This file is the pure, platform-neutral decoder: a JSON line → an intermediate
// esEvent. It has no build tag so it compiles and is unit-tested on every
// platform (Linux CI included). The darwin-only live wiring is in
// collector_darwin.go; see SCHEMA.md for the pinned eslogger field paths.
package esf

import "encoding/json"

// esKind classifies a decoded eslogger event (dispatched on the `event` payload
// key, not the numeric event_type — see SCHEMA.md).
type esKind int

const (
	esUnknown esKind = iota
	esExec
	esFork
	esExit
	esOpen
	esWrite
	esRename
	esUnlink
)

// esEvent is one eslogger line reduced to the fields the tracker needs.
type esEvent struct {
	Kind     esKind
	PID      int32  // acting process (process.audit_token.pid)
	PPID     int32  // process.ppid
	ChildPID int32  // fork only (event.fork.child.audit_token.pid)
	ExePath  string // exec only (the new image)
	Path     string // open/write/rename/unlink target
	Flags    uint32 // open fflag
}

// decodeLine parses one eslogger JSON line. ok=false (err=nil) means a
// subscribed-but-unmapped line we skip; err is returned only for malformed JSON.
func decodeLine(b []byte) (esEvent, bool, error) {
	var raw struct {
		Process struct {
			AuditToken struct {
				PID int32 `json:"pid"`
			} `json:"audit_token"`
			PPID int32 `json:"ppid"`
		} `json:"process"`
		Event map[string]json.RawMessage `json:"event"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return esEvent{}, false, err
	}

	e := esEvent{PID: raw.Process.AuditToken.PID, PPID: raw.Process.PPID}
	for key, payload := range raw.Event {
		switch key {
		case "exec":
			e.Kind = esExec
			var p struct {
				Target struct {
					Executable struct {
						Path string `json:"path"`
					} `json:"executable"`
				} `json:"target"`
			}
			_ = json.Unmarshal(payload, &p)
			e.ExePath = p.Target.Executable.Path
		case "fork":
			e.Kind = esFork
			var p struct {
				Child struct {
					AuditToken struct {
						PID int32 `json:"pid"`
					} `json:"audit_token"`
				} `json:"child"`
			}
			_ = json.Unmarshal(payload, &p)
			e.ChildPID = p.Child.AuditToken.PID
		case "exit":
			e.Kind = esExit
		case "open":
			e.Kind = esOpen
			var p struct {
				Fflag uint32 `json:"fflag"`
				File  struct {
					Path string `json:"path"`
				} `json:"file"`
			}
			_ = json.Unmarshal(payload, &p)
			e.Flags, e.Path = p.Fflag, p.File.Path
		case "write":
			e.Kind = esWrite
			e.Path = targetPath(payload)
		case "unlink":
			e.Kind = esUnlink
			e.Path = targetPath(payload)
		case "rename":
			e.Kind = esRename
			var p struct {
				Source struct {
					Path string `json:"path"`
				} `json:"source"`
			}
			_ = json.Unmarshal(payload, &p)
			e.Path = p.Source.Path
		default:
			return esEvent{}, false, nil // unmapped event key
		}
		return e, true, nil
	}
	return esEvent{}, false, nil // no event payload
}

// targetPath extracts event.<x>.target.path (shared by write and unlink).
func targetPath(payload json.RawMessage) string {
	var p struct {
		Target struct {
			Path string `json:"path"`
		} `json:"target"`
	}
	_ = json.Unmarshal(payload, &p)
	return p.Target.Path
}

// openMode decodes macOS open fflags into the collector's access-intent string
// ("r"/"w"/"rw", "+create" when O_CREAT). Matches the Linux backend's convention.
func openMode(fflag uint32) string {
	const (
		oWRONLY  = 0x0001
		oRDWR    = 0x0002
		oACCMODE = 0x0003
		oCREAT   = 0x0200
	)
	var mode string
	switch fflag & oACCMODE {
	case oWRONLY:
		mode = "w"
	case oRDWR:
		mode = "rw"
	default:
		mode = "r"
	}
	if fflag&oCREAT != 0 {
		mode += "+create"
	}
	return mode
}
