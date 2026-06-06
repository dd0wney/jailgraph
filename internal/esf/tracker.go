package esf

import "github.com/dd0wney/jailgraph/internal/collector"

// fileStat accumulates one file's per-run write/rename/unlink activity. macOS ES
// gives no byte count, so Bytes is always 0 (the detector grades adaptively).
type fileStat struct {
	writes  int64
	renames int64
	unlinks int64
}

// tracker reconstructs the target's process subtree from the system-wide
// eslogger stream and folds file activity. eslogger reports every process, so
// the tracker filters to the tracked PID set: seeded with the target, grown when
// a tracked process forks, shrunk on exit. exec/fork/open stream through as
// BehaviorEvents; write/rename/unlink fold per path and emit at teardown (Fold).
//
// Not safe for concurrent use — the live collector drives it from a single
// goroutine (the eslogger scanner) and reads Fold() only after that goroutine
// has finished.
type tracker struct {
	tracked   map[int32]bool
	targetPID int32
	exited    bool
	fold      map[string]*fileStat
}

func newTracker(targetPID int32) *tracker {
	return &tracker{
		tracked:   map[int32]bool{targetPID: true},
		targetPID: targetPID,
		fold:      map[string]*fileStat{},
	}
}

// OnEvent updates the tracked set and returns the BehaviorEvents this event
// implies (nil for untracked PIDs, or for folded file activity).
func (t *tracker) OnEvent(e esEvent) []collector.BehaviorEvent {
	switch e.Kind {
	case esFork:
		if t.tracked[e.PID] {
			t.tracked[e.ChildPID] = true
			return []collector.BehaviorEvent{{Kind: collector.EventSpawn, PID: e.ChildPID, PPID: e.PID}}
		}
	case esExec:
		if t.tracked[e.PID] {
			return []collector.BehaviorEvent{{Kind: collector.EventExec, PID: e.PID, PPID: e.PPID, Exe: e.ExePath}}
		}
	case esExit:
		if e.PID == t.targetPID {
			t.exited = true
		}
		delete(t.tracked, e.PID)
	case esOpen:
		if t.tracked[e.PID] {
			return []collector.BehaviorEvent{{Kind: collector.EventOpen, PID: e.PID, PPID: e.PPID, Path: e.Path, OpenMode: openMode(e.Flags)}}
		}
	case esWrite:
		if t.tracked[e.PID] {
			t.bump(e.Path, 1, 0, 0)
		}
	case esRename:
		if t.tracked[e.PID] {
			t.bump(e.Path, 0, 1, 0)
		}
	case esUnlink:
		if t.tracked[e.PID] {
			t.bump(e.Path, 0, 0, 1)
		}
	}
	return nil
}

func (t *tracker) bump(path string, w, r, u int64) {
	if path == "" {
		return
	}
	s := t.fold[path]
	if s == nil {
		s = &fileStat{}
		t.fold[path] = s
	}
	s.writes += w
	s.renames += r
	s.unlinks += u
}

// targetExited reports whether the seed target process has exited (teardown
// signal; descendants may still be alive but the run is done).
func (t *tracker) targetExited() bool { return t.exited }

// Fold drains the per-file accumulator into one EventFileActivity per file.
func (t *tracker) Fold() []collector.BehaviorEvent {
	out := make([]collector.BehaviorEvent, 0, len(t.fold))
	for path, s := range t.fold {
		out = append(out, collector.BehaviorEvent{
			Kind:        collector.EventFileActivity,
			Path:        path,
			WriteCount:  s.writes,
			Bytes:       0, // macOS ES exposes no write byte count
			RenameCount: s.renames,
			UnlinkCount: s.unlinks,
		})
	}
	return out
}
