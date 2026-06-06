//go:build darwin && darwin_integration

// Live observability test for the macOS eslogger collector. It is the decisive
// check the unit tests can't make: does eslogger, read through the pty collector,
// actually observe the TARGET's file activity (filtered to its subtree)?
//
// Needs root (eslogger) + Full Disk Access for the running terminal. Run:
//
//	sudo go test -tags darwin_integration ./internal/esf/ -run TestESFLive -v
package esf

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dd0wney/jailgraph/internal/collector"
)

func TestESFLive_CapturesTargetFileActivity(t *testing.T) {
	if t == nil {
		return
	}
	// Workload: a sh subtree that writes 40 files, renames 20, unlinks 10 — all
	// tagged JGESFLIVE so we match by marker (sidesteps /tmp→/private/tmp symlink
	// path resolution).
	const script = `d="$(mktemp -d /tmp/jgesflive.XXXXXX)"
for i in $(seq 1 40);  do echo data > "$d/JGESFLIVE_$i.txt"; done
for i in $(seq 1 20);  do mv "$d/JGESFLIVE_$i.txt" "$d/JGESFLIVE_$i.locked"; done
for i in $(seq 21 30); do rm "$d/JGESFLIVE_$i.txt"; done
rm -rf "$d"`

	c, err := NewCollector("/bin/sh", []string{"-c", script}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ch, err := c.Start(ctx)
	if err != nil {
		t.Fatalf("start (need sudo + Full Disk Access?): %v", err)
	}

	var total int
	var execs, opens, fileActs int
	var writes, renames, unlinks int64
	for e := range ch {
		total++
		switch e.Kind {
		case collector.EventExec:
			execs++
		case collector.EventOpen:
			if strings.Contains(e.Path, "JGESFLIVE") {
				opens++
			}
		case collector.EventFileActivity:
			if strings.Contains(e.Path, "JGESFLIVE") {
				fileActs++
				writes += e.WriteCount
				renames += e.RenameCount
				unlinks += e.UnlinkCount
			}
		}
	}

	t.Logf("total events=%d execs=%d targetOpens=%d targetFileActivity=%d writes=%d renames=%d unlinks=%d",
		total, execs, opens, fileActs, writes, renames, unlinks)

	if fileActs == 0 || writes == 0 {
		t.Fatalf("no target FileActivity captured — eslogger did not observe the target's writes "+
			"(Full Disk Access for the terminal? root? buffering?). total=%d", total)
	}
	if renames == 0 {
		t.Errorf("expected rename activity (extension churn) but saw none")
	}
}
