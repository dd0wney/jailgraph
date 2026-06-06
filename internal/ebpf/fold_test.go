package ebpf

import (
	"testing"

	"github.com/dd0wney/jailgraph/internal/collector"
)

func TestFoldFileActivity_MergesWritesAndChurnByPath(t *testing.T) {
	// Streamed rename/unlink already folded into agg before writes are joined.
	agg := map[string]*fileStat{
		"/data/a.docx": {renames: 1}, // written AND renamed
		"b.docx":       {unlinks: 1}, // churn-only (basename from an unlink hook)
	}
	writes := []pathWrite{
		{path: "/data/a.docx", stat: writeStat{Count: 5, Bytes: 5120}},
		{path: "/data/c.bin", stat: writeStat{Count: 5, Bytes: 9000}}, // write-only
	}

	out := foldFileActivity(agg, writes)
	if len(out) != 3 {
		t.Fatalf("want 3 file-activity events (a, b, c), got %d: %+v", len(out), out)
	}

	byPath := map[string]collector.BehaviorEvent{}
	for _, e := range out {
		if e.Kind != collector.EventFileActivity {
			t.Fatalf("wrong kind for %s: %v", e.Path, e.Kind)
		}
		byPath[e.Path] = e
	}

	if a := byPath["/data/a.docx"]; a.WriteCount != 5 || a.Bytes != 5120 || a.RenameCount != 1 {
		t.Errorf("a.docx = %+v, want writes 5 / bytes 5120 / renames 1", a)
	}
	if c := byPath["/data/c.bin"]; c.WriteCount != 5 || c.Bytes != 9000 || c.RenameCount != 0 {
		t.Errorf("c.bin = %+v, want writes 5 / bytes 9000 / no churn", c)
	}
	// Churn-only files still surface (a delete with no observed write is signal).
	if b := byPath["b.docx"]; b.WriteCount != 0 || b.UnlinkCount != 1 {
		t.Errorf("b.docx = %+v, want write 0 / unlink 1", b)
	}
}
