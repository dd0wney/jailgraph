package ingest

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/model"
	"github.com/dd0wney/jailgraph/internal/run"
)

// TestIntegration_IngestPipelineAgainstRealGraphDB drives the full ingest path
// against a real graphdb server — the highest-value test, since it exercises
// the actual partial-success / out-of-order / no-server-dedup contract that
// mocks only approximate. It needs no Linux tracing, so it runs on macOS.
//
// Gated on JAILGRAPH_GRAPHDB_URL (and skipped under -short). JAILGRAPH_API_KEY
// supplies the X-API-Key.
func TestIntegration_IngestPipelineAgainstRealGraphDB(t *testing.T) {
	url := os.Getenv("JAILGRAPH_GRAPHDB_URL")
	if url == "" || testing.Short() {
		t.Skip("set JAILGRAPH_GRAPHDB_URL (and don't pass -short) to run the real-graphdb integration test")
	}

	client := graphdb.New(graphdb.Config{BaseURL: url, APIKey: os.Getenv("JAILGRAPH_API_KEY")})
	ctx := context.Background()

	// First run: everything is new.
	sess1 := run.New("integration", time.Unix(0, 0))
	stats1, err := NewWorker(client, quietLogger(), WithCacheRebuild(true)).
		Flush(ctx, sess1, buildSampleGraph(sess1.ID))
	if err != nil {
		t.Fatalf("first flush: %v", err)
	}
	if stats1.NodesCreated == 0 || stats1.EdgesCreated == 0 {
		t.Fatalf("first flush created nothing: %+v", stats1)
	}
	if stats1.EdgesQuarantined != 0 || stats1.NodesDropped != 0 || stats1.EdgesDropped != 0 {
		t.Errorf("first flush had losses against real graphdb: %+v", stats1)
	}

	// Persistence check: the File node we wrote is queryable by label.
	files, err := client.NodesByLabel(ctx, model.LabelFile, 500)
	if err != nil {
		t.Fatalf("query files: %v", err)
	}
	if !containsPath(files, "/etc/hostname") {
		t.Errorf("File{/etc/hostname} not found after flush")
	}

	// Second run (fresh worker = cold cache): the shared Binary/File/Syscall
	// nodes must be deduped against the prior run via the server-backed rebuild,
	// proving we don't duplicate shared nodes without server-side uniqueness.
	sess2 := run.New("integration", time.Unix(0, 0))
	stats2, err := NewWorker(client, quietLogger(), WithCacheRebuild(true)).
		Flush(ctx, sess2, buildSampleGraph(sess2.ID))
	if err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if stats2.NodesDeduped == 0 {
		t.Errorf("second run deduped nothing; shared nodes were duplicated: %+v", stats2)
	}
}

func containsPath(nodes []*graphdb.NodeResponse, path string) bool {
	for _, n := range nodes {
		if p, _ := n.Properties["path"].(string); p == path {
			return true
		}
	}
	return false
}
