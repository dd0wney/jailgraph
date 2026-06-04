package graphdb

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestClient(srv *httptest.Server) *Client {
	return New(Config{
		BaseURL: srv.URL,
		APIKey:  "test",
		Sleep:   func(time.Duration) {}, // no real waiting in tests
	})
}

func TestBatchNodes_ReturnsOnlyCreatedOutOfOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req batchNodeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		// Echo back in REVERSE order and drop the middle item, simulating
		// graphdb's partial-success + out-of-order contract.
		var out []*NodeResponse
		for i := len(req.Nodes) - 1; i >= 0; i-- {
			if i == 1 {
				continue // dropped (e.g. failed validation)
			}
			out = append(out, &NodeResponse{
				ID:         uint64(100 + i),
				Labels:     req.Nodes[i].Labels,
				Properties: req.Nodes[i].Properties,
			})
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(batchNodeResponse{Nodes: out, Created: len(out)})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	reqs := []NodeRequest{
		{Labels: []string{"X"}, Properties: map[string]any{"_key": "a"}},
		{Labels: []string{"X"}, Properties: map[string]any{"_key": "b"}},
		{Labels: []string{"X"}, Properties: map[string]any{"_key": "c"}},
	}
	got, err := c.BatchNodes(context.Background(), reqs)
	if err != nil {
		t.Fatalf("BatchNodes: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d created, want 2 (one dropped)", len(got))
	}
	// Caller must be able to reconcile by echoed _key regardless of order.
	byKey := map[string]uint64{}
	for _, n := range got {
		byKey[n.Properties["_key"].(string)] = n.ID
	}
	if byKey["a"] != 100 || byKey["c"] != 102 {
		t.Errorf("reconciliation by _key failed: %+v", byKey)
	}
	if _, dropped := byKey["b"]; dropped {
		t.Error("expected key b to be absent (dropped)")
	}
}

func TestDoJSON_RetriesOn429ThenSucceeds(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(NodeResponse{ID: 7})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	n, err := c.CreateNode(context.Background(), NodeRequest{Labels: []string{"Run"}})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if n.ID != 7 || calls != 2 {
		t.Errorf("id=%d calls=%d, want id=7 calls=2", n.ID, calls)
	}
}

func TestDoJSON_DoesNotRetryOn400(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, `{"error":"batch too large"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.BatchNodes(context.Background(), []NodeRequest{{Labels: []string{"X"}}})
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("err = %v, want ErrBadRequest", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (4xx must not retry)", calls)
	}
}

func TestDoJSON_5xxRetriesThenExhausts(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New(Config{BaseURL: srv.URL, APIKey: "t", MaxRetries: 2, Sleep: func(time.Duration) {}})
	_, err := c.BatchNodes(context.Background(), []NodeRequest{{Labels: []string{"X"}}})
	if !errors.Is(err, ErrServer) {
		t.Fatalf("err = %v, want ErrServer", err)
	}
	if calls != 3 { // initial + 2 retries
		t.Errorf("calls = %d, want 3 (initial + MaxRetries)", calls)
	}
}

func TestDoJSON_TransportErrorIsRetriedThenSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now nothing is listening -> connection refused (transport error)
	c := New(Config{BaseURL: url, APIKey: "t", MaxRetries: 1, Sleep: func(time.Duration) {}})
	if _, err := c.CreateNode(context.Background(), NodeRequest{Labels: []string{"Run"}}); err == nil {
		t.Fatal("expected a transport error")
	} else if !errors.Is(err, ErrServer) {
		t.Errorf("transport error should wrap ErrServer, got %v", err)
	}
}

func TestDoJSON_MalformedJSONResponseSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{ this is not json"))
	}))
	defer srv.Close()
	c := newTestClient(srv)
	if _, err := c.CreateNode(context.Background(), NodeRequest{Labels: []string{"Run"}}); err == nil {
		t.Fatal("expected a decode error on malformed JSON")
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := map[string]time.Duration{
		"1":   time.Second,
		"5":   5 * time.Second,
		"0":   0,
		"":    0,
		"abc": 0, // non-numeric -> 0 (falls through to exponential backoff)
	}
	for in, want := range cases {
		if got := parseRetryAfter(in); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestBatchEdges_AndEmptyBatches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		switch r.URL.Path {
		case "/edges/batch":
			var req batchEdgeRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			out := make([]*EdgeResponse, 0, len(req.Edges))
			for i, e := range req.Edges {
				out = append(out, &EdgeResponse{ID: uint64(i + 1), FromNodeID: e.FromNodeID, ToNodeID: e.ToNodeID, Type: e.Type})
			}
			_ = json.NewEncoder(w).Encode(batchEdgeResponse{Edges: out, Created: len(out)})
		default:
			_ = json.NewEncoder(w).Encode(batchNodeResponse{})
		}
	}))
	defer srv.Close()
	c := newTestClient(srv)

	edges, err := c.BatchEdges(context.Background(), []EdgeRequest{{FromNodeID: 1, ToNodeID: 2, Type: "X"}})
	if err != nil || len(edges) != 1 {
		t.Fatalf("BatchEdges: got %d edges, err %v", len(edges), err)
	}
	// Empty batches must round-trip cleanly (no panic, no error).
	if e, err := c.BatchEdges(context.Background(), nil); err != nil || len(e) != 0 {
		t.Errorf("empty BatchEdges: %d edges, err %v", len(e), err)
	}
	if n, err := c.BatchNodes(context.Background(), nil); err != nil || len(n) != 0 {
		t.Errorf("empty BatchNodes: %d nodes, err %v", len(n), err)
	}
}

func TestNodesByLabel_FollowsCursorToCompletion(t *testing.T) {
	// Three nodes across two pages; the client must concatenate both.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		switch cursor {
		case "":
			w.Header().Set("X-Next-Cursor", "page2")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]*NodeResponse{{ID: 1}, {ID: 2}})
		case "page2":
			// No X-Next-Cursor → final page.
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]*NodeResponse{{ID: 3}})
		default:
			t.Errorf("unexpected cursor %q", cursor)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv)
	got, err := c.NodesByLabel(context.Background(), "Binary", 2)
	if err != nil {
		t.Fatalf("NodesByLabel: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d nodes, want 3 across two pages", len(got))
	}
}
