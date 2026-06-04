// Package graphdb is a minimal REST client for the subset of graphdb's HTTP API
// that jailgraph needs: batch node/edge creation, single node creation (for the
// Run node), and label-scoped node listing (to rebuild the ingest id-cache).
//
// The client encodes three hard facts about graphdb's contract:
//   - Batch creation is partial-success: the response contains only the items
//     that were created, and NOT in request order. Callers reconcile by a key
//     echoed back in properties (nodes) or by the (from,to,type) tuple (edges).
//   - 429 carries Retry-After and means "slow down" (retryable). Other 4xx are
//     deterministic client errors and are never retried.
//   - Label listing is cursor-paginated via the X-Next-Cursor response header.
package graphdb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Sentinel errors let callers branch on failure mode (see the ingest worker's
// retry decisions).
var (
	ErrRateLimited  = errors.New("graphdb: rate limited")
	ErrUnauthorized = errors.New("graphdb: unauthorized")
	ErrBadRequest   = errors.New("graphdb: bad request")
	ErrServer       = errors.New("graphdb: server error")
)

// NodeRequest / NodeResponse / EdgeRequest / EdgeResponse mirror graphdb's
// pkg/api types exactly (field names and JSON tags verified against source).
type NodeRequest struct {
	Labels     []string       `json:"labels"`
	Properties map[string]any `json:"properties"`
}

type NodeResponse struct {
	ID         uint64         `json:"id"`
	Labels     []string       `json:"labels"`
	Properties map[string]any `json:"properties"`
}

type EdgeRequest struct {
	FromNodeID uint64         `json:"from_node_id"`
	ToNodeID   uint64         `json:"to_node_id"`
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties,omitempty"`
	Weight     float64        `json:"weight"`
}

type EdgeResponse struct {
	ID         uint64         `json:"id"`
	FromNodeID uint64         `json:"from_node_id"`
	ToNodeID   uint64         `json:"to_node_id"`
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties"`
	Weight     float64        `json:"weight"`
}

type batchNodeRequest struct {
	Nodes []NodeRequest `json:"nodes"`
}
type batchNodeResponse struct {
	Nodes   []*NodeResponse `json:"nodes"`
	Created int             `json:"created"`
}
type batchEdgeRequest struct {
	Edges []EdgeRequest `json:"edges"`
}
type batchEdgeResponse struct {
	Edges   []*EdgeResponse `json:"edges"`
	Created int             `json:"created"`
}

// Config configures a Client.
type Config struct {
	BaseURL string
	APIKey  string

	// HTTPClient is optional; a default with a sane timeout is used if nil.
	HTTPClient *http.Client
	// MaxRetries bounds retries for 429/5xx (default 5).
	MaxRetries int
	// Sleep and Now are injectable for deterministic tests; defaults use the
	// real clock.
	Sleep func(time.Duration)
	Now   func() time.Time
}

// Client talks to one graphdb server with one API key.
type Client struct {
	baseURL    string
	apiKey     string
	httpc      *http.Client
	maxRetries int
	sleep      func(time.Duration)
	now        func() time.Time
}

// New builds a Client from cfg.
func New(cfg Config) *Client {
	c := &Client{
		baseURL:    trimSlash(cfg.BaseURL),
		apiKey:     cfg.APIKey,
		httpc:      cfg.HTTPClient,
		maxRetries: cfg.MaxRetries,
		sleep:      cfg.Sleep,
		now:        cfg.Now,
	}
	if c.httpc == nil {
		c.httpc = &http.Client{Timeout: 30 * time.Second}
	}
	if c.maxRetries == 0 {
		c.maxRetries = 5
	}
	if c.sleep == nil {
		c.sleep = time.Sleep
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// CreateNode creates a single node and returns it (with its assigned id). Used
// for the Run node, which must exist before any PART_OF edge references it.
func (c *Client) CreateNode(ctx context.Context, req NodeRequest) (*NodeResponse, error) {
	var resp NodeResponse
	if err := c.doJSON(ctx, http.MethodPost, "/nodes", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// BatchNodes creates up to len(reqs) nodes. The returned slice contains only the
// nodes graphdb actually created, in graphdb's order — callers must reconcile by
// the key echoed in properties, not by index.
func (c *Client) BatchNodes(ctx context.Context, reqs []NodeRequest) ([]*NodeResponse, error) {
	var resp batchNodeResponse
	if err := c.doJSON(ctx, http.MethodPost, "/nodes/batch", batchNodeRequest{Nodes: reqs}, &resp); err != nil {
		return nil, err
	}
	return resp.Nodes, nil
}

// BatchEdges creates up to len(reqs) edges, returning only those created.
func (c *Client) BatchEdges(ctx context.Context, reqs []EdgeRequest) ([]*EdgeResponse, error) {
	var resp batchEdgeResponse
	if err := c.doJSON(ctx, http.MethodPost, "/edges/batch", batchEdgeRequest{Edges: reqs}, &resp); err != nil {
		return nil, err
	}
	return resp.Edges, nil
}

type traversalRequest struct {
	StartNodeID uint64 `json:"start_node_id"`
	MaxDepth    int    `json:"max_depth"`
}

type traversalResponse struct {
	Nodes []*NodeResponse `json:"nodes"`
	Count int             `json:"count"`
}

// Traverse returns the nodes reachable from startID within maxDepth hops. Note
// graphdb's /traverse follows OUTGOING edges only and ignores any edge-type or
// direction filter, so callers must filter the returned nodes by label.
func (c *Client) Traverse(ctx context.Context, startID uint64, maxDepth int) ([]*NodeResponse, error) {
	var resp traversalResponse
	req := traversalRequest{StartNodeID: startID, MaxDepth: maxDepth}
	if err := c.doJSON(ctx, http.MethodPost, "/traverse", req, &resp); err != nil {
		return nil, err
	}
	return resp.Nodes, nil
}

// NodesByLabel returns every node with the given label, following X-Next-Cursor
// pagination to completion. A partial fetch would corrupt the id-cache (and,
// with no server-side dedup, duplicate shared nodes on the next run), so this
// must read the full corpus before returning.
func (c *Client) NodesByLabel(ctx context.Context, label string, pageLimit int) ([]*NodeResponse, error) {
	if pageLimit <= 0 {
		pageLimit = 500
	}
	var all []*NodeResponse
	cursor := ""
	for {
		q := url.Values{}
		q.Set("label", label)
		q.Set("limit", strconv.Itoa(pageLimit))
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page []*NodeResponse
		next, err := c.doJSONWithHeader(ctx, http.MethodGet, "/nodes?"+q.Encode(), nil, &page, "X-Next-Cursor")
		if err != nil {
			return nil, fmt.Errorf("list label %q: %w", label, err)
		}
		all = append(all, page...)
		if next == "" {
			return all, nil
		}
		cursor = next
	}
}

func (c *Client) doJSON(ctx context.Context, method, path string, body, out any) error {
	_, err := c.doJSONWithHeader(ctx, method, path, body, out, "")
	return err
}

// doJSONWithHeader performs the request with retry on 429/5xx and returns the
// value of respHeader (empty if respHeader == "").
func (c *Client) doJSONWithHeader(ctx context.Context, method, path string, body, out any, respHeader string) (string, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return "", fmt.Errorf("marshal request: %w", err)
		}
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return "", fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if c.apiKey != "" {
			req.Header.Set("X-API-Key", c.apiKey)
		}

		resp, err := c.httpc.Do(req)
		if err != nil {
			// Transport errors are transient; retry with backoff.
			lastErr = fmt.Errorf("%w: %v", ErrServer, err)
			if !c.backoff(ctx, attempt, 0) {
				return "", lastErr
			}
			continue
		}

		hdr := ""
		if respHeader != "" {
			hdr = resp.Header.Get(respHeader)
		}
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		err = c.handleStatus(resp, out)
		_ = resp.Body.Close()

		switch {
		case err == nil:
			return hdr, nil
		case errors.Is(err, ErrRateLimited):
			lastErr = err
			if !c.backoff(ctx, attempt, retryAfter) {
				return "", err
			}
		case errors.Is(err, ErrServer):
			lastErr = err
			if !c.backoff(ctx, attempt, 0) {
				return "", err
			}
		default:
			// 4xx other than 429: deterministic, do not retry.
			return "", err
		}
	}
	return "", fmt.Errorf("exhausted %d retries: %w", c.maxRetries, lastErr)
}

func (c *Client) handleStatus(resp *http.Response, out any) error {
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if out == nil {
			return nil
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return ErrRateLimited
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrUnauthorized, readSnippet(resp.Body))
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("%w (%d): %s", ErrBadRequest, resp.StatusCode, readSnippet(resp.Body))
	default:
		return fmt.Errorf("%w (%d): %s", ErrServer, resp.StatusCode, readSnippet(resp.Body))
	}
}

// backoff sleeps before the next attempt and returns false when retries are
// exhausted or ctx is done. retryAfter, when >0, takes precedence over the
// exponential schedule (graphdb sends Retry-After: 1 on 429).
func (c *Client) backoff(ctx context.Context, attempt int, retryAfter time.Duration) bool {
	if attempt >= c.maxRetries {
		return false
	}
	d := retryAfter
	if d <= 0 {
		d = time.Duration(1<<uint(attempt)) * 100 * time.Millisecond
	}
	select {
	case <-ctx.Done():
		return false
	default:
	}
	c.sleep(d)
	return true
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	return 0
}

func readSnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 512))
	return string(bytes.TrimSpace(b))
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
