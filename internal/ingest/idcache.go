package ingest

import (
	"context"

	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/model"
)

// GraphClient is the subset of the graphdb client the worker needs. Defining it
// here (consumer-side) lets tests substitute a fake without httptest and keeps
// the worker decoupled from the concrete client.
type GraphClient interface {
	CreateNode(ctx context.Context, req graphdb.NodeRequest) (*graphdb.NodeResponse, error)
	BatchNodes(ctx context.Context, reqs []graphdb.NodeRequest) ([]*graphdb.NodeResponse, error)
	BatchEdges(ctx context.Context, reqs []graphdb.EdgeRequest) ([]*graphdb.EdgeResponse, error)
	NodesByLabel(ctx context.Context, label string, pageLimit int) ([]*graphdb.NodeResponse, error)
}

// IDCache maps a node's natural key to its graphdb-assigned id. It is the
// mechanism that makes client-side dedup work: graphdb enforces no uniqueness
// for our labels, so a key already in the cache is never re-created.
type IDCache struct {
	m map[string]uint64
}

// NewIDCache returns an empty cache.
func NewIDCache() *IDCache { return &IDCache{m: make(map[string]uint64)} }

// Get returns the id for key and whether it was present.
func (c *IDCache) Get(key string) (uint64, bool) {
	id, ok := c.m[key]
	return id, ok
}

// Put records key→id.
func (c *IDCache) Put(key string, id uint64) { c.m[key] = id }

// Len reports the number of cached keys.
func (c *IDCache) Len() int { return len(c.m) }

// Rebuild repopulates the cache from the server for the given labels, reading
// each node's natural key from its echoed _key property. This is the
// authoritative defence against duplicating shared nodes (Binary/Syscall/...)
// across runs: a fresh process starts with an empty cache, so without this it
// would re-create every shared node. It paginates each label to completion.
func (c *IDCache) Rebuild(ctx context.Context, client GraphClient, labels []string, pageLimit int) error {
	for _, label := range labels {
		nodes, err := client.NodesByLabel(ctx, label, pageLimit)
		if err != nil {
			return err
		}
		for _, n := range nodes {
			key, _ := n.Properties[model.PropKey].(string)
			if key != "" {
				c.m[key] = n.ID
			}
		}
	}
	return nil
}
