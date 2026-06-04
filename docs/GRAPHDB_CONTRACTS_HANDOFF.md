# Handoff → graphdb agent: pin jailgraph's consumer contracts

**From:** jailgraph (new graphdb consumer). **To:** whoever's maintaining graphdb.
**Date:** 2026-06-04. **Status:** request / spec — no graphdb changes made by jailgraph.

## TL;DR

jailgraph is now a **validated graphdb consumer** (ingest → profile → audit →
stór convergence, proven end-to-end on real graphdb servers, both arm64 and
amd64). graphdb is functionally ready for this workload. The one gap worth
closing: **the behaviors jailgraph's correctness depends on are not pinned as
CONSUMER CONTRACTs**, so the in-flight storage-hardening wave could change them
and no regression test would catch the break. Per `docs/CONSUMER_CONTRACTS.md`'s
own growth rule, please add the entries below (suggested CC7–CC9).

jailgraph repo: https://github.com/dd0wney/jailgraph (Apache-2.0). It uses
graphdb purely over the REST API (no internal coupling).

## Behaviors jailgraph depends on (proposed contracts)

### CC7 — batch create is partial-success, out-of-order, with properties echoed
**Why jailgraph needs it:** there is no server-side dedup for jailgraph's labels,
so the ingest worker reconciles created node IDs to a client-supplied correlation
key (`_key`) carried **in properties** and read back from the batch response.
This only works if `POST /nodes/batch` (a) returns only the nodes actually
created, (b) echoes each node's `properties` (including `_key`), and (c) makes no
guarantee about order. jailgraph maps response→request by the echoed `_key`, not
by index.
**Suggested test (`pkg/api`):** submit N nodes each with a distinct `_key`
property (with one deliberately-invalid node to force a partial result); assert
the response contains only the valid nodes, each returned node's echoed
`_key` resolves to its assigned `id`, and a dropped node's `_key` is absent.
**Catalogue row:**
`| CC7-batch-partial-echo | POST /nodes/batch returns only created nodes (partial success), in unspecified order, echoing each node's properties so a client can reconcile assigned IDs to a correlation key | jailgraph | pkg/api TestBatchNodes_PartialOutOfOrderEchoesProperties | <PR> |`

### CC8 — label listing returns properties and paginates to completion
**Why jailgraph needs it:** the ingest worker rebuilds its natural-key→ID cache
across runs by `GET /nodes?label=<L>` and reading each node's `_key` property;
`internal/profile.Collect` enumerates a run's `Process` nodes the same way. Both
require the listing to (a) include node `properties`, and (b) be followable to
completion via `X-Next-Cursor`. A partial fetch silently duplicates shared nodes
on the next run (no server-side dedup to save it).
**Suggested test (`pkg/api`):** create more labeled nodes than one page; list
with a small `limit`; assert every node is returned across pages **with its
properties intact**.
**Catalogue row:**
`| CC8-label-list-properties-paginated | GET /nodes?label= returns nodes with their properties and is followable to completion via X-Next-Cursor | jailgraph | pkg/api TestNodesByLabel_ReturnsPropertiesAcrossPages | <PR> |`

### CC9 — /traverse follows outgoing edges to max_depth (lower priority)
**Why jailgraph needs it:** `Collect` does a depth-1 `/traverse` from each
`Process` node to gather its `Syscall`/`File`/`Binary`/`Capability`/`Namespace`
neighbors, relying on outgoing-edge traversal returning the immediate neighbors.
jailgraph filters by label client-side, so it would *adapt* if traverse gained
edge-type/direction filters — this contract just guards against regressing to
"returns nothing / drops neighbors."
**Suggested test (`pkg/api`):** build a star graph; traverse depth-1 from the
center; assert all outgoing neighbors are returned.
**Catalogue row:**
`| CC9-traverse-outgoing-depth | POST /traverse returns nodes reachable via outgoing edges within max_depth | jailgraph | pkg/api TestTraverse_OutgoingNeighborsAtDepth | <PR> |`

## Not contracts — readiness notes / opportunities (no action required)

- **`NodesByLabel` is an unindexed full scan**; jailgraph filters `Process` nodes
  by `_key` prefix `proc:<runID>:` client-side — O(all processes across all runs).
  Your in-flight **property index** (`test/storage-property-index-invariant`):
  **if `PrefixLookup` is exposed via REST**, jailgraph could query a run's
  processes directly and drop the full-scan workaround. That's the single
  highest-value scale unlock for this consumer.
- **No server-side dedup for jailgraph's labels** (only `["Claim"]` gated).
  jailgraph dedups client-side; fine. The existing uniqueness-rules-registry TODO
  in `mutations_resolvers.go` would generalize it if ever wanted.
- **Richer `/traverse` (edge-type/direction) or the `/query` DSL** would let
  jailgraph express "every process that ever opened `/etc/shadow`" as one
  server-side query instead of N depth-1 traverses + client filtering. Nice-to-have.

## What's NOT being asked

No API changes are required for jailgraph to function — it works against graphdb
as-is. This is purely about **defending the integration with regression tests**
(CC7/CC8 are the load-bearing ones) so the storage-hardening wave can proceed
without silently breaking a downstream consumer.
