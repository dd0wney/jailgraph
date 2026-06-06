// Package detect is the offline ransomware analyzer. It reads a run's per-file
// write/rename/unlink activity (FileActivity nodes, captured by the eBPF backend)
// and applies a STRUCTURAL ransomware heuristic: a run that writes across many
// distinct files, churns extensions (renames/unlinks), and moves real volume
// looks like bulk encryption.
//
// Honesty (mirrors internal/harden): this is a structural heuristic WITHOUT
// content entropy (deferred to phase 2), so it cannot distinguish encryption
// from any other mass-rewrite workload — backups, compilers, archivers, package
// managers all trip it. Every report says so, and there is no single "score".
// It also requires the eBPF backend: a seccomp/replay run captures no writes, so
// detection on it is reported as inconclusive rather than "clean".
package detect

import (
	"context"
	"fmt"
	"strings"

	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/model"
)

// Detection thresholds for the v1 structural signature. Tunable; defensible
// defaults, workload-dependent — the disclaimer covers their imprecision.
var (
	TFiles = 50              // distinct files written
	TChurn = int64(25)       // renames + unlinks
	TBytes = int64(10 << 20) // total bytes written (10 MiB)
)

// Severity is detect's own enum (no cross-import of audit/harden), so a string
// --json stays readable and rank() drives ordering + the exit gate.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevInfo     Severity = "info"
)

func (s Severity) rank() int {
	switch s {
	case SevCritical:
		return 3
	case SevHigh:
		return 2
	case SevMedium:
		return 1
	default:
		return 0
	}
}

// FileActivity is one file's per-run write/rename/unlink stats.
type FileActivity struct {
	Path        string `json:"path"`
	WriteCount  int64  `json:"write_count"`
	Bytes       int64  `json:"bytes"`
	RenameCount int64  `json:"rename_count"`
	UnlinkCount int64  `json:"unlink_count"`
}

// RunSummary is the detector's input: one run's coverage state + file activity.
type RunSummary struct {
	RunID    string         `json:"run_id"`
	Target   string         `json:"target"`
	Coverage string         `json:"coverage"`
	Lossy    bool           `json:"lossy"`
	Files    []FileActivity `json:"files"`
}

// Finding is one detector observation.
type Finding struct {
	Category       string   `json:"category"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Evidence       string   `json:"evidence"`
	Recommendation string   `json:"recommendation"`
}

// Report is the full detection result for one run.
type Report struct {
	RunID    string    `json:"run_id"`
	Target   string    `json:"target"`
	Coverage string    `json:"coverage"`
	Lossy    bool      `json:"lossy"`
	Findings []Finding `json:"findings"`
}

// GraphClient is the narrow read surface the detector needs.
type GraphClient interface {
	NodesByLabel(ctx context.Context, label string, pageLimit int) ([]*graphdb.NodeResponse, error)
}

// Collect reads one run's coverage metadata and its FileActivity nodes (filtered
// to this run by key prefix, mirroring how profile.Collect enumerates a run's
// processes). Properties are coerced float64-aware: graphdb returns JSON numbers
// as float64 on read-back, so a naive int assertion would silently zero them.
func Collect(ctx context.Context, client GraphClient, runID string, pageLimit int) (RunSummary, error) {
	s := RunSummary{RunID: runID}

	runs, err := client.NodesByLabel(ctx, model.LabelRun, pageLimit)
	if err != nil {
		return s, fmt.Errorf("list runs: %w", err)
	}
	found := false
	for _, r := range runs {
		if id, _ := r.Properties["id"].(string); id == runID {
			found = true
			s.Target, _ = r.Properties["target"].(string)
			s.Lossy, _ = r.Properties["lossy"].(bool)
			if cov, _ := r.Properties["coverage"].(string); cov == "full" {
				s.Coverage = "full (eBPF)"
			} else {
				s.Coverage = "partial (seccomp/replay)"
			}
			break
		}
	}
	if !found {
		return s, fmt.Errorf("run %q not found", runID)
	}

	prefix := model.FileActivityPrefix(runID)
	nodes, err := client.NodesByLabel(ctx, model.LabelFileActivity, pageLimit)
	if err != nil {
		return s, fmt.Errorf("list file activity: %w", err)
	}
	for _, n := range nodes {
		key, _ := n.Properties[model.PropKey].(string)
		if !strings.HasPrefix(key, prefix) {
			continue // a different run's file activity
		}
		path, _ := n.Properties["path"].(string)
		s.Files = append(s.Files, FileActivity{
			Path:        path,
			WriteCount:  toInt64(n.Properties["write_count"]),
			Bytes:       toInt64(n.Properties["bytes"]),
			RenameCount: toInt64(n.Properties["rename_count"]),
			UnlinkCount: toInt64(n.Properties["unlink_count"]),
		})
	}
	return s, nil
}

// toInt64 coerces a graph property (float64 from JSON, or a native int) to int64.
func toInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case int32:
		return int64(x)
	default:
		return 0
	}
}

// Analyze applies the v1 structural ransomware heuristic to one run.
func Analyze(s RunSummary) Report {
	r := Report{RunID: s.RunID, Target: s.Target, Coverage: s.Coverage, Lossy: s.Lossy}
	add := func(cat string, sev Severity, title, ev, rec string) {
		r.Findings = append(r.Findings, Finding{cat, sev, title, ev, rec})
	}

	// The structural heuristic — always emitted so the output never reads as
	// ground truth.
	add("method", SevInfo, "structural heuristic only (no content entropy)",
		"v1 detects bulk-rewrite shape, not encryption; entropy is deferred to phase 2",
		"treat as a signal, not proof — backups, compilers, archivers, and package managers trip it too")

	// Detection requires eBPF write capture; a seccomp/replay run sees no writes.
	if !strings.HasPrefix(s.Coverage, "full") {
		add("coverage", SevInfo, "detection inconclusive — no file-write capture on this backend",
			"the eBPF backend is required to observe writes/renames/unlinks; this run is "+s.Coverage,
			"re-run with --collector ebpf to enable ransomware detection")
		finalize(&r)
		return r
	}
	if s.Lossy {
		add("coverage", SevHigh, "trace was lossy — detection is degraded",
			"the trace dropped events; file-activity counts may be incomplete",
			"re-run without drops before trusting this result (absence is not evidence of absence)")
	}

	// Structural signal.
	var distinct int
	var churn, bytes int64
	for _, f := range s.Files {
		if f.WriteCount > 0 {
			distinct++
		}
		churn += f.RenameCount + f.UnlinkCount
		bytes += f.Bytes
	}

	hitFiles := distinct >= TFiles
	hitChurn := churn >= TChurn
	hitBytes := bytes >= TBytes
	hits := b2i(hitFiles) + b2i(hitChurn) + b2i(hitBytes)
	strong := distinct >= 2*TFiles && churn >= 2*TChurn && bytes >= 2*TBytes

	ev := fmt.Sprintf("%d distinct files written, %d renames+unlinks, %d bytes (thresholds: %d / %d / %d)",
		distinct, churn, bytes, TFiles, TChurn, TBytes)
	switch {
	case hitFiles && hitChurn && hitBytes && strong:
		add("ransomware", SevCritical, "strong bulk-rewrite + churn signature", ev,
			"isolate and investigate: this matches mass-encryption behavior on every structural axis")
	case hitFiles && hitChurn && hitBytes:
		add("ransomware", SevHigh, "bulk-rewrite + extension-churn signature", ev,
			"investigate: write-spread, churn, and volume all exceed thresholds")
	case hits >= 2:
		add("ransomware", SevMedium, "partial bulk-rewrite signature", ev,
			"review: some but not all structural axes exceed thresholds")
	default:
		add("ransomware", SevInfo, "no bulk-rewrite signature", ev,
			"no action: file activity is below the structural thresholds")
	}

	finalize(&r)
	return r
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func finalize(r *Report) {
	// stable sort: worst severity first, then category, then title.
	for i := 1; i < len(r.Findings); i++ {
		for j := i; j > 0; j-- {
			a, b := r.Findings[j-1], r.Findings[j]
			less := a.Severity.rank() < b.Severity.rank() ||
				(a.Severity.rank() == b.Severity.rank() && (a.Category > b.Category ||
					(a.Category == b.Category && a.Title > b.Title)))
			if !less {
				break
			}
			r.Findings[j-1], r.Findings[j] = r.Findings[j], r.Findings[j-1]
		}
	}
}

// HasHighOrAbove drives the CLI exit code (a High/Critical detection → exit 1).
func (r Report) HasHighOrAbove() bool {
	for _, f := range r.Findings {
		if f.Severity.rank() >= SevHigh.rank() {
			return true
		}
	}
	return false
}

var severityOrder = []Severity{SevCritical, SevHigh, SevMedium, SevInfo}

// RenderText renders the detection report: coverage preamble first, findings
// worst-first, then a per-severity summary.
func (r Report) RenderText() string {
	var sb strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&sb, f, a...); sb.WriteByte('\n') }

	w("ransomware detection (structural)")
	w("  target:   %s", r.Target)
	w("  run:      %s", r.RunID)
	w("  coverage: %s", r.Coverage)
	if r.Lossy {
		w("  WARNING: trace was lossy — counts may be incomplete.")
	}
	w("")

	counts := map[Severity]int{}
	for _, sev := range severityOrder {
		first := true
		for _, f := range r.Findings {
			if f.Severity != sev {
				continue
			}
			counts[sev]++
			if first {
				w("== %s ==", strings.ToUpper(string(sev)))
				first = false
			}
			w("[%s] %s", strings.ToUpper(string(sev)), f.Title)
			w("    evidence:  %s", f.Evidence)
			w("    recommend: %s", f.Recommendation)
		}
		if !first {
			w("")
		}
	}

	var parts []string
	for _, sev := range severityOrder {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], strings.ToUpper(string(sev[:1]))+string(sev[1:])))
		}
	}
	w("summary: %s", strings.Join(parts, ", "))
	return sb.String()
}
