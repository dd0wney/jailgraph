package anomaly

import (
	"strings"
	"testing"
)

func TestSeverityRankOrder(t *testing.T) {
	order := []Severity{SevCritical, SevHigh, SevMedium, SevInfo}
	for i := 0; i+1 < len(order); i++ {
		if order[i].rank() <= order[i+1].rank() {
			t.Errorf("%s should outrank %s", order[i], order[i+1])
		}
	}
}

func TestHasHighOrAbove(t *testing.T) {
	clean := Report{Findings: []Finding{{Category: "method", Severity: SevInfo}}}
	if clean.HasHighOrAbove() {
		t.Error("info-only report must not be >=High")
	}
	hit := Report{Findings: []Finding{{Category: "syscall", Severity: SevHigh}}}
	if !hit.HasHighOrAbove() {
		t.Error("a High finding must be >=High")
	}
}

func TestRenderText_PreambleAndSummary(t *testing.T) {
	r := Report{
		RunID: "r1", Target: "/bin/x", BaselineRuns: 8,
		Findings: []Finding{
			{Category: "method", Severity: SevInfo, Title: "population-novelty heuristic", Evidence: "e", Recommendation: "r"},
			{Category: "syscall", Severity: SevHigh, Title: "novel syscall setns", Evidence: "seen in 0/8 runs (novel)", Recommendation: "r"},
		},
	}
	out := r.RenderText()
	for _, want := range []string{"anomaly", "/bin/x", "baseline", "[HIGH]", "novel syscall setns", "summary:"} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderText missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "[HIGH]") > strings.Index(out, "population-novelty heuristic") {
		t.Errorf("findings not ordered worst-first:\n%s", out)
	}
}
