package anomaly

import (
	"strings"
	"testing"

	"github.com/dd0wney/jailgraph/internal/profile"
)

// baselineN builds a baseline of n runs where "read"/"write" syscalls, /bin/x,
// and /etc/conf are universal; caps observed (eBPF-class) but empty.
func baselineN(n int) Baseline {
	return Baseline{
		Target: "/bin/x", TotalRuns: n, CandidateFullCoverage: true,
		Syscalls: DimBaseline{Support: map[string]float64{"read": 1.0, "write": 1.0}, N: n},
		Binaries: DimBaseline{Support: map[string]float64{"/bin/x": 1.0}, N: n},
		Files:    DimBaseline{Support: map[string]float64{"/etc/conf": 1.0}, N: n},
		Caps:     DimBaseline{Support: map[string]float64{}, N: n},
	}
}

func beh(syscalls, binaries, files, caps []string) profile.Behavior {
	sm := map[string]bool{}
	for _, s := range syscalls {
		sm[s] = true
	}
	return profile.Behavior{RunID: "cand", Syscalls: sm, Binaries: binaries, Files: files, Caps: caps}
}

func score(b Baseline, cand profile.Behavior) Report { return Analyze(cand, b, FrequencyScorer{}) }

func has(r Report, sub string) bool { return strings.Contains(r.RenderText(), sub) }

func TestAnalyze_NovelSyscallIsHigh(t *testing.T) {
	r := score(baselineN(8), beh([]string{"read", "setns"}, []string{"/bin/x"}, nil, nil))
	if !r.HasHighOrAbove() || !has(r, "novel syscall: setns") {
		t.Errorf("a novel syscall should be High:\n%s", r.RenderText())
	}
}

func TestAnalyze_CommonSurfaceIsClean(t *testing.T) {
	r := score(baselineN(8), beh([]string{"read", "write"}, []string{"/bin/x"}, []string{"/etc/conf"}, nil))
	if r.HasHighOrAbove() {
		t.Errorf("a run whose surface is all in-baseline must be clean:\n%s", r.RenderText())
	}
}

func TestAnalyze_NovelBinaryIsMedium(t *testing.T) {
	r := score(baselineN(8), beh([]string{"read"}, []string{"/bin/x", "/usr/bin/curl"}, nil, nil))
	if r.HasHighOrAbove() || !has(r, "novel binary: /usr/bin/curl") {
		t.Errorf("a novel binary should be Medium (not High):\n%s", r.RenderText())
	}
}

func TestAnalyze_NovelFileNeverDrives(t *testing.T) {
	r := score(baselineN(8), beh([]string{"read"}, []string{"/bin/x"}, []string{"/etc/conf", "/etc/shadow"}, nil))
	if r.HasHighOrAbove() {
		t.Errorf("a novel file must never drive the verdict above Info:\n%s", r.RenderText())
	}
	if !has(r, "novel file: /etc/shadow") {
		t.Errorf("the novel file should still be reported (informationally):\n%s", r.RenderText())
	}
}

func TestAnalyze_CapsNotComparableCannotScore(t *testing.T) {
	// Full-coverage candidate, but the baseline observed no caps (partial backend):
	// Caps.N=0 → cannot score; a held cap must NOT register as novel.
	b := baselineN(8)
	b.Caps = DimBaseline{Support: map[string]float64{}, N: 0}
	r := score(b, beh([]string{"read"}, []string{"/bin/x"}, nil, []string{"CAP_SETUID"}))
	if r.HasHighOrAbove() {
		t.Errorf("an uncomparable caps dimension must not produce a verdict:\n%s", r.RenderText())
	}
	if !has(r, "cannot score caps") {
		t.Errorf("expected an explicit 'cannot score caps' coverage finding:\n%s", r.RenderText())
	}
}

func TestAnalyze_SmallBaselineCapsSeverity(t *testing.T) {
	// N=3 (< MinConfidentN) → a novel syscall is capped High→Medium + a
	// low-confidence finding; it must not trip exit 1.
	r := score(baselineN(3), beh([]string{"read", "setns"}, []string{"/bin/x"}, nil, nil))
	if r.HasHighOrAbove() {
		t.Errorf("a thin baseline must cap a novel syscall below High:\n%s", r.RenderText())
	}
	if !has(r, "low-confidence syscall baseline") {
		t.Errorf("expected a low-confidence baseline finding:\n%s", r.RenderText())
	}
}

func TestAnalyze_NonGateableSyscallNoveltyIsNotHigh(t *testing.T) {
	// futex is novel (not in baseline) but NON-gateable → hot-path/scheduler noise
	// that drifts between benign runs. It must not trip High; only a summary.
	r := score(baselineN(8), beh([]string{"read", "futex"}, []string{"/bin/x"}, nil, nil))
	if r.HasHighOrAbove() {
		t.Errorf("a novel non-gateable syscall must not drive the verdict:\n%s", r.RenderText())
	}
	if !has(r, "non-security syscall(s) novel") {
		t.Errorf("expected the non-gateable novelty summary:\n%s", r.RenderText())
	}
}

func TestAnalyze_GateableSyscallStillHigh(t *testing.T) {
	// A gateable novel syscall (setns) IS the meaningful signal → High.
	r := score(baselineN(8), beh([]string{"read", "setns"}, []string{"/bin/x"}, nil, nil))
	if !r.HasHighOrAbove() {
		t.Errorf("a novel gateable syscall must still drive High:\n%s", r.RenderText())
	}
}

func TestAnalyze_ExecBinaryNotDoubledAsFile(t *testing.T) {
	// /usr/bin/curl is exec'd (Binary) AND opened (File); report it once, as a binary.
	r := score(baselineN(8), beh([]string{"read"}, []string{"/bin/x", "/usr/bin/curl"}, []string{"/usr/bin/curl", "/etc/conf"}, nil))
	if !has(r, "novel binary: /usr/bin/curl") {
		t.Errorf("the exec'd novel binary should be reported:\n%s", r.RenderText())
	}
	if has(r, "novel file: /usr/bin/curl") {
		t.Errorf("an exec'd binary must not also be reported as a novel file:\n%s", r.RenderText())
	}
}
