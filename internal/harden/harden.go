// Package harden turns one program's observed behavior (a profile.Behavior)
// into an evidence-based hardening report: ranked, severity-tagged findings.
//
// Positioned against Lynis: evidence-based, not rule-based. Every finding cites
// what was OBSERVED. The hard part is honesty about what a given backend can
// even see — a seccomp trace cannot observe capabilities or namespaces, so those
// categories are gated on full (eBPF) coverage and, on a partial run, surface an
// explicit "not observable on this backend" finding rather than going silent
// (silence would read as "clean" — a false absence). For that reason the report
// emits NO single hardening score: a number computed over findings would rank a
// seccomp run higher than an eBPF run of the same program purely because it saw
// less. Output is ranked findings + a per-severity summary under a coverage label.
package harden

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dd0wney/jailgraph/internal/profile"
)

// Severity is a string enum (like audit.Mode) so --json is human-readable and
// rank() can drive sorting and the exit threshold.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// rank orders severities for sorting and the exit threshold. Higher = worse.
func (s Severity) rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default: // SevInfo and unknown
		return 0
	}
}

// Finding is one evidence-based observation about the program's hardening posture.
type Finding struct {
	Category       string   `json:"category"` // capabilities | namespaces | syscalls | files | effectiveness | coverage
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Evidence       string   `json:"evidence"` // what was OBSERVED (or why it can't be)
	Recommendation string   `json:"recommendation"`
}

// Report is the full hardening report for one program (one run, or a union).
type Report struct {
	RunID    string    `json:"run_id"`
	Target   string    `json:"target"`
	Coverage string    `json:"coverage"` // "full (eBPF)" | "partial (seccomp/replay)"
	Lossy    bool      `json:"lossy"`
	Findings []Finding `json:"findings"`
}

// highRiskCaps are capabilities whose presence is a High finding (the rest are
// Medium). Tight, defensible set; expand only with evidence.
var highRiskCaps = map[string]bool{
	"CAP_SYS_ADMIN":       true,
	"CAP_SYS_MODULE":      true,
	"CAP_SYS_PTRACE":      true,
	"CAP_SYS_RAWIO":       true,
	"CAP_BPF":             true,
	"CAP_NET_ADMIN":       true,
	"CAP_DAC_READ_SEARCH": true,
	"CAP_SETUID":          true,
	"CAP_SETGID":          true,
}

// Analyze applies the v1 rule table to one (already collected/unioned) Behavior.
// Findings are returned sorted worst-first (by descending severity, then category,
// then title).
func Analyze(b profile.Behavior) Report {
	r := Report{RunID: b.RunID, Target: b.Target, Lossy: b.Lossy}
	if b.FullCoverage {
		r.Coverage = "full (eBPF)"
	} else {
		r.Coverage = "partial (seccomp/replay)"
	}
	add := func(cat string, sev Severity, title, ev, rec string) {
		r.Findings = append(r.Findings, Finding{Category: cat, Severity: sev, Title: title, Evidence: ev, Recommendation: rec})
	}

	// R8: a lossy trace degrades every finding below it (absence is not evidence
	// of absence), so flag it loudly.
	if b.Lossy {
		add("coverage", SevHigh, "trace was lossy — report is degraded",
			"the trace dropped events",
			"absence of a finding is not evidence of absence; re-run without drops before trusting this report")
	}

	// R1/R2/R3: capabilities, gated on full coverage. The seccomp backend cannot
	// observe cap_capable, so on a partial run we must NOT report "no caps" as if
	// it were evidence — we say so explicitly (R3) rather than going silent.
	if b.FullCoverage {
		for _, c := range b.Caps {
			sev := SevMedium
			if highRiskCaps[c] {
				sev = SevHigh
			}
			add("capabilities", sev, "capability held: "+c,
				"observed via cap_capable",
				"drop "+c+" if the program does not require it (firejail: omit from caps.keep)")
		}
		if len(b.Caps) == 0 {
			add("capabilities", SevInfo, "no capability use observed — program needs none",
				"full (eBPF) coverage observed no capability check",
				"set caps.drop all")
		}
	} else {
		// R3: honesty — do NOT go silent on a backend that can't see caps/NS.
		add("coverage", SevInfo, "capabilities and namespaces not observable on this backend",
			"seccomp/replay coverage cannot observe cap_capable or namespace creation",
			"re-run with --collector ebpf for capability and namespace findings")
	}

	// R4: namespaces, gated on full coverage (decode is eBPF-only).
	if b.FullCoverage {
		for _, n := range b.Namespaces {
			switch n {
			case "user":
				add("namespaces", SevHigh, "user namespace created: user",
					"observed unshare(CLONE_NEWUSER)",
					"user namespaces are a privilege-escalation surface; deny if unneeded")
			case "net":
				add("namespaces", SevMedium, "network namespace created: net",
					"observed unshare(CLONE_NEWNET)",
					"program manages its own networking; review the net policy")
			default:
				add("namespaces", SevLow, "namespace created: "+n,
					"observed unshare for "+n,
					"informational; confirm the program needs its own "+n+" namespace")
			}
		}
	}

	// R5: dangerous (gateable) syscalls actually observed — the inverse of
	// DeniedSyscalls(). open/openat/openat2 are ubiquitous (watched for gating,
	// not inherently dangerous), so they are Low; the rest are Medium.
	for _, sc := range profile.GateableSyscalls {
		if !b.Syscalls[sc] {
			continue
		}
		sev := SevMedium
		switch sc {
		case "open", "openat", "openat2":
			sev = SevLow
		}
		add("syscalls", sev, "dangerous syscall observed: "+sc,
			"the program invoked "+sc,
			"ensure this syscall is intended; a generated seccomp profile keeps it allowed")
	}

	// R6: sensitive file access.
	for _, f := range b.Files {
		if reason := sensitiveReason(f); reason != "" {
			add("files", SevHigh, "sensitive file accessed: "+f,
				"observed open of "+f+" ("+reason+")",
				"confirm the program legitimately needs this path; restrict via the firejail whitelist")
		}
	}

	// R7: profile effectiveness — what the matching seccomp profile actually buys.
	denied := b.DeniedSyscalls()
	add("effectiveness", SevInfo,
		fmt.Sprintf("generated seccomp profile would deny %d of %d watched dangerous syscalls",
			len(denied), len(profile.GateableSyscalls)),
		"denies: "+strings.Join(denied, ", "),
		"run `jailgraph profile --run "+b.RunID+" --format seccomp` to emit it")

	finalize(&r)
	return r
}

// severityOrder is the render/summary order (worst first).
var severityOrder = []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}

// HasHighOrAbove reports whether any finding is at or above High — drives the
// CLI exit code (the CI gate).
func (r Report) HasHighOrAbove() bool {
	for _, f := range r.Findings {
		if f.Severity.rank() >= SevHigh.rank() {
			return true
		}
	}
	return false
}

// counts returns the number of findings per severity.
func (r Report) counts() map[Severity]int {
	m := map[Severity]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}

// RenderText renders a Lynis-style report: the coverage preamble first (epistemic
// state before findings), then findings grouped worst-first, then a severity
// summary line. Mirrors audit.Report.RenderText's strings.Builder idiom.
func (r Report) RenderText() string {
	var sb strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&sb, f, a...); sb.WriteByte('\n') }

	w("hardening report")
	w("  target:   %s", r.Target)
	w("  run:      %s", r.RunID)
	w("  coverage: %s", r.Coverage)
	if !strings.HasPrefix(r.Coverage, "full") {
		w("  NOTE: capabilities and namespaces are not observable on this backend;")
		w("        re-run with --collector ebpf for those findings.")
	}
	if r.Lossy {
		w("  WARNING: trace was lossy — findings may be incomplete (absence is not evidence of absence).")
	}
	w("")

	for _, sev := range severityOrder {
		first := true
		for _, f := range r.Findings {
			if f.Severity != sev {
				continue
			}
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

	c := r.counts()
	var parts []string
	for _, sev := range severityOrder {
		if c[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[sev], titleCase(string(sev))))
		}
	}
	if len(parts) == 0 {
		parts = []string{"no findings"}
	}
	w("summary: %s", strings.Join(parts, ", "))
	return sb.String()
}

// titleCase upper-cases the first byte of an ASCII word (severity labels are
// lowercase ASCII). Avoids the deprecated strings.Title.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// sensitiveExact/sensitiveDirs drive R6. Kept deliberately small and
// evidence-based — credential and kernel-memory paths, not a CVE database.
var sensitiveExact = []string{"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/dev/mem", "/dev/kmem"}
var sensitiveDirs = []string{"/root/.ssh", "/etc/ssh", "/etc/sudoers.d"}

// sensitiveReason returns a non-empty reason if path is security-sensitive.
func sensitiveReason(p string) string {
	for _, e := range sensitiveExact {
		if p == e {
			return "credential/kernel-memory file"
		}
	}
	for _, d := range sensitiveDirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return "credential/key directory"
		}
	}
	if strings.Contains(p, "/.ssh/id_") {
		return "ssh private key"
	}
	if strings.HasPrefix(p, "/proc/") && strings.HasSuffix(p, "/mem") {
		return "process memory"
	}
	return ""
}

// finalize sorts findings worst-first: descending severity, then category, then
// title — deterministic output for both RenderText and --json.
func finalize(r *Report) {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity.rank() != b.Severity.rank() {
			return a.Severity.rank() > b.Severity.rank()
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Title < b.Title
	})
}
