package profile

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleBehavior() Behavior {
	return Behavior{
		RunID:  "r1",
		Target: "/bin/sh",
		// Used openat + clone + execve; never used setns/unshare/capset/fork/open/vfork/openat2/clone3.
		Syscalls: map[string]bool{"openat": true, "clone": true, "execve": true, "execveat": true},
		Files:    []string{"/etc/hostname", "/etc/passwd", "/lib/x86_64-linux-gnu/libc.so.6"},
		Binaries: []string{"/bin/sh", "/bin/cat"},
	}
}

func TestDeniedSyscalls_GatesUnobservedDangerous(t *testing.T) {
	denied := sampleBehavior().DeniedSyscalls()
	// Exact membership (not substring: "openat" is a substring of "openat2").
	for _, used := range []string{"openat", "clone", "execve", "execveat"} {
		if contains(denied, used) {
			t.Errorf("denied list %v must not contain observed syscall %q", denied, used)
		}
	}
	for _, want := range []string{"setns", "unshare", "capset", "fork", "vfork", "open", "openat2", "clone3"} {
		if !contains(denied, want) {
			t.Errorf("expected %q to be denied; got %v", want, denied)
		}
	}
}

func TestRenderSeccompOCI_DefaultAllowWithErrnoDenies(t *testing.T) {
	data, err := RenderSeccompOCI(sampleBehavior(), SeccompOptions{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var prof struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(data, &prof); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Honest encoding: default ALLOW (we lack full coverage), explicit ERRNO denies.
	if prof.DefaultAction != "SCMP_ACT_ALLOW" {
		t.Errorf("defaultAction = %q, want SCMP_ACT_ALLOW", prof.DefaultAction)
	}
	if len(prof.Syscalls) != 1 || prof.Syscalls[0].Action != "SCMP_ACT_ERRNO" {
		t.Fatalf("expected one ERRNO rule, got %+v", prof.Syscalls)
	}
	if !contains(prof.Syscalls[0].Names, "setns") {
		t.Error("expected setns in the ERRNO deny list")
	}
}

func TestRenderSeccompOCI_NoDeniesWhenAllUsed(t *testing.T) {
	b := Behavior{RunID: "r2"}
	b.Syscalls = map[string]bool{}
	for _, sc := range GateableSyscalls {
		b.Syscalls[sc] = true
	}
	data, _ := RenderSeccompOCI(b, SeccompOptions{})
	var prof struct {
		Syscalls []any `json:"syscalls"`
	}
	_ = json.Unmarshal(data, &prof)
	if len(prof.Syscalls) != 0 {
		t.Errorf("expected no deny rules when all gateable syscalls used, got %d", len(prof.Syscalls))
	}
}

func fullCoverageBehavior(syscalls ...string) Behavior {
	m := map[string]bool{}
	for _, s := range syscalls {
		m[s] = true
	}
	return Behavior{RunID: "rfull", FullCoverage: true, Syscalls: m}
}

func parseSeccomp(t *testing.T, data []byte) (def string, allow []string) {
	t.Helper()
	var prof struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(data, &prof); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, r := range prof.Syscalls {
		if r.Action == "SCMP_ACT_ALLOW" {
			allow = append(allow, r.Names...)
		}
	}
	return prof.DefaultAction, allow
}

func TestRenderSeccompOCI_FullCoverageDefaultsToComplainMode(t *testing.T) {
	b := fullCoverageBehavior("openat", "read", "write")
	data, err := RenderSeccompOCI(b, SeccompOptions{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	def, allow := parseSeccomp(t, data)
	// Complain mode by default — safe, enforces nothing.
	if def != "SCMP_ACT_LOG" {
		t.Errorf("default action = %q, want SCMP_ACT_LOG (complain)", def)
	}
	// Allowlist = observed UNION safe floor; observed must be present...
	if !contains(allow, "openat") {
		t.Error("observed openat missing from allowlist")
	}
	// ...and the floor must be present...
	if !contains(allow, "futex") {
		t.Error("safe floor (futex) missing from allowlist")
	}
	// ...but never a dangerous syscall the program didn't use.
	for _, dangerous := range []string{"setns", "unshare", "ptrace", "execve", "clone"} {
		if contains(allow, dangerous) {
			t.Errorf("dangerous syscall %q must not be in the allowlist/floor", dangerous)
		}
	}
}

func TestRenderSeccompOCI_EnforceRefusesUnnamedSyscalls(t *testing.T) {
	// A run with a number-only syscall (eBPF partial name table) must refuse to
	// enforce — allowlisting by name would silently deny it and break the program.
	b := fullCoverageBehavior("openat", "read", "sys_278")
	if _, err := RenderSeccompOCI(b, SeccompOptions{Enforce: true}); err == nil {
		t.Fatal("expected enforce to refuse when an observed syscall is unnamed")
	}
	// Complain mode still works (unnamed syscalls just fall through to LOG).
	if _, err := RenderSeccompOCI(b, SeccompOptions{}); err != nil {
		t.Errorf("complain mode should tolerate unnamed syscalls: %v", err)
	}
}

func TestRenderSeccompOCI_EnforceRefusesLossy(t *testing.T) {
	b := fullCoverageBehavior("openat", "read")
	b.Lossy = true
	if _, err := RenderSeccompOCI(b, SeccompOptions{Enforce: true}); err == nil {
		t.Fatal("expected enforce to refuse a lossy run")
	}
}

func TestRenderSeccompOCI_EnforceEmitsDefaultDeny(t *testing.T) {
	b := fullCoverageBehavior("openat", "read", "write")
	data, err := RenderSeccompOCI(b, SeccompOptions{Enforce: true})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	def, allow := parseSeccomp(t, data)
	if def != "SCMP_ACT_ERRNO" {
		t.Errorf("enforce default action = %q, want SCMP_ACT_ERRNO", def)
	}
	if !contains(allow, "openat") {
		t.Error("observed syscall missing from enforced allowlist")
	}
}

func TestRenderFirejail_WhitelistsObservedDirsAndDropsUnused(t *testing.T) {
	out := RenderFirejail(sampleBehavior())
	for _, dir := range []string{"whitelist /etc", "whitelist /lib/x86_64-linux-gnu"} {
		if !strings.Contains(out, dir) {
			t.Errorf("firejail profile missing %q\n%s", dir, out)
		}
	}
	if !strings.Contains(out, "seccomp.drop") || !strings.Contains(out, "setns") {
		t.Error("expected a seccomp.drop line containing setns")
	}
	// Conservative defaults must be present and labeled.
	for _, want := range []string{"caps.drop all", "net none", "nonewprivs"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing conservative default %q", want)
		}
	}
}

func TestRenderFirejail_LossyWarning(t *testing.T) {
	b := sampleBehavior()
	b.Lossy = true
	if !strings.Contains(RenderFirejail(b), "WARNING: trace was lossy") {
		t.Error("lossy profile must carry a warning")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
