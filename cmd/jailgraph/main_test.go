package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	cases := []struct {
		name       string
		argv       []string
		wantFlags  []string
		wantTarget string
		wantArgs   []string
	}{
		{"flags then target", []string{"-v", "--", "cat", "/etc/hostname"}, []string{"-v"}, "cat", []string{"/etc/hostname"}},
		{"no separator", []string{"-v", "x"}, []string{"-v", "x"}, "", nil},
		{"separator at end", []string{"-v", "--"}, []string{"-v"}, "", nil},
		{"separator first", []string{"--", "cat"}, []string{}, "cat", nil},
		{"empty", nil, nil, "", nil},
		{"multiple separators", []string{"--", "a", "--", "b"}, []string{}, "a", []string{"--", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			flags, target, args := splitArgs(c.argv)
			if target != c.wantTarget {
				t.Errorf("target = %q, want %q", target, c.wantTarget)
			}
			if !eq(flags, c.wantFlags) {
				t.Errorf("flags = %v, want %v", flags, c.wantFlags)
			}
			if !eq(args, c.wantArgs) {
				t.Errorf("args = %v, want %v", args, c.wantArgs)
			}
		})
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("JG_TEST_ENV", "value")
	if got := envOr("JG_TEST_ENV", "def"); got != "value" {
		t.Errorf("present: got %q, want value", got)
	}
	if got := envOr("JG_TEST_UNSET_XYZ", "def"); got != "def" {
		t.Errorf("absent: got %q, want def", got)
	}
	t.Setenv("JG_TEST_ENV", "")
	if got := envOr("JG_TEST_ENV", "def"); got != "def" {
		t.Errorf("empty value should fall back to default, got %q", got)
	}
}

func TestSplitCSV(t *testing.T) {
	cases := map[string][]string{
		"a,b,c":   {"a", "b", "c"},
		" a , b ": {"a", "b"},
		"a,,b,":   {"a", "b"}, // empty/trailing parts dropped
		"":        nil,
		"   ":     nil,
		"only":    {"only"},
	}
	for in, want := range cases {
		if got := splitCSV(in); !eq(got, want) {
			t.Errorf("splitCSV(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestResolveExit(t *testing.T) {
	if code, msg := resolveExit(errors.New("boom")); code != 1 || msg != "boom" {
		t.Errorf("plain error => (%d,%q), want (1,boom)", code, msg)
	}
	if code, msg := resolveExit(&exitErr{code: 2, msg: "lossy"}); code != 2 || msg != "lossy" {
		t.Errorf("exitErr{2,lossy} => (%d,%q), want (2,lossy)", code, msg)
	}
	// Drift case: code 1, empty message (report already printed → no stderr line).
	if code, msg := resolveExit(&exitErr{code: 1, msg: ""}); code != 1 || msg != "" {
		t.Errorf("exitErr{1,\"\"} => (%d,%q), want (1,\"\")", code, msg)
	}
}

func TestLoadFixture(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Valid: a one-event array.
	valid := write("ok.json", `[{"Kind":1,"PID":10,"Exe":"/bin/sh"}]`)
	evs, err := loadFixture(valid)
	if err != nil || len(evs) != 1 || evs[0].Exe != "/bin/sh" {
		t.Errorf("valid fixture: events=%v err=%v", evs, err)
	}
	// Empty array is valid → zero events.
	if evs, err := loadFixture(write("empty.json", `[]`)); err != nil || len(evs) != 0 {
		t.Errorf("empty array: events=%v err=%v", evs, err)
	}
	// Invalid JSON → error.
	if _, err := loadFixture(write("bad.json", `{not json`)); err == nil {
		t.Error("invalid JSON should error")
	}
	// Missing file → error.
	if _, err := loadFixture(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("missing file should error")
	}
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
