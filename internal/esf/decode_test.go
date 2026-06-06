package esf

import "testing"

func TestDecodeLine_Kinds(t *testing.T) {
	cases := []struct {
		line     string
		wantKind esKind
		wantPID  int32
		wantPath string
		wantExe  string
	}{
		{`{"event":{"exec":{"target":{"executable":{"path":"/usr/bin/myapp"}}}},"process":{"audit_token":{"pid":500},"ppid":1}}`, esExec, 500, "", "/usr/bin/myapp"},
		{`{"event":{"open":{"fflag":1537,"file":{"path":"/tmp/a"}}},"process":{"audit_token":{"pid":501},"ppid":500}}`, esOpen, 501, "/tmp/a", ""},
		{`{"event":{"write":{"target":{"path":"/tmp/a"}}},"process":{"audit_token":{"pid":501},"ppid":500}}`, esWrite, 501, "/tmp/a", ""},
		{`{"event":{"rename":{"source":{"path":"/tmp/a"}}},"process":{"audit_token":{"pid":501},"ppid":500}}`, esRename, 501, "/tmp/a", ""},
		{`{"event":{"unlink":{"target":{"path":"/tmp/old"}}},"process":{"audit_token":{"pid":501},"ppid":500}}`, esUnlink, 501, "/tmp/old", ""},
		{`{"event":{"exit":{"stat":0}},"process":{"audit_token":{"pid":501},"ppid":500}}`, esExit, 501, "", ""},
	}
	for _, c := range cases {
		e, ok, err := decodeLine([]byte(c.line))
		if err != nil || !ok {
			t.Fatalf("decodeLine(%s) ok=%v err=%v", c.line, ok, err)
		}
		if e.Kind != c.wantKind || e.PID != c.wantPID || e.Path != c.wantPath || e.ExePath != c.wantExe {
			t.Errorf("decode %s => %+v, want kind=%d pid=%d path=%q exe=%q", c.line, e, c.wantKind, c.wantPID, c.wantPath, c.wantExe)
		}
	}
}

func TestDecodeLine_ForkChildPID(t *testing.T) {
	e, ok, err := decodeLine([]byte(`{"event":{"fork":{"child":{"audit_token":{"pid":777}}}},"process":{"audit_token":{"pid":500},"ppid":1}}`))
	if err != nil || !ok || e.Kind != esFork || e.PID != 500 || e.ChildPID != 777 {
		t.Fatalf("fork decode => %+v ok=%v err=%v", e, ok, err)
	}
}

func TestDecodeLine_UnknownKeySkipped(t *testing.T) {
	_, ok, err := decodeLine([]byte(`{"event":{"close":{"file":{"path":"/x"}}},"process":{"audit_token":{"pid":1}}}`))
	if err != nil || ok {
		t.Errorf("unmapped event key should skip (ok=false, err=nil), got ok=%v err=%v", ok, err)
	}
}

func TestDecodeLine_MalformedIsError(t *testing.T) {
	if _, _, err := decodeLine([]byte(`not json`)); err == nil {
		t.Error("malformed JSON should error")
	}
}

func TestOpenMode(t *testing.T) {
	cases := map[uint32]string{
		0:     "r",         // O_RDONLY
		1:     "w",         // O_WRONLY
		2:     "rw",        // O_RDWR
		1537:  "w+create",  // O_WRONLY|O_CREAT|O_TRUNC
		0x201: "w+create",  // O_WRONLY|O_CREAT
		0x202: "rw+create", // O_RDWR|O_CREAT
	}
	for f, want := range cases {
		if got := openMode(f); got != want {
			t.Errorf("openMode(%#x) = %q, want %q", f, got, want)
		}
	}
}
