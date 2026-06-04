//go:build linux

package seccomp

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// maxPathLen bounds a pathname read from the target to avoid unbounded reads.
const maxPathLen = 4096

// decode turns a notification into a BehaviorEvent. For syscalls whose
// arguments are pointers into the target's address space (exec, open) it reads
// the target's memory and then RE-VALIDATES the notification id: if the target
// died or the syscall was interrupted in the meantime, the pid may have been
// reused and the read is untrustworthy, so the event is discarded (ok=false)
// rather than emitted as fact.
//
// Capability (capset) and namespace (setns) decoding is deferred to a later
// increment; those syscalls are still observed via the INVOKED edge by
// downgrading them to a plain syscall event here.
func (s *supervisor) decode(req seccompNotif) (collector.BehaviorEvent, bool, error) {
	nr := int(req.data.nr)
	pid := int32(req.pid)
	ev := collector.BehaviorEvent{
		Kind:        s.tables.kinds[nr],
		PID:         pid,
		PPID:        readPPID(pid),
		Timestamp:   time.Now(),
		SyscallNr:   nr,
		SyscallName: s.tables.names[nr],
		UID:         readUID(pid),
	}

	switch ev.Kind {
	case collector.EventExec:
		path, err := readCString(pid, uintptr(req.data.args[0]))
		if err != nil {
			return ev, false, nil // unreadable arg; skip rather than fabricate
		}
		if !notifIDValid(s.notifyFD, req.id) {
			return ev, false, nil // TOCTOU: target gone, discard the read
		}
		ev.Exe = path
		ev.BinSHA256 = bestEffortSHA256(path)

	case collector.EventOpen:
		pathIdx := openPathArgIndex(ev.SyscallName)
		path, err := readCString(pid, uintptr(req.data.args[pathIdx]))
		if err != nil {
			return ev, false, nil
		}
		if !notifIDValid(s.notifyFD, req.id) {
			return ev, false, nil
		}
		ev.Path = path
		ev.OpenMode = decodeOpenMode(ev.SyscallName, req.data.args)

	case collector.EventCap, collector.EventJoinNS:
		// Decoding deferred: record only the syscall invocation for now.
		ev.Kind = collector.EventSyscall
	}

	return ev, true, nil
}

// openPathArgIndex returns the index of the pathname argument for the given
// open-family syscall. open(path, ...) has it at 0; openat*(dirfd, path, ...)
// at 1.
func openPathArgIndex(name string) int {
	if name == "open" {
		return 0
	}
	return 1
}

// decodeOpenMode renders the access intent from the flags argument. openat2's
// flags live in an open_how struct (a pointer), which we do not dereference
// here; it returns "" in that case.
func decodeOpenMode(name string, args [6]uint64) string {
	var flags uint64
	switch name {
	case "open":
		flags = args[1]
	case "openat":
		flags = args[2]
	default: // openat2 and anything else: flags not directly available
		return ""
	}
	mode := "r"
	switch flags & uint64(unix.O_ACCMODE) {
	case uint64(unix.O_WRONLY):
		mode = "w"
	case uint64(unix.O_RDWR):
		mode = "rw"
	}
	if flags&uint64(unix.O_CREAT) != 0 {
		mode += "+create"
	}
	return mode
}

// readCString reads a NUL-terminated string from the target's memory at addr.
func readCString(pid int32, addr uintptr) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, maxPathLen)
	n, err := f.ReadAt(buf, int64(addr))
	if n == 0 && err != nil && err != io.EOF {
		return "", err
	}
	if i := strings.IndexByte(string(buf[:n]), 0); i >= 0 {
		return string(buf[:i]), nil
	}
	return "", fmt.Errorf("no NUL terminator within %d bytes", maxPathLen)
}

// bestEffortSHA256 hashes the file at path; it returns "" on any error rather
// than fabricating a value (the BinSHA256 field is documented as best-effort).
func bestEffortSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// readPPID parses the parent pid from /proc/<pid>/stat. Field 4 (1-indexed) is
// ppid, but the comm field (field 2) may contain spaces/parens, so we split
// after the closing paren.
func readPPID(pid int32) int32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(data)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 || rparen+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[rparen+2:]) // state, ppid, ...
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return int32(ppid)
}

// readUID parses the real UID from /proc/<pid>/status (the "Uid:" line).
func readUID(pid int32) uint32 {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if uid, err := strconv.Atoi(fields[1]); err == nil {
					return uint32(uid)
				}
			}
			return 0
		}
	}
	return 0
}
