//go:build linux

// Package ebpf is the second Collector backend (Strategy 3): it traces a target
// with eBPF instead of seccomp user-notify. Its decisive advantage is FULL
// syscall coverage — a raw tracepoint on sys_enter records every syscall the
// target (and, since v1.1, its descendants) make, including the read/write/mmap
// hot path the seccomp backend skips. That full set is what lets the profile
// generator build a tight default-deny allowlist.
//
// v1.1a: descendant following + race-free seeding + SPAWN events. The launcher's
// own tgid is recorded before fork; the target is born as its child and tracked
// at fork time (before its first syscall), so there is no startup race and no
// re-exec wrapper. fork events stream over a ringbuf; the syscall set is read
// from a map at teardown.
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// event kinds, mirroring trace.bpf.c.
const (
	evSpawn  uint32 = 1
	evExec   uint32 = 2
	evOpen   uint32 = 3
	evNS     uint32 = 4
	evRename uint32 = 5
	evUnlink uint32 = 6
)

// evDNS (7) matches EVENT_DNS in trace.bpf.c; defined in dns.go alongside the
// platform-neutral qname parser so both live in one place.

// rawEvent mirrors `struct event` in trace.bpf.c (all fields 4-byte aligned).
type rawEvent struct {
	Kind  uint32
	Pid   uint32
	Ppid  uint32
	Flags uint32 // NS: the CLONE_NEW* bits unshared
	Path  [256]byte
}

// nsBits maps CLONE_NEW* flags to namespace type names (matching trace.bpf.c).
var nsBits = []struct {
	bit  uint32
	name string
}{
	{0x00020000, "mnt"}, {0x04000000, "uts"}, {0x08000000, "ipc"},
	{0x10000000, "user"}, {0x20000000, "pid"}, {0x40000000, "net"},
	{0x02000000, "cgroup"}, {0x00000080, "time"},
}

// drainGrace is how long we let the ringbuf flush in-flight events after the
// target exits, before closing the reader.
const drainGrace = 200 * time.Millisecond

// Config configures the eBPF collector.
type Config struct {
	EventBuffer  int
	PollInterval time.Duration
}

type ebpfCollector struct {
	target string
	args   []string
	cfg    Config

	objs   traceObjects
	links  []link.Link
	reader *ringbuf.Reader
	cmd    *exec.Cmd

	out         chan collector.BehaviorEvent
	errs        chan error
	childDone   chan struct{}
	ringbufDone chan struct{}
	once        sync.Once
	waitErr     error

	// fileAgg folds per-file write/rename/unlink activity. Written only by the
	// ringbuf goroutine (renames/unlinks) and by finalize (writes, after the
	// ringbuf goroutine has finished — see the <-ringbufDone barrier), so no lock
	// is needed.
	fileAgg map[string]*fileStat

	// dnsAgg folds DNS queries per (pid, name). Written only by the ringbuf
	// goroutine; read in finalize after <-ringbufDone (no lock needed).
	dnsAgg map[dnsKey]int64
}

// dnsKey identifies one folded (process, queried-name) pair.
type dnsKey struct {
	pid  int32
	name string
}

// NewCollector returns an eBPF-backed Collector for target.
func NewCollector(target string, args []string, cfg Config) (collector.Collector, error) {
	if cfg.EventBuffer <= 0 {
		cfg.EventBuffer = 1024
	}
	return &ebpfCollector{target: target, args: args, cfg: cfg}, nil
}

func (c *ebpfCollector) Start(ctx context.Context) (<-chan collector.BehaviorEvent, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	if err := loadTraceObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	// Seed the launcher tgid BEFORE forking the target, so the target is tracked
	// at fork time (race-free). The launcher itself is never added to `tracked`.
	if err := c.objs.Launcher.Put(uint32(0), uint32(os.Getpid())); err != nil {
		c.cleanup()
		return nil, fmt.Errorf("seed launcher tgid: %w", err)
	}

	if err := c.attach("sys_enter", c.objs.HandleSysEnter); err != nil {
		c.cleanup()
		return nil, err
	}
	if err := c.attach("sched_process_fork", c.objs.HandleFork); err != nil {
		c.cleanup()
		return nil, err
	}
	if err := c.attach("sched_process_exec", c.objs.HandleExec); err != nil {
		c.cleanup()
		return nil, err
	}
	// fentry (security_file_open) attaches via the tracing link, not a raw
	// tracepoint. bpf_d_path is allowlisted for this hook.
	openLink, err := link.AttachTracing(link.TracingOptions{Program: c.objs.HandleOpen})
	if err != nil {
		c.cleanup()
		return nil, fmt.Errorf("attach security_file_open: %w", err)
	}
	c.links = append(c.links, openLink)
	// fentry on cap_capable: records capabilities the subtree's actions require.
	capLink, err := link.AttachTracing(link.TracingOptions{Program: c.objs.HandleCap})
	if err != nil {
		c.cleanup()
		return nil, fmt.Errorf("attach cap_capable: %w", err)
	}
	c.links = append(c.links, capLink)
	// fentry on ksys_unshare: records namespace types the subtree creates.
	unshareLink, err := link.AttachTracing(link.TracingOptions{Program: c.objs.HandleUnshare})
	if err != nil {
		c.cleanup()
		return nil, fmt.Errorf("attach ksys_unshare: %w", err)
	}
	c.links = append(c.links, unshareLink)
	// fentry on vfs_write / security_inode_rename / security_inode_unlink: the
	// ransomware-signal capture (write volume per inode + extension churn).
	// security_socket_connect: the egress-connect (network) signal.
	for _, h := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"vfs_write", c.objs.HandleWrite},
		{"security_inode_rename", c.objs.HandleRename},
		{"security_inode_unlink", c.objs.HandleUnlink},
		{"security_socket_connect", c.objs.HandleConnect},
		{"udp_sendmsg", c.objs.HandleDnsSend},
	} {
		l, err := link.AttachTracing(link.TracingOptions{Program: h.prog})
		if err != nil {
			c.cleanup()
			return nil, fmt.Errorf("attach %s: %w", h.name, err)
		}
		c.links = append(c.links, l)
	}

	rd, err := ringbuf.NewReader(c.objs.Events)
	if err != nil {
		c.cleanup()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	c.reader = rd

	cmd := exec.CommandContext(ctx, c.target, c.args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		c.cleanup()
		return nil, fmt.Errorf("start target: %w", err)
	}
	c.cmd = cmd

	c.out = make(chan collector.BehaviorEvent, c.cfg.EventBuffer)
	c.errs = make(chan error, c.cfg.EventBuffer)
	c.childDone = make(chan struct{})
	c.ringbufDone = make(chan struct{})
	c.fileAgg = make(map[string]*fileStat)
	c.dnsAgg = make(map[dnsKey]int64)

	go func() {
		c.once.Do(func() { c.waitErr = c.cmd.Wait() })
		close(c.childDone)
	}()
	go c.readRingbuf()
	go c.finalize(ctx)
	return c.out, nil
}

func (c *ebpfCollector) attach(name string, prog *ebpf.Program) error {
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: name, Program: prog})
	if err != nil {
		return fmt.Errorf("attach %s: %w", name, err)
	}
	c.links = append(c.links, l)
	return nil
}

// readRingbuf streams SPAWN/EXEC/OPEN records until the reader is closed.
func (c *ebpfCollector) readRingbuf() {
	defer close(c.ringbufDone)
	for {
		rec, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			c.emitErr(fmt.Errorf("ringbuf read: %w", err))
			continue
		}
		var ev rawEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			c.emitErr(fmt.Errorf("decode event: %w", err))
			continue
		}
		for _, be := range c.toBehaviors(ev) {
			c.emit(be)
		}
	}
}

// toBehaviors decodes a raw event into one or more BehaviorEvents. NS events fan
// out to one JOINED_NS per CLONE_NEW* bit set.
func (c *ebpfCollector) toBehaviors(ev rawEvent) []collector.BehaviorEvent {
	base := collector.BehaviorEvent{PID: int32(ev.Pid), PPID: int32(ev.Ppid), Timestamp: time.Now()}
	switch ev.Kind {
	case evSpawn:
		base.Kind = collector.EventSpawn
		return []collector.BehaviorEvent{base}
	case evExec:
		base.Kind = collector.EventExec
		base.Exe = cstr(ev.Path[:])
		return []collector.BehaviorEvent{base}
	case evOpen:
		base.Kind = collector.EventOpen
		base.Path = cstr(ev.Path[:])
		return []collector.BehaviorEvent{base}
	case evNS:
		var out []collector.BehaviorEvent
		for _, b := range nsBits {
			if ev.Flags&b.bit != 0 {
				e := base
				e.Kind = collector.EventJoinNS
				e.NSType = b.name
				out = append(out, e)
			}
		}
		return out
	case evRename:
		c.bumpChurn(cstr(ev.Path[:]), 1, 0)
		return nil // folded; emitted as EventFileActivity at teardown
	case evUnlink:
		c.bumpChurn(cstr(ev.Path[:]), 0, 1)
		return nil
	case evDNS:
		n := int(ev.Flags)
		if n > len(ev.Path) {
			n = len(ev.Path)
		}
		name, err := parseDNSQName(ev.Path[:n])
		if err != nil {
			c.emitErr(fmt.Errorf("parse dns query (pid %d): %w", ev.Pid, err))
			return nil
		}
		c.bumpDNS(int32(ev.Pid), name)
		return nil // folded; emitted as EventDNS at teardown
	}
	return nil
}

// bumpChurn folds a streamed rename/unlink into the per-file aggregate. Called
// only from the ringbuf goroutine.
func (c *ebpfCollector) bumpChurn(name string, renames, unlinks int64) {
	if name == "" {
		return
	}
	st := c.fileAgg[name]
	if st == nil {
		st = &fileStat{}
		c.fileAgg[name] = st
	}
	st.renames += renames
	st.unlinks += unlinks
}

// bumpDNS folds a streamed DNS query into the per-(pid,name) aggregate. Called
// only from the ringbuf goroutine.
func (c *ebpfCollector) bumpDNS(pid int32, name string) {
	if name == "" {
		return
	}
	c.dnsAgg[dnsKey{pid, name}]++
}

// cstr converts a NUL-terminated C char array to a Go string.
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// finalize implements the shutdown ordering: wait for target exit, let the
// ringbuf flush, close the reader (unblocking readRingbuf), then read the
// syscall set, then close the output. Doing it in this order avoids both a
// hung ringbuf reader and a lost final flush.
func (c *ebpfCollector) finalize(ctx context.Context) {
	defer close(c.out)
	defer close(c.errs)

	select {
	case <-c.childDone:
	case <-ctx.Done():
	}
	time.Sleep(drainGrace) // let in-flight ringbuf records drain
	_ = c.reader.Close()   // unblocks readRingbuf's Read
	<-c.ringbufDone        // wait for the ringbuf goroutine to finish

	// Materialize the full per-pid syscall set captured in the map.
	var key uint64
	var val uint8
	it := c.objs.Seen.Iterate()
	for it.Next(&key, &val) {
		c.emit(collector.BehaviorEvent{
			Kind:        collector.EventSyscall,
			PID:         int32(key >> 32),
			Timestamp:   time.Now(),
			SyscallNr:   int(uint32(key)),
			SyscallName: syscallName(int(uint32(key))),
		})
	}
	if err := it.Err(); err != nil {
		c.emitErr(fmt.Errorf("iterate seen map: %w", err))
	}

	// Materialize the capabilities the subtree's actions required.
	var ckey uint64
	var cval uint8
	cit := c.objs.SeenCaps.Iterate()
	for cit.Next(&ckey, &cval) {
		c.emit(collector.BehaviorEvent{
			Kind:      collector.EventCap,
			PID:       int32(ckey >> 32),
			Timestamp: time.Now(),
			CapName:   capName(int(uint32(ckey))),
		})
	}
	if err := cit.Err(); err != nil {
		c.emitErr(fmt.Errorf("iterate seen_caps map: %w", err))
	}

	// Fold per-inode write volume into the per-path file-activity aggregate,
	// resolving each inode to the path captured at open-for-write, then emit one
	// FileActivity event per file. Touching fileAgg here is safe: the ringbuf
	// goroutine (the only other writer) has finished (<-ringbufDone above).
	var ino uint64
	var ws traceWriteStat // generated type: exact C layout incl. the content sample
	var pb [256]byte
	var writes []pathWrite
	wit := c.objs.WriteStats.Iterate()
	for wit.Next(&ino, &ws) {
		path := fmt.Sprintf("inode:%d", ino) // fallback if no open-for-write was seen
		if err := c.objs.WritePaths.Lookup(&ino, &pb); err == nil {
			if p := cstr(pb[:]); p != "" {
				path = p
			}
		}
		// Copy the per-file write-content sample (ws is reused each iteration).
		var sample []byte
		if n := int(ws.SampleLen); n > 0 {
			if n > len(ws.Sample) {
				n = len(ws.Sample)
			}
			sample = append([]byte(nil), ws.Sample[:n]...)
		}
		writes = append(writes, pathWrite{
			path:   path,
			stat:   writeStat{Count: ws.Count, Bytes: ws.Bytes},
			sample: sample,
		})
	}
	if err := wit.Err(); err != nil {
		c.emitErr(fmt.Errorf("iterate write_stats map: %w", err))
	}
	for _, be := range foldFileActivity(c.fileAgg, writes) {
		be.Timestamp = time.Now()
		c.emit(be)
	}

	// Materialize folded egress connects: one EventConnect per (process,
	// destination). Like write_stats, the hot connect path was folded in-kernel;
	// we read the count out here. Safe to touch after <-ringbufDone.
	var ck traceConnKey
	var cs traceConnStat
	cit2 := c.objs.ConnStats.Iterate()
	for cit2.Next(&ck, &cs) {
		be := connToBehavior(
			connKey{TGID: ck.Tgid, Family: ck.Family, Port: ntohs(ck.Dport), Addr: ck.Daddr},
			connStat{Count: cs.Count, Proto: cs.Proto},
		)
		be.Timestamp = time.Now()
		c.emit(be)
	}
	if err := cit2.Err(); err != nil {
		c.emitErr(fmt.Errorf("iterate conn_stats map: %w", err))
	}

	// Emit folded DNS queries: one EventDNS per (process, name) with its count.
	for k, count := range c.dnsAgg {
		c.emit(collector.BehaviorEvent{
			Kind: collector.EventDNS, PID: k.pid, Domain: k.name,
			ResolveCount: count, Timestamp: time.Now(),
		})
	}
}

func (c *ebpfCollector) emit(ev collector.BehaviorEvent) {
	select {
	case c.out <- ev:
	default:
	}
}

func (c *ebpfCollector) emitErr(err error) {
	select {
	case c.errs <- err:
	default:
	}
}

func (c *ebpfCollector) Errors() <-chan error { return c.errs }

func (c *ebpfCollector) Wait() error {
	if c.childDone != nil {
		<-c.childDone
	}
	return c.waitErr
}

func (c *ebpfCollector) Close() error {
	c.cleanup()
	return nil
}

func (c *ebpfCollector) cleanup() {
	if c.reader != nil {
		_ = c.reader.Close()
		c.reader = nil
	}
	for _, l := range c.links {
		_ = l.Close()
	}
	c.links = nil
	c.objs.Close()
}
