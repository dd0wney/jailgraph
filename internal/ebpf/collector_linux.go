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
	evSpawn uint32 = 1
)

// rawEvent mirrors `struct event` in trace.bpf.c (all fields 4-byte aligned).
type rawEvent struct {
	Kind uint32
	Pid  uint32
	Ppid uint32
	Path [256]byte
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
		c.emit(c.toBehavior(ev))
	}
}

func (c *ebpfCollector) toBehavior(ev rawEvent) collector.BehaviorEvent {
	be := collector.BehaviorEvent{PID: int32(ev.Pid), PPID: int32(ev.Ppid), Timestamp: time.Now()}
	switch ev.Kind {
	case evSpawn:
		be.Kind = collector.EventSpawn
	}
	return be
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
