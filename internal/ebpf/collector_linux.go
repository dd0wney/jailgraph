//go:build linux

// Package ebpf is the second Collector backend (Strategy 3): it traces a target
// with eBPF instead of seccomp user-notify. Its decisive advantage is FULL
// syscall coverage — a raw tracepoint on sys_enter records every syscall the
// target makes, including the read/write/mmap hot path the seccomp backend
// skips for performance. That full set is what lets the profile generator build
// a genuinely tight (default-deny) allowlist rather than baseline-plus-gating.
//
// v1.0 records the per-PID syscall set for a single seeded target PID. The
// committed bpf2go artifacts (trace_bpfel.go + trace_bpfel.o) mean `go build`
// needs no clang; regenerate with `make bpf-generate`.
package ebpf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// Config configures the eBPF collector.
type Config struct {
	// EventBuffer sizes the channel returned by Start (default 1024).
	EventBuffer int
	// PollInterval bounds how often the recv loop checks for target exit.
	PollInterval time.Duration
}

type ebpfCollector struct {
	target string
	args   []string
	cfg    Config

	objs traceObjects
	lnk  link.Link
	cmd  *exec.Cmd

	out       chan collector.BehaviorEvent
	errs      chan error
	childDone chan struct{}
	once      sync.Once
	waitErr   error
}

// NewCollector returns an eBPF-backed Collector for target.
func NewCollector(target string, args []string, cfg Config) (collector.Collector, error) {
	if cfg.EventBuffer <= 0 {
		cfg.EventBuffer = 1024
	}
	return &ebpfCollector{target: target, args: args, cfg: cfg}, nil
}

func (c *ebpfCollector) Start(ctx context.Context) (<-chan collector.BehaviorEvent, error) {
	// On modern kernels memlock is unlimited for BPF, but removing the limit
	// keeps us working on older ones too.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	if err := loadTraceObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: c.objs.HandleSysEnter,
	})
	if err != nil {
		c.objs.Close()
		return nil, fmt.Errorf("attach sys_enter: %w", err)
	}
	c.lnk = lnk

	// Launch the target. NOTE (v1.0): there is a small startup race — the target
	// may execute a few syscalls between exec and seeding its PID into `tracked`.
	// We seed immediately to minimize it; a stopped-child seed (pipe sync) is the
	// follow-up that closes it fully.
	cmd := exec.CommandContext(ctx, c.target, c.args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		c.cleanup()
		return nil, fmt.Errorf("start target: %w", err)
	}
	c.cmd = cmd
	pid := uint32(cmd.Process.Pid)
	if err := c.objs.Tracked.Put(pid, uint8(1)); err != nil {
		c.cleanup()
		return nil, fmt.Errorf("seed tracked pid: %w", err)
	}

	c.out = make(chan collector.BehaviorEvent, c.cfg.EventBuffer)
	c.errs = make(chan error, c.cfg.EventBuffer)
	c.childDone = make(chan struct{})
	go func() {
		c.once.Do(func() { c.waitErr = c.cmd.Wait() })
		close(c.childDone)
	}()
	go c.drainOnExit(ctx, pid)
	return c.out, nil
}

// drainOnExit waits for the target to finish, then materializes the recorded
// per-PID syscall set into BehaviorEvents. (v1.0 reads the set at teardown
// rather than streaming; ringbuf-based exec/open/fork events are layered next.)
func (c *ebpfCollector) drainOnExit(ctx context.Context, pid uint32) {
	defer close(c.out)
	defer close(c.errs)
	select {
	case <-c.childDone:
	case <-ctx.Done():
	}
	var key uint64
	var val uint8
	it := c.objs.Seen.Iterate()
	for it.Next(&key, &val) {
		evPID := int32(key >> 32)
		nr := int(uint32(key))
		c.emit(collector.BehaviorEvent{
			Kind:        collector.EventSyscall,
			PID:         evPID,
			Timestamp:   time.Now(),
			SyscallNr:   nr,
			SyscallName: syscallName(nr),
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
	if c.lnk != nil {
		c.lnk.Close()
		c.lnk = nil
	}
	c.objs.Close()
}
