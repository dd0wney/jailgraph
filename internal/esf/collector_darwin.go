//go:build darwin

// The macOS live collector. It spawns Apple's `eslogger` (Endpoint Security)
// under a PTY so its JSON stdout line-buffers — a plain pipe block-buffers and
// would lose the unflushed tail when we stop it. eslogger streams system-wide;
// the tracker (tracker.go) filters to the target's process subtree. eslogger
// must run as root (it is Apple-signed with the ES entitlement, so our binary
// needs none); the target is dropped back to the invoking user so it does not
// run as root. The lifecycle mirrors the eBPF backend (internal/ebpf).
package esf

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/dd0wney/jailgraph/internal/collector"
)

const esloggerPath = "/usr/bin/eslogger"

// esEventTypes are the ES event short-names we subscribe to.
var esEventTypes = []string{"exec", "fork", "exit", "open", "write", "rename", "unlink"}

// startupGrace lets eslogger subscribe before the target launches, so the
// target's earliest events are not missed.
const startupGrace = 600 * time.Millisecond

// drainGrace lets the pty flush in-flight events after the target exits.
const drainGrace = 300 * time.Millisecond

// Config configures the esf collector.
type Config struct {
	EventBuffer int
}

type esfCollector struct {
	target string
	args   []string
	cfg    Config

	eslogger *exec.Cmd
	ptmx     *os.File
	cmd      *exec.Cmd
	tr       *tracker

	out       chan collector.BehaviorEvent
	errs      chan error
	childDone chan struct{}
	scanDone  chan struct{}
	once      sync.Once
	waitErr   error
}

// NewCollector returns an eslogger-backed Collector for target.
func NewCollector(target string, args []string, cfg Config) (collector.Collector, error) {
	if cfg.EventBuffer <= 0 {
		cfg.EventBuffer = 1024
	}
	return &esfCollector{target: target, args: args, cfg: cfg}, nil
}

func (c *esfCollector) Start(ctx context.Context) (<-chan collector.BehaviorEvent, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("the esf collector needs root for eslogger — re-run under sudo")
	}

	// eslogger under a pty so its JSON output line-buffers.
	c.eslogger = exec.CommandContext(ctx, esloggerPath, append(append([]string{}, esEventTypes...), "--format", "json")...)
	ptmx, err := pty.Start(c.eslogger)
	if err != nil {
		return nil, fmt.Errorf("start eslogger (need sudo + Full Disk Access for the terminal?): %w", err)
	}
	c.ptmx = ptmx
	time.Sleep(startupGrace) // let eslogger subscribe before the target runs

	// Launch the target, dropped to the invoking (pre-sudo) user so it is not
	// traced running as root.
	c.cmd = exec.CommandContext(ctx, c.target, c.args...)
	c.cmd.Stdin, c.cmd.Stdout, c.cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if cred := invokingUserCred(); cred != nil {
		c.cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	if err := c.cmd.Start(); err != nil {
		c.cleanup()
		return nil, fmt.Errorf("start target: %w", err)
	}
	c.tr = newTracker(int32(c.cmd.Process.Pid))

	c.out = make(chan collector.BehaviorEvent, c.cfg.EventBuffer)
	c.errs = make(chan error, c.cfg.EventBuffer)
	c.childDone = make(chan struct{})
	c.scanDone = make(chan struct{})

	go func() {
		c.once.Do(func() { c.waitErr = c.cmd.Wait() })
		close(c.childDone)
	}()
	go c.scan()
	go c.finalize(ctx)
	return c.out, nil
}

// scan reads eslogger's pty output line by line, decodes, tracks, and emits.
func (c *esfCollector) scan() {
	defer close(c.scanDone)
	sc := bufio.NewScanner(c.ptmx)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // ES lines are large
	for sc.Scan() {
		line := bytes.TrimRight(sc.Bytes(), "\r")
		if len(line) == 0 || line[0] != '{' {
			continue // pty banner / blank
		}
		ev, ok, err := decodeLine(line)
		if err != nil {
			c.emitErr(fmt.Errorf("decode eslogger line: %w", err))
			continue
		}
		if !ok {
			continue
		}
		for _, be := range c.tr.OnEvent(ev) {
			c.emit(be)
		}
	}
	// A read error after teardown (ptmx closed) is expected; surface anything else.
	if err := sc.Err(); err != nil && c.ptmx != nil {
		c.emitErr(fmt.Errorf("eslogger scan: %w", err))
	}
}

// finalize: wait for the target to exit, let the pty drain, stop eslogger, then
// emit the folded file activity and close the channels.
func (c *esfCollector) finalize(ctx context.Context) {
	defer close(c.out)
	defer close(c.errs)

	select {
	case <-c.childDone:
	case <-ctx.Done():
	}
	time.Sleep(drainGrace)
	c.stopEslogger() // closes ptmx → unblocks scan
	<-c.scanDone

	for _, be := range c.tr.Fold() {
		c.emit(be)
	}
}

func (c *esfCollector) stopEslogger() {
	if c.ptmx != nil {
		_ = c.ptmx.Close()
	}
	if c.eslogger != nil && c.eslogger.Process != nil {
		_ = c.eslogger.Process.Kill()
		_ = c.eslogger.Wait()
	}
}

func (c *esfCollector) emit(ev collector.BehaviorEvent) {
	select {
	case c.out <- ev:
	default:
	}
}

func (c *esfCollector) emitErr(err error) {
	select {
	case c.errs <- err:
	default:
	}
}

func (c *esfCollector) Errors() <-chan error { return c.errs }

func (c *esfCollector) Wait() error {
	if c.childDone != nil {
		<-c.childDone
	}
	return c.waitErr
}

func (c *esfCollector) Close() error {
	c.cleanup()
	return nil
}

func (c *esfCollector) cleanup() {
	c.stopEslogger()
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
}

// invokingUserCred returns the pre-sudo user's credential (from SUDO_UID/GID) so
// the target runs as that user rather than root. Returns nil when not under sudo.
func invokingUserCred() *syscall.Credential {
	uid, gid := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if uid == "" || gid == "" {
		return nil
	}
	u, err1 := strconv.Atoi(uid)
	g, err2 := strconv.Atoi(gid)
	if err1 != nil || err2 != nil {
		return nil
	}
	return &syscall.Credential{Uid: uint32(u), Gid: uint32(g)}
}
