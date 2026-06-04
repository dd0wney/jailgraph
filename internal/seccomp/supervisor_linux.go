//go:build linux

// Package seccomp implements the first Collector backend: it traces a target
// program with a seccomp user-notification filter and emits decoded
// BehaviorEvents. It is observe-only — every notification is answered with
// CONTINUE, so the target runs normally and nothing is ever blocked.
//
// This package is the only OS-locked part of jailgraph. Its build is verified
// by cross-compilation; its runtime behavior is validated on Linux CI, because
// the seccomp notify path cannot run on the developer's macOS host.
package seccomp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// childEnv signals to a re-exec'd copy of this binary that it is the stage-2
// child: it should install the filter, hand the notify fd back, and exec the
// real target.
const childEnv = "JAILGRAPH_TRACED_CHILD"

// Config configures the supervisor.
type Config struct {
	// EventBuffer sizes the channel returned by Start (default 1024).
	EventBuffer int
}

type supervisor struct {
	target string
	args   []string
	cfg    Config
	tables tables

	cmd      *exec.Cmd
	notifyFD int

	out       chan collector.BehaviorEvent
	errs      chan error
	once      sync.Once
	waitErr   error
	childDone chan struct{} // closed when the traced child has been reaped

	// lossy/dropped account for out-channel overflow — the capture-side drop
	// point. The downstream ring accounts for its own drops separately.
	lossy   atomic.Bool
	dropped atomic.Int64
}

// NewSupervisor returns a Collector that traces target with the given args.
func NewSupervisor(target string, args []string, cfg Config) (collector.Collector, error) {
	if cfg.EventBuffer <= 0 {
		cfg.EventBuffer = 1024
	}
	return &supervisor{target: target, args: args, cfg: cfg, tables: buildTables()}, nil
}

// MaybeRunChild must be called at the very top of main. If this process is the
// stage-2 traced child it installs the seccomp filter, sends the notify fd back
// to the supervisor, execs the real target, and never returns on success.
// Otherwise it returns (false, nil) and normal startup proceeds.
func MaybeRunChild() (bool, error) {
	if os.Getenv(childEnv) == "" {
		return false, nil
	}
	if len(os.Args) < 2 {
		return true, fmt.Errorf("traced child: missing target argument")
	}
	return true, runChild(os.Args[1], os.Args[2:])
}

func (s *supervisor) Start(ctx context.Context) (<-chan collector.BehaviorEvent, error) {
	// Socketpair: the child sends the notify fd back over sp[1]; we read sp[0].
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}
	parentSock := os.NewFile(uintptr(sp[0]), "notify-parent")
	childSock := os.NewFile(uintptr(sp[1]), "notify-child")
	defer childSock.Close()

	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate self: %w", err)
	}

	// Re-exec ourselves as the stage-2 child. The child sees the socket as fd 3.
	cmd := exec.CommandContext(ctx, self, append([]string{s.target}, s.args...)...)
	cmd.Env = append(os.Environ(), childEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{childSock}
	if err := cmd.Start(); err != nil {
		parentSock.Close()
		return nil, fmt.Errorf("start traced child: %w", err)
	}
	s.cmd = cmd

	// Receive the notify fd the child installed.
	fd, err := recvFD(parentSock)
	parentSock.Close()
	if err != nil {
		return nil, fmt.Errorf("receive notify fd: %w", err)
	}
	s.notifyFD = fd

	s.out = make(chan collector.BehaviorEvent, s.cfg.EventBuffer)
	s.errs = make(chan error, s.cfg.EventBuffer)
	s.childDone = make(chan struct{})
	// Reap the child exactly once, in the background, so recvLoop can detect
	// target exit (the notify fd's POLLHUP is the primary signal; this is the
	// belt-and-suspenders so we never block forever if that signal is missed).
	go func() {
		s.once.Do(func() { s.waitErr = s.cmd.Wait() })
		close(s.childDone)
	}()
	go s.recvLoop(ctx)
	return s.out, nil
}

func (s *supervisor) childExited() bool {
	select {
	case <-s.childDone:
		return true
	default:
		return false
	}
}

// pollTimeoutMs bounds how long recvLoop waits in a single poll before
// re-checking liveness (ctx cancellation, child exit).
const pollTimeoutMs = 200

// recvLoop services notifications until the target exits or ctx is cancelled,
// answering every one with CONTINUE. It POLLs the notify fd rather than calling
// the blocking RECV ioctl directly: NOTIF_RECV never returns on its own when the
// target is gone, so a bare RECV loop would hang forever after the last syscall.
// The kernel raises POLLHUP on the notify fd once the filter has no live tasks;
// that, plus the reaped-child check, are the termination signals.
func (s *supervisor) recvLoop(ctx context.Context) {
	defer close(s.out)
	defer close(s.errs)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pfd := []unix.PollFd{{Fd: int32(s.notifyFD), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, pollTimeoutMs)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			s.emitErr(fmt.Errorf("poll notify fd: %w", err))
			return
		}
		// Target gone (filter detached) or fd closed by Close(): stop.
		if pfd[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return
		}
		if n == 0 {
			// Timed out with no notification. If the child has already been
			// reaped, no more events can arrive, so finish.
			if s.childExited() {
				return
			}
			continue
		}
		if pfd[0].Revents&unix.POLLIN == 0 {
			continue
		}

		req, err := notifRecv(s.notifyFD)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			// ENOENT means this specific notification was cancelled (target
			// thread died mid-call); keep servicing the rest.
			if err != unix.ENOENT {
				s.emitErr(fmt.Errorf("notif recv: %w", err))
				return
			}
			continue
		}
		s.handle(req)
		// Always let the real syscall proceed: observe, never block.
		resp := seccompNotifResp{id: req.id, flags: uint32(unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE)}
		if err := notifSend(s.notifyFD, resp); err != nil && err != unix.ENOENT {
			s.emitErr(fmt.Errorf("notif send: %w", err))
		}
	}
}

func (s *supervisor) handle(req seccompNotif) {
	ev, ok, err := s.decode(req)
	if err != nil {
		s.emitErr(err)
		return
	}
	if !ok {
		return // discarded (failed TOCTOU revalidation)
	}
	// Propagate any prior out-channel drop so downstream marks the run lossy —
	// this drop point would otherwise be unaccounted.
	ev.Lossy = s.lossy.Load()
	select {
	case s.out <- ev:
	default:
		// out is full and we must not block the notify path. Drop, count it,
		// and flag subsequent events lossy so the Run node reflects it.
		s.lossy.Store(true)
		s.dropped.Add(1)
	}
}

func (s *supervisor) emitErr(err error) {
	select {
	case s.errs <- err:
	default:
	}
}

func (s *supervisor) Errors() <-chan error { return s.errs }

func (s *supervisor) Wait() error {
	// The reaper goroutine (started in Start) owns the single cmd.Wait via
	// s.once; block until it has finished, then report its result.
	if s.childDone != nil {
		<-s.childDone
	}
	return s.waitErr
}

func (s *supervisor) Close() error {
	if s.notifyFD != 0 {
		unix.Close(s.notifyFD)
		s.notifyFD = 0
	}
	return nil
}

// runChild is the stage-2 entrypoint: install no_new_privs + the filter, send
// the notify fd to the parent, then exec the target.
func runChild(target string, args []string) error {
	// Pin this goroutine to its OS thread BEFORE installing the filter. We
	// install without SECCOMP_FILTER_FLAG_TSYNC, so the filter attaches to the
	// calling thread only; if the Go scheduler moved us to a different thread
	// before execve, the execve would run unfiltered and we'd observe nothing.
	// We never unlock — execve replaces the whole process image.
	runtime.LockOSThread()

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	prog := buildFilter(buildTables().nrs)
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}

	r, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER),
		uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return fmt.Errorf("install seccomp filter: %w", errno)
	}
	notifyFD := int(r)

	// fd 3 is the socket the supervisor passed via ExtraFiles.
	if err := sendFD(3, notifyFD); err != nil {
		return fmt.Errorf("send notify fd: %w", err)
	}

	// Resolve the target on PATH and exec it. This execve is itself flagged and
	// traps once; the supervisor answers CONTINUE so it proceeds.
	path, err := exec.LookPath(target)
	if err != nil {
		return fmt.Errorf("resolve target %q: %w", target, err)
	}
	if err := unix.Exec(path, append([]string{target}, args...), os.Environ()); err != nil {
		return fmt.Errorf("exec target: %w", err)
	}
	return nil // unreachable on success
}

// sendFD passes fd over the unix socket at socketFD via SCM_RIGHTS.
func sendFD(socketFD, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(socketFD, []byte{0}, rights, nil, 0)
}

// recvFD receives a single fd sent via SCM_RIGHTS.
func recvFD(sock *os.File) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, 0)
	if err != nil {
		return 0, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, err
	}
	if len(msgs) == 0 {
		return 0, fmt.Errorf("no control message received")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil {
		return 0, err
	}
	if len(fds) == 0 {
		return 0, fmt.Errorf("no fd in control message")
	}
	return fds[0], nil
}
