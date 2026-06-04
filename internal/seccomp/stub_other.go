//go:build !linux

// On non-Linux platforms the seccomp backend is unavailable. The stub lets the
// rest of jailgraph build and its cross-platform tests run (via the
// FakeCollector / replay path) on macOS and elsewhere, while making the
// limitation explicit at runtime rather than failing to compile.
package seccomp

import (
	"errors"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// ErrUnsupportedPlatform is returned by NewSupervisor off Linux.
var ErrUnsupportedPlatform = errors.New("seccomp collector requires Linux")

// NewSupervisor reports that live seccomp tracing is unavailable on this OS.
func NewSupervisor(_ string, _ []string, _ Config) (collector.Collector, error) {
	return nil, ErrUnsupportedPlatform
}

// MaybeRunChild is a no-op off Linux: there is no traced-child stage to enter.
func MaybeRunChild() (bool, error) { return false, nil }

// Config configures the seccomp supervisor. Defined here too so callers compile
// on every platform.
type Config struct {
	// Errno, when non-zero, is unused in observe-only mode (reserved for the
	// future enforcer).
	_ struct{}
}
