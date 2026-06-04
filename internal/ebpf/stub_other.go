//go:build !linux

// On non-Linux platforms the eBPF backend is unavailable; the stub keeps the
// rest of jailgraph building and testing on macOS etc.
package ebpf

import (
	"errors"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// ErrUnsupportedPlatform is returned by NewCollector off Linux.
var ErrUnsupportedPlatform = errors.New("eBPF collector requires Linux")

// Config configures the eBPF collector (defined on all platforms so callers
// compile everywhere).
type Config struct {
	EventBuffer  int
	PollInterval int64
}

// NewCollector reports that eBPF tracing is unavailable on this OS.
func NewCollector(_ string, _ []string, _ Config) (collector.Collector, error) {
	return nil, ErrUnsupportedPlatform
}
