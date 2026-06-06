//go:build !darwin

// On non-macOS platforms the eslogger backend is unavailable; the stub keeps the
// rest of jailgraph building and testing (the pure decoder/tracker in decode.go
// and tracker.go have no build tag and are tested everywhere).
package esf

import (
	"errors"

	"github.com/dd0wney/jailgraph/internal/collector"
)

// ErrUnsupportedPlatform is returned by NewCollector off macOS.
var ErrUnsupportedPlatform = errors.New("esf collector requires macOS")

// Config configures the esf collector (defined on all platforms so callers
// compile everywhere).
type Config struct {
	EventBuffer int
}

// NewCollector reports that eslogger tracing is unavailable on this OS.
func NewCollector(_ string, _ []string, _ Config) (collector.Collector, error) {
	return nil, ErrUnsupportedPlatform
}
