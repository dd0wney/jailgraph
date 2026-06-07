package anomaly

import "github.com/dd0wney/jailgraph/internal/profile"

// Scorer scores a candidate run's behaviour against a learned Baseline and emits
// findings. It is the pluggable seam between the population model and the scoring
// strategy.
//
// v1 ships FrequencyScorer (statistical: novel/rare per-item support — see
// scorer_freq.go). A future EmbeddingScorer (JEPA-style: embed the Behavior,
// score its distance from a population embedding) plugs in behind this exact
// interface with no change to Collect or the CLI — earning its way in once there
// is enough run data to train, and reported alongside the statistical verdict
// rather than replacing it (mirroring how audit treats its low-confidence
// dimension).
type Scorer interface {
	Score(base Baseline, candidate profile.Behavior) []Finding
}
