package relay

import (
	"fmt"
	"time"
)

// ADR-0103 (relay metadata privacy) Decision 2: any transient operational log
// the Hosted Relay keeps must have a *defined maximum* retention window — target
// "days, not months" — that is fixed when the Hosted Relay is built (ADR-0025
// timing), bounded, and published. The ADR defers the actual purge mechanism to
// the deployment (journald / logrotate); this layer's obligation is that the
// bound exists, is fixed at build time, and is published (see metrics.go, which
// exports it on /metrics).
const (
	// MaxOperationalLogRetention is the ADR-0103 policy ceiling: no operational
	// log retention window may exceed it. "Days, not months."
	MaxOperationalLogRetention = 7 * 24 * time.Hour

	// OperationalLogRetentionWindow is the published build-time retention window
	// the Hosted Relay deployment must honor. It must satisfy
	// ValidateRetentionWindow; init() enforces that at process start so a bad
	// constant fails fast (mirroring ValidateTokenStrength in token.go).
	OperationalLogRetentionWindow = 24 * time.Hour
)

// ValidateRetentionWindow rejects a retention window that ADR-0103 forbids: a
// non-positive window (unbounded / "never delete", which recreates the viewing
// fingerprint the relay exists to avoid) or one exceeding MaxOperationalLogRetention.
// Exported so a future Hosted Relay build that makes the window operator-set
// inherits the same fail-fast enforcement.
func ValidateRetentionWindow(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("operational log retention window must be positive and bounded (ADR-0103: no unbounded retention), got %s", d)
	}
	if d > MaxOperationalLogRetention {
		return fmt.Errorf("operational log retention window %s exceeds ADR-0103 ceiling %s", d, MaxOperationalLogRetention)
	}
	return nil
}

// Fail fast at process start if the build-time retention constant violates the
// ADR-0103 bound — the test suite is the primary gate, but this makes a bad
// constant crash the binary at deploy rather than ship silently.
func init() {
	if err := ValidateRetentionWindow(OperationalLogRetentionWindow); err != nil {
		panic(fmt.Sprintf("invalid build-time retention policy: %v", err))
	}
}
