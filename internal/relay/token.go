package relay

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beamfall/relay/internal/protocol"
)

var ErrUnauthorized = errors.New("unauthorized tunnel token")

const (
	// MinTokenBytes is the minimum accepted carrier-token length. A real random
	// token (e.g. `openssl rand -base64 48`) clears this comfortably; it rejects
	// short hand-typed secrets that are brute-forceable over the carrier port.
	MinTokenBytes = 32
	// minTokenDistinctBytes is a cheap, dependency-free entropy proxy: the number
	// of distinct byte values the token must contain. It rejects long-but-trivial
	// tokens (e.g. a run of one repeated character) that clear the length floor
	// while carrying almost no entropy.
	minTokenDistinctBytes = 16
)

// ValidateTokenStrength enforces a minimum-entropy floor on a carrier token at
// load time. It returns a clear, actionable error on a weak token and NEVER
// includes the token bytes in the message (the relay must not log token bytes).
// relayd calls this at startup and fails fast so a weak shared secret can never
// reach the carrier-auth path.
func ValidateTokenStrength(token []byte) error {
	if len(token) < MinTokenBytes {
		return fmt.Errorf("carrier token too short: %d bytes, need at least %d (generate with `openssl rand -base64 48`)", len(token), MinTokenBytes)
	}
	var seen [256]bool
	distinct := 0
	for _, b := range token {
		if !seen[b] {
			seen[b] = true
			distinct++
		}
	}
	if distinct < minTokenDistinctBytes {
		return fmt.Errorf("carrier token too low-entropy: %d distinct byte values, need at least %d (use a random token, not a passphrase)", distinct, minTokenDistinctBytes)
	}
	return nil
}

type TokenVerifier interface {
	VerifyTunnelToken(ctx context.Context, token []byte, requestedHostnames []string) (VerifiedCarrier, error)
}

type SurfaceTokenVerifier interface {
	VerifyCarrierToken(ctx context.Context, token []byte, requestedHostnames []string, surface string) (VerifiedCarrier, error)
}

type CacheCarrierTokenVerifier interface {
	VerifyCacheCarrierToken(ctx context.Context, token []byte, requestedHostnames []string, cacheVerificationKey []byte) (VerifiedCarrier, error)
}

type VerifiedCarrier struct {
	ID                   string
	Hostnames            []string
	TraceCorrelationID   string
	Surface              string
	CacheVerificationKey []byte
	// ExpiresAt is the token's own expiry claim (ADR-0018 §5: hosted-relay tunnel
	// tokens carry a short-TTL expires-at). When non-zero, the relay tears down the
	// still-open carrier session at this deadline rather than only refusing the next
	// dial (RELAY-REVOKE-1). A zero value means "no token-driven expiry" — the
	// StaticTokenVerifier (tests/self-hosted demos) leaves it zero, preserving the
	// long-lived-session behavior for shared-secret carriers. This is the token's
	// self-contained signed claim, not a fetched revocation list or a playback-time
	// phone-home (distinct from ADR-0024/0031 Entitlement Tokens).
	ExpiresAt time.Time
}

// StaticTokenVerifier is for tests and self-hosted demos only. Production hosted relay
// deployments should replace it with a verifier backed by the reserved token mint.
type StaticTokenVerifier struct {
	Token     []byte
	CarrierID string
	Hostnames []string
	Surface   string
}

func (v StaticTokenVerifier) VerifyTunnelToken(ctx context.Context, token []byte, requestedHostnames []string) (VerifiedCarrier, error) {
	return v.VerifyCarrierToken(ctx, token, requestedHostnames, protocol.SurfacePassthrough)
}

func (v StaticTokenVerifier) VerifyCarrierToken(ctx context.Context, token []byte, requestedHostnames []string, surface string) (VerifiedCarrier, error) {
	select {
	case <-ctx.Done():
		return VerifiedCarrier{}, ctx.Err()
	default:
	}
	wantSurface := v.Surface
	if wantSurface == "" {
		wantSurface = protocol.SurfacePassthrough
	}
	if surface != wantSurface {
		return VerifiedCarrier{}, ErrUnauthorized
	}
	if len(v.Token) == 0 || subtle.ConstantTimeCompare(token, v.Token) != 1 {
		return VerifiedCarrier{}, ErrUnauthorized
	}
	hostnames, err := allowedHostnames(v.Hostnames, requestedHostnames)
	if err != nil {
		return VerifiedCarrier{}, err
	}
	id := v.CarrierID
	if id == "" {
		id = hostnames[0]
	}
	return VerifiedCarrier{ID: id, Hostnames: hostnames, Surface: surface}, nil
}

func (v StaticTokenVerifier) VerifyCacheCarrierToken(ctx context.Context, token []byte, requestedHostnames []string, cacheVerificationKey []byte) (VerifiedCarrier, error) {
	verified, err := v.VerifyCarrierToken(ctx, token, requestedHostnames, protocol.SurfaceCache)
	if err != nil {
		return VerifiedCarrier{}, err
	}
	verified.CacheVerificationKey = append([]byte(nil), cacheVerificationKey...)
	return verified, nil
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
