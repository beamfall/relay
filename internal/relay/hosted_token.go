package relay

import (
	"container/heap"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/beamfall/relay/relaytoken"
)

const hostedRelayTokenType = relaytoken.TokenType

const (
	// MaxIssuedAtSkew is the 60-second issued-at skew: how far a carrier
	// token's issued_at (hosted or HMAC v2) may sit ahead of the relay clock and
	// still verify, so a relay clock that lags the mint's by a few seconds does
	// not reject every freshly minted token. The leeway applies to issued_at
	// only; expires_at gets none.
	MaxIssuedAtSkew = 60 * time.Second

	// MaxHostedTokenTTL is the longest signed lifetime (expires_at - issued_at) a
	// hosted token may carry. Every admitted nonce is held until its token
	// expires, so the ceiling bounds how long one token occupies the durable
	// nonce store (capped at the store's configured capacity).
	MaxHostedTokenTTL = 24 * time.Hour
)

// Replay nonce store sizing. Every admitted nonce occupies one store entry
// until its token expires, so live entries are bounded by token lifetime x
// distinct-token mint rate. A store that reaches its capacity refuses every new
// admission with ErrNonceStoreFull (fail closed, RV-RELAY-007) until entries
// expire, so the default is sized for the longest lifetime any carrier token
// may carry (MaxHostedTokenTTL) at NonceStoreSizingPeakMintRate, plus headroom.
const (
	// NonceStoreSizingPeakMintRate is the sustained peak rate, in distinct
	// valid carrier tokens per second summed across every relay instance
	// sharing one store, that DefaultNonceStoreCapacity is sized for.
	NonceStoreSizingPeakMintRate = 2

	// nonceStoreSizingHeadroomPercent scales the peak-rate estimate so the
	// default saturates only at 1.5x the stated peak held for a full
	// MaxHostedTokenTTL.
	nonceStoreSizingHeadroomPercent = 150

	// DefaultNonceStoreCapacity is the default live-nonce capacity of a replay
	// nonce store: 86,400 s x 2 tokens/s x 150% = 259,200 entries. relayd
	// exposes it as --hmac-nonce-store-capacity.
	DefaultNonceStoreCapacity = int(MaxHostedTokenTTL/time.Second) * NonceStoreSizingPeakMintRate * nonceStoreSizingHeadroomPercent / 100

	// MaxNonceStoreCapacity is the largest capacity a FileHMACNonceStore
	// accepts. It also bounds how many entries a persisted state file may hold
	// before it is rejected as corrupt.
	MaxNonceStoreCapacity = 1_000_000
)

type HostedTokenVerifier struct {
	Issuer     string
	Audience   string
	Purpose    string
	PublicKeys map[string]ed25519.PublicKey
	Now        func() time.Time

	// NonceStore is the durable, shared replay authority. Verification fails
	// closed when it is absent, unavailable, replayed, or at capacity.
	NonceStore HMACNonceStore

	// NonceCacheCap bounds the process-local metadata mirror used only for
	// aggregate pressure metrics. Evicting mirror entries cannot weaken replay
	// protection because NonceStore remains authoritative. <=0 uses
	// DefaultNonceStoreCapacity.
	NonceCacheCap int

	// Logger receives the server-local diagnostic naming which validateClaims
	// guard rejected a token. nil discards it.
	Logger *slog.Logger

	mu       sync.Mutex
	nonces   map[string]time.Time
	expiries nonceExpiryHeap // min-heap of nonces keyed by expiry, for O(log n) eviction
}

func (v *HostedTokenVerifier) Validate() error {
	if v == nil {
		return errors.New("hosted token verifier is required")
	}
	if strings.TrimSpace(v.Issuer) == "" {
		return errors.New("hosted token verifier issuer is required")
	}
	if strings.TrimSpace(v.Audience) == "" {
		return errors.New("hosted token verifier audience is required")
	}
	if v.NonceStore == nil {
		return errors.New("hosted token verifier nonce store is required")
	}
	return nil
}

// hostedRelayClaims is Relay's in-tree hosted-relay token claim set. Its
// provenance and canonical-parity tests pin it to the Cloud-owned schema
// (ORG-14 / UF-3). It is a type alias, so the wire format (JSON tags, canonical
// encoding) is identical to the former inline struct — a dependency-locality
// change, not a schema change.
type hostedRelayClaims = relaytoken.Claims

func (v *HostedTokenVerifier) VerifyTunnelToken(ctx context.Context, token []byte, requestedHostnames []string) (VerifiedCarrier, error) {
	select {
	case <-ctx.Done():
		return VerifiedCarrier{}, ctx.Err()
	default:
	}
	claims, err := v.verify(token)
	if err != nil {
		return VerifiedCarrier{}, err
	}
	hostnames, err := allowedHostnames(claims.Hostnames, requestedHostnames)
	if err != nil {
		return VerifiedCarrier{}, err
	}
	if err := v.admitNonce(ctx, claims); err != nil {
		return VerifiedCarrier{}, err
	}
	// Carry the token's expiry so serveCarrierSession can tear the session down
	// when the token expires, not just refuse the next dial (RELAY-REVOKE-1). The
	// claim is already validated as within its window by validateClaimTiming.
	return VerifiedCarrier{ID: claims.ServerID, Hostnames: hostnames, TraceCorrelationID: claims.TraceCorrelationID, ExpiresAt: claims.ExpiresAt}, nil
}

func (v *HostedTokenVerifier) verify(raw []byte) (hostedRelayClaims, error) {
	// Structure, EdDSA signature, canonical-JSON re-encode, token type, and the
	// header.KeyID == claims.KeyID integrity check are all owned by the
	// single-owner relaytoken module (ORG-14). relaytoken.ErrUnauthorized is
	// mapped to this package's ErrUnauthorized so the transport contract is
	// unchanged. Policy (issuer/audience/purpose/expiry/nonce) stays here.
	claims, err := relaytoken.Verify(raw, v.PublicKeys)
	if err != nil {
		return hostedRelayClaims{}, ErrUnauthorized
	}
	if err := v.validateClaims(claims); err != nil {
		return hostedRelayClaims{}, err
	}
	return claims, nil
}

// validateClaims enforces policy (as opposed to structural/signature
// verification, owned by relaytoken.Verify) on an already-authenticated
// claim set. Each condition is checked by its own named guard so a failure
// can be attributed to a specific field when auditing or extending this
// function; every guard returns ErrUnauthorized (the lifetime ceiling wraps it
// with a reason), and the handshake answers all of them with the same opaque
// "unauthorized" frame, so the external error contract is unchanged.
//
// A rejection also writes the rejecting guard's name to v.Logger. That record
// is server-local only: it never reaches the wire frame, the returned error, or
// a metric label, and it carries no claim value, so operators can tell a clock
// or lifetime rejection apart from any other claim failure without widening
// the external contract.
func (v *HostedTokenVerifier) validateClaims(claims hostedRelayClaims) error {
	guard, err := v.rejectingClaimGuard(claims)
	if err != nil {
		v.logClaimRejection(guard)
	}
	return err
}

// Guard names recorded by the validateClaims rejection diagnostic.
const (
	claimGuardPresence     = "presence"
	claimGuardAudience     = "audience"
	claimGuardPurpose      = "purpose"
	claimGuardIssuedAtSkew = "issued_at_skew"
	claimGuardExpiryOrder  = "expiry_order"
	claimGuardTTLCeiling   = "ttl_ceiling"
	claimGuardExpired      = "expired"
)

// rejectingClaimGuard runs the validateClaims guards in order and returns the
// name of the first one that rejects claims, with its error.
func (v *HostedTokenVerifier) rejectingClaimGuard(claims hostedRelayClaims) (string, error) {
	if err := v.validateClaimPresence(claims); err != nil {
		return claimGuardPresence, err
	}
	if err := v.validateClaimAudience(claims); err != nil {
		return claimGuardAudience, err
	}
	if err := v.validateClaimPurpose(claims); err != nil {
		return claimGuardPurpose, err
	}
	return v.rejectingTimingGuard(claims)
}

// logClaimRejection writes the server-local rejection diagnostic.
func (v *HostedTokenVerifier) logClaimRejection(guard string) {
	if v.Logger == nil {
		return
	}
	v.Logger.Warn("hosted token claims rejected", "guard", guard)
}

// validateClaimPresence checks that every required claim field is set.
func (v *HostedTokenVerifier) validateClaimPresence(claims hostedRelayClaims) error {
	if claims.Type != hostedRelayTokenType {
		return ErrUnauthorized
	}
	if claims.KeyID == "" {
		return ErrUnauthorized
	}
	if claims.ServerID == "" {
		return ErrUnauthorized
	}
	if len(claims.Hostnames) == 0 {
		return ErrUnauthorized
	}
	if claims.Purpose == "" {
		return ErrUnauthorized
	}
	if claims.IssuedAt.IsZero() {
		return ErrUnauthorized
	}
	if claims.ExpiresAt.IsZero() {
		return ErrUnauthorized
	}
	if claims.Nonce == "" {
		return ErrUnauthorized
	}
	if claims.TraceCorrelationID != "" && !validRelayTraceCorrelationID(claims.TraceCorrelationID) {
		return ErrUnauthorized
	}
	return nil
}

func validRelayTraceCorrelationID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

// validateClaimAudience checks the token was minted for this issuer/audience pair.
func (v *HostedTokenVerifier) validateClaimAudience(claims hostedRelayClaims) error {
	if err := v.Validate(); err != nil {
		return ErrUnauthorized
	}
	if claims.Issuer != v.Issuer {
		return ErrUnauthorized
	}
	if claims.Audience != v.Audience {
		return ErrUnauthorized
	}
	return nil
}

// validateClaimPurpose checks the token was minted for the expected purpose.
func (v *HostedTokenVerifier) validateClaimPurpose(claims hostedRelayClaims) error {
	purpose := v.Purpose
	if purpose == "" {
		purpose = "tunnel-connect"
	}
	if claims.Purpose != purpose {
		return ErrUnauthorized
	}
	return nil
}

// validateClaimTiming checks the token is within its issued/expiry window,
// allowing issued_at up to MaxIssuedAtSkew ahead of the relay clock, and that
// its signed lifetime is at most MaxHostedTokenTTL.
func (v *HostedTokenVerifier) validateClaimTiming(claims hostedRelayClaims) error {
	_, err := v.rejectingTimingGuard(claims)
	return err
}

// rejectingTimingGuard runs the timing checks against one relay-clock sample
// and returns the name of the first one that rejects claims, with its error.
func (v *HostedTokenVerifier) rejectingTimingGuard(claims hostedRelayClaims) (string, error) {
	now := v.now()
	if now.Add(MaxIssuedAtSkew).Before(claims.IssuedAt) {
		return claimGuardIssuedAtSkew, ErrUnauthorized
	}
	if !claims.ExpiresAt.After(claims.IssuedAt) {
		return claimGuardExpiryOrder, ErrUnauthorized
	}
	if claims.ExpiresAt.Sub(claims.IssuedAt) > MaxHostedTokenTTL {
		return claimGuardTTLCeiling, fmt.Errorf("%w: token ttl exceeds %s", ErrUnauthorized, MaxHostedTokenTTL)
	}
	if !now.Before(claims.ExpiresAt) {
		return claimGuardExpired, ErrUnauthorized
	}
	return "", nil
}

// acceptNonce updates the bounded process-local telemetry mirror after the
// durable replay authority has admitted a nonce. It is not an authorization
// decision; admitNonce is the only verification path.
func (v *HostedTokenVerifier) acceptNonce(claims hostedRelayClaims) error {
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.nonces == nil {
		v.nonces = map[string]time.Time{}
	}
	for v.expiries.Len() > 0 && !now.Before(v.expiries[0].expires) {
		v.popExpiry()
	}
	key := strings.Join([]string{claims.Issuer, claims.Audience, claims.KeyID, claims.ServerID, claims.Nonce}, "\x00")
	maxNonces := v.NonceCacheCap
	if maxNonces <= 0 {
		maxNonces = DefaultNonceStoreCapacity
	}
	// This is a telemetry mirror only. Its bounded eviction never removes the
	// durable nonce from NonceStore and therefore cannot reopen a replay window.
	for len(v.nonces) >= maxNonces {
		v.popExpiry()
	}
	v.nonces[key] = claims.ExpiresAt
	heap.Push(&v.expiries, nonceExpiry{key: key, expires: claims.ExpiresAt})
	return nil
}

func (v *HostedTokenVerifier) admitNonce(ctx context.Context, claims hostedRelayClaims) error {
	if v.NonceStore == nil {
		return errors.New("hosted token replay authority is unavailable")
	}
	now := v.now()
	admitted, err := v.NonceStore.Admit(ctx, hostedNonceStoreKey(claims), claims.ExpiresAt, now)
	if err != nil {
		return fmt.Errorf("admit hosted token nonce: %w", err)
	}
	if !admitted {
		return ErrUnauthorized
	}
	return v.acceptNonce(claims)
}

func hostedNonceStoreKey(claims hostedRelayClaims) string {
	raw := strings.Join([]string{claims.Issuer, claims.Audience, claims.KeyID, claims.ServerID, claims.Nonce}, "\x00")
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:hmacNonceBytes])
}

// popExpiry removes the single nonce with the earliest expiry from both the
// map and the heap. A heap entry is stale if its key was already removed
// from the map by an earlier popExpiry call (e.g. the expiry-sweep loop
// above can drain several entries in one call); those are skipped lazily
// rather than eagerly invalidated. The caller holds v.mu.
func (v *HostedTokenVerifier) popExpiry() {
	for v.expiries.Len() > 0 {
		next := heap.Pop(&v.expiries).(nonceExpiry)
		if exp, ok := v.nonces[next.key]; ok && exp.Equal(next.expires) {
			delete(v.nonces, next.key)
			return
		}
		// Stale heap entry (already evicted by a prior popExpiry) — keep popping.
	}
}

func (v *HostedTokenVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// nonceCacheSnapshot is a label-free aggregate view of the nonce cache's
// current pressure (MEMHID-RELAY-NONCE-GAUGE): how many entries it holds and
// the effective capacity it is bounded to. It never carries a nonce value or
// any claim field, so it is safe to publish on the metrics registry.
type nonceCacheSnapshot struct {
	Entries int
	Cap     int
}

// nonceCacheSnapshot reports the current nonce-cache size and effective
// capacity, satisfying nonceCacheSnapshotter (metrics.go). It first sweeps
// already-expired entries the same way acceptNonce does, so a snapshot taken
// between verifications (e.g. a Prometheus scrape with no recent traffic)
// still reflects live pressure rather than stale, unswept entries.
func (v *HostedTokenVerifier) nonceCacheSnapshot() nonceCacheSnapshot {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	for v.expiries.Len() > 0 && !now.Before(v.expiries[0].expires) {
		v.popExpiry()
	}
	maxNonces := v.NonceCacheCap
	if maxNonces <= 0 {
		maxNonces = DefaultNonceStoreCapacity
	}
	return nonceCacheSnapshot{Entries: len(v.nonces), Cap: maxNonces}
}

// nonceStoreFill reports the fill of the durable NonceStore, satisfying
// nonceStoreFillReporter (metrics.go). ok is false when the configured store
// does not report its fill.
func (v *HostedTokenVerifier) nonceStoreFill() (nonceStoreFill, bool) {
	return replayStoreFill(v.NonceStore, v.now())
}

// nonceExpiry is one entry in the nonceExpiryHeap: a nonce cache key and the
// expiry it was inserted with.
type nonceExpiry struct {
	key     string
	expires time.Time
}

// nonceExpiryHeap is a container/heap min-heap ordered by expires, giving
// O(log n) soonest-to-expire eviction instead of an O(n) map scan. Every push
// has exactly one corresponding map entry (acceptNonce rejects duplicate keys
// before pushing), but a single popExpiry call can drain more than one heap
// entry for the same already-deleted map key when a cap-eviction pop lands on
// an entry the expiry sweep already removed; popExpiry skips those lazily.
type nonceExpiryHeap []nonceExpiry

func (h nonceExpiryHeap) Len() int           { return len(h) }
func (h nonceExpiryHeap) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h nonceExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *nonceExpiryHeap) Push(x any)        { *h = append(*h, x.(nonceExpiry)) }
func (h *nonceExpiryHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}
