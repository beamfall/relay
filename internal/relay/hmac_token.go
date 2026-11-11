package relay

import (
	"container/heap"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beamfall/relay/internal/protocol"
)

// HMAC tunnel-token format versions.
//
// v1 (legacy): a bare hex HMAC over the sorted, normalized hostname set. It carries
// no expiry and no nonce, so a captured token is replayable forever. Accepted for one
// release for in-place upgrades; operators should rotate to v2 (see the operator doc's
// "Token Rotation" section) and a future release drops v1 acceptance.
//
// v2: a self-contained signed claim of the shape
//
//	v2.<issuedAtUnix>.<expiresAtUnix>.<nonceHex>.<macHex>
//
// where the MAC covers the version tag, the sorted hostname set, issued-at, expires-at,
// and the nonce. The verifier rejects a token past its expiry and rejects a nonce it has
// already admitted within its validity window (replay). This is the token's own signed
// claim — there is no fetched revocation list and no verify-time network call (distinct
// from ADR-0024/0031 Entitlement Tokens; mirrors the ADR-0018 §5 hosted-relay token shape
// of issued-at + expires-at + replay-resistant nonce).
const (
	hmacTokenV2Prefix = "v2"
	hmacTokenV2Parts  = 5 // prefix, issuedAt, expiresAt, nonce, mac
	hmacNonceBytes    = 16

	// MaxHMACTokenTTL is the longest signed lifetime a v2 token may carry. A
	// five-minute ceiling keeps captured-token and replay exposure short even
	// when a mint is misconfigured or deliberately requests a longer lifetime.
	MaxHMACTokenTTL = 5 * time.Minute
)

// HMACNonceStore atomically records accepted v2 nonces until their token expiry.
// Implementations must return admitted=false when nonce was already recorded and
// must be safe for concurrent use. Production deployments must provide a
// shared/persistent implementation such as FileHMACNonceStore.
//
// now is supplied by the verifier so deterministic clocks and expiry sweeping use
// the same time source as token validation.
type HMACNonceStore interface {
	Admit(ctx context.Context, nonce string, expiresAt, now time.Time) (admitted bool, err error)
}

// ErrNonceStoreFull reports that a replay nonce store refused an admission
// because it already holds its configured capacity of live nonces. It is a
// capacity refusal, not a verdict on the presented token, so it deliberately
// does not wrap ErrUnauthorized; verification still fails closed.
var ErrNonceStoreFull = errors.New("nonce store is full")

// nonceStoreFillSource is implemented by nonce stores that can report how many
// live nonces they hold against their capacity.
type nonceStoreFillSource interface {
	fill(now time.Time) nonceStoreFill
}

// replayStoreFill reports store's fill when it implements nonceStoreFillSource.
func replayStoreFill(store HMACNonceStore, now time.Time) (nonceStoreFill, bool) {
	source, ok := store.(nonceStoreFillSource)
	if !ok {
		return nonceStoreFill{}, false
	}
	return source.fill(now), true
}

// HMACTokenVerifier is a deterministic self-hosted verifier. It is not the hosted relay
// token mint; production hosted authorization belongs in the reserved control plane
// (HostedTokenVerifier). It accepts the v2 expiring, replay-resistant token format and,
// while AcceptLegacyV1 is set, the legacy bare-HMAC format for one upgrade release.
//
// The v2 format's replay protection is routed through NonceStore. Verification
// fails closed when that authority is absent or unavailable.
type HMACTokenVerifier struct {
	Secret    []byte
	CarrierID string
	Hostnames []string
	Surface   string

	// Now overrides the clock for expiry checks; nil uses time.Now. Tests set it.
	Now func() time.Time

	// AcceptLegacyV1 keeps the bare-HMAC (no-expiry, no-nonce) format acceptable for
	// one release so operators can upgrade carriers without a hard cutover. Leave true
	// for the dual-accept release; a future release sets it false to require v2.
	AcceptLegacyV1 bool

	// NonceStore atomically records accepted v2 nonces. Use FileHMACNonceStore
	// on storage shared by all relay instances or another shared implementation.
	NonceStore HMACNonceStore
}

// nonceStoreFill reports the fill of NonceStore, satisfying
// nonceStoreFillReporter (metrics.go). ok is false when the configured store
// does not report its fill.
func (v *HMACTokenVerifier) nonceStoreFill() (nonceStoreFill, bool) {
	return replayStoreFill(v.NonceStore, v.now())
}

func (v *HMACTokenVerifier) Validate() error {
	if v.NonceStore == nil {
		return errors.New("hmac token verifier nonce store is required")
	}
	return nil
}

func (v *HMACTokenVerifier) VerifyTunnelToken(ctx context.Context, token []byte, requestedHostnames []string) (VerifiedCarrier, error) {
	return v.VerifyCarrierToken(ctx, token, requestedHostnames, protocol.SurfacePassthrough)
}

func (v *HMACTokenVerifier) VerifyCarrierToken(ctx context.Context, token []byte, requestedHostnames []string, surface string) (VerifiedCarrier, error) {
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
	hostnames, err := allowedHostnames(v.Hostnames, requestedHostnames)
	if err != nil {
		return VerifiedCarrier{}, err
	}
	expiresAt, err := v.verifyClaim(ctx, token, hostnames)
	if err != nil {
		return VerifiedCarrier{}, err
	}
	id := v.CarrierID
	if id == "" {
		id = hostnames[0]
	}
	return VerifiedCarrier{ID: id, Hostnames: hostnames, Surface: surface, ExpiresAt: expiresAt}, nil
}

func (v *HMACTokenVerifier) VerifyCacheCarrierToken(ctx context.Context, token []byte, requestedHostnames []string, cacheVerificationKey []byte) (VerifiedCarrier, error) {
	verified, err := v.VerifyCarrierToken(ctx, token, requestedHostnames, protocol.SurfaceCache)
	if err != nil {
		return VerifiedCarrier{}, err
	}
	verified.CacheVerificationKey = append([]byte(nil), cacheVerificationKey...)
	return verified, nil
}

// verifyClaim dispatches on token format and returns the token's expiry (zero for the
// legacy v1 format, which carries no token-driven expiry). The MAC is computed over the
// SORTED hostname set on both mint and verify, so a carrier may list hostnames in any
// order in its hello.
func (v *HMACTokenVerifier) verifyClaim(ctx context.Context, token []byte, hostnames []string) (time.Time, error) {
	sorted := sortNormalizedHosts(hostnames)
	if isHMACV2(token) {
		return v.verifyV2(ctx, token, sorted)
	}
	if !v.AcceptLegacyV1 {
		return time.Time{}, ErrUnauthorized
	}
	return time.Time{}, verifyV1(v.Secret, token, sorted)
}

func isHMACV2(token []byte) bool {
	return strings.HasPrefix(string(token), hmacTokenV2Prefix+".")
}

func verifyV1(secret, token []byte, hostnames []string) error {
	expected := mintV1(secret, hostnames)
	if !hmac.Equal(token, expected) {
		return ErrUnauthorized
	}
	return nil
}

func (v *HMACTokenVerifier) verifyV2(ctx context.Context, token []byte, hostnames []string) (time.Time, error) {
	fields := strings.Split(string(token), ".")
	if len(fields) != hmacTokenV2Parts {
		return time.Time{}, ErrUnauthorized
	}
	issuedAt, expiresAt, err := parseV2Times(fields[1], fields[2])
	if err != nil {
		return time.Time{}, err
	}
	nonce := fields[3]
	if !validHMACNonce(nonce) {
		return time.Time{}, fmt.Errorf("%w: bad nonce", ErrUnauthorized)
	}
	expectedMAC := macV2(v.Secret, hostnames, issuedAt, expiresAt, nonce)
	if !hmac.Equal([]byte(fields[4]), []byte(expectedMAC)) {
		return time.Time{}, ErrUnauthorized
	}
	now := v.now()
	if now.Add(MaxIssuedAtSkew).Before(issuedAt) {
		return time.Time{}, fmt.Errorf("%w: token not yet valid", ErrUnauthorized)
	}
	if expiresAt.Sub(issuedAt) > MaxHMACTokenTTL {
		return time.Time{}, fmt.Errorf("%w: token ttl exceeds %s", ErrUnauthorized, MaxHMACTokenTTL)
	}
	if !now.Before(expiresAt) {
		return time.Time{}, fmt.Errorf("%w: token expired", ErrUnauthorized)
	}
	if v.NonceStore == nil {
		return time.Time{}, errors.New("hmac token replay authority is unavailable")
	}
	admitted, err := v.NonceStore.Admit(ctx, nonce, expiresAt, now)
	if err != nil {
		return time.Time{}, fmt.Errorf("admit hmac token nonce: %w", err)
	}
	if !admitted {
		return time.Time{}, fmt.Errorf("%w: token replayed", ErrUnauthorized)
	}
	return expiresAt, nil
}

func validHMACNonce(nonce string) bool {
	if len(nonce) != hex.EncodedLen(hmacNonceBytes) {
		return false
	}
	var decoded [hmacNonceBytes]byte
	_, err := hex.Decode(decoded[:], []byte(nonce))
	return err == nil
}

func parseV2Times(issuedStr, expiresStr string) (issuedAt, expiresAt time.Time, err error) {
	issuedUnix, errIssued := strconv.ParseInt(issuedStr, 10, 64)
	if errIssued != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: bad issued-at", ErrUnauthorized)
	}
	expiresUnix, errExpires := strconv.ParseInt(expiresStr, 10, 64)
	if errExpires != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: bad expires-at", ErrUnauthorized)
	}
	if expiresUnix <= issuedUnix {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: expires-at not after issued-at", ErrUnauthorized)
	}
	return time.Unix(issuedUnix, 0), time.Unix(expiresUnix, 0), nil
}

func (v *HMACTokenVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// MintHMACTestToken mints a legacy v1 token (bare HMAC over the hostname set). Retained
// for existing callers and the dual-accept release. Prefer MintHMACTunnelToken.
func MintHMACTestToken(secret []byte, hostnames []string) []byte {
	return mintV1(secret, sortNormalizedHosts(hostnames))
}

// MintHMACTunnelToken mints a v2 self-contained tunnel token that expires ttl after now
// and carries a fresh random nonce, so a captured token stops verifying at expiry and a
// re-presented token is rejected as a replay. ttl must be positive.
func MintHMACTunnelToken(secret []byte, hostnames []string, ttl time.Duration) ([]byte, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("tunnel-token ttl must be positive, got %s", ttl)
	}
	hosts := sortNormalizedHosts(hostnames)
	nonce, err := newHMACNonce()
	if err != nil {
		return nil, err
	}
	issuedAt := time.Now().Truncate(time.Second)
	expiresAt := issuedAt.Add(ttl)
	mac := macV2(secret, hosts, issuedAt, expiresAt, nonce)
	token := strings.Join([]string{
		hmacTokenV2Prefix,
		strconv.FormatInt(issuedAt.Unix(), 10),
		strconv.FormatInt(expiresAt.Unix(), 10),
		nonce,
		mac,
	}, ".")
	return []byte(token), nil
}

func mintV1(secret []byte, sortedHosts []string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strings.Join(sortedHosts, "\n")))
	return []byte(hex.EncodeToString(mac.Sum(nil)))
}

// macV2 computes the v2 MAC over field-separated components. The NUL separators are
// unambiguous because no component can contain a NUL: hostnames are normalized DNS
// names, the times are decimal integers, and the nonce is hex.
func macV2(secret []byte, sortedHosts []string, issuedAt, expiresAt time.Time, nonce string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(hmacTokenV2Prefix))
	mac.Write([]byte{0})
	mac.Write([]byte(strings.Join(sortedHosts, "\n")))
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.FormatInt(issuedAt.Unix(), 10)))
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.FormatInt(expiresAt.Unix(), 10)))
	mac.Write([]byte{0})
	mac.Write([]byte(nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

func newHMACNonce() (string, error) {
	buf := make([]byte, hmacNonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("mint tunnel-token nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func sortNormalizedHosts(hostnames []string) []string {
	normalized := make([]string, 0, len(hostnames))
	for _, host := range hostnames {
		normalized = append(normalized, normalizeHost(host))
	}
	sort.Strings(normalized)
	return normalized
}

// hmacReplayGuard rejects a nonce it has already admitted, until that nonce's token has
// expired. It uses the same expiry-swept, cap-bounded, heap-backed design as
// the durable store. Under normal operation the cache is bounded by token TTL x
// connect-rate; the cap backstops memory under an abnormal burst of distinct valid
// tokens. Capacity fails closed rather than evicting a still-live nonce.
type hmacReplayGuard struct {
	mu       sync.Mutex
	nonces   map[string]time.Time
	expiries nonceExpiryHeap
}

func (g *hmacReplayGuard) Admit(ctx context.Context, nonce string, expiresAt, now time.Time) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.nonces == nil {
		g.nonces = map[string]time.Time{}
	}
	for g.expiries.Len() > 0 && !now.Before(g.expiries[0].expires) {
		g.pop()
	}
	if _, seen := g.nonces[nonce]; seen {
		return false, nil
	}
	if len(g.nonces) >= DefaultNonceStoreCapacity {
		return false, fmt.Errorf("hmac %w", ErrNonceStoreFull)
	}
	g.nonces[nonce] = expiresAt
	heap.Push(&g.expiries, nonceExpiry{key: nonce, expires: expiresAt})
	return true, nil
}

// pop removes the single nonce with the earliest expiry from both the map and the heap,
// skipping stale heap entries lazily. The caller holds g.mu. Mirrors
// HostedTokenVerifier.popExpiry.
func (g *hmacReplayGuard) pop() {
	for g.expiries.Len() > 0 {
		next := heap.Pop(&g.expiries).(nonceExpiry)
		if exp, ok := g.nonces[next.key]; ok && exp.Equal(next.expires) {
			delete(g.nonces, next.key)
			return
		}
	}
}

func allowedHostnames(allowedHosts, requestedHostnames []string) ([]string, error) {
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, host := range allowedHosts {
		allowed[normalizeHost(host)] = struct{}{}
	}
	hostnames := make([]string, 0, len(requestedHostnames))
	for _, host := range requestedHostnames {
		host = normalizeHost(host)
		if _, ok := allowed[host]; !ok {
			return nil, fmt.Errorf("%w: hostname %q not allowed", ErrUnauthorized, host)
		}
		hostnames = append(hostnames, host)
	}
	if len(hostnames) == 0 {
		return nil, fmt.Errorf("%w: no hostnames requested", ErrUnauthorized)
	}
	return hostnames, nil
}
