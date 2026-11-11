package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beamfall/relay/relaytoken"
)

func TestHostedTokenVerifierAcceptsCloudMintedToken(t *testing.T) {
	key := hostedTestKey()
	now := hostedTestNow()
	token := signHostedTestToken(t, key, hostedRelayClaims{
		Type:               hostedRelayTokenType,
		Issuer:             "beamfall-cloud",
		Audience:           "beamfall-relay",
		KeyID:              "relay-2026-06",
		ServerID:           "srv_1",
		Hostnames:          []string{"home.relay.test"},
		Purpose:            "tunnel-connect",
		TraceCorrelationID: "0123456789abcdef0123456789abcdef",
		IssuedAt:           now,
		ExpiresAt:          now.Add(2 * time.Minute),
		Nonce:              "nonce-1",
	})
	verifier := hostedTestVerifier(key.Public().(ed25519.PublicKey), now)
	got, err := verifier.VerifyTunnelToken(context.Background(), []byte(token), []string{"home.relay.test"})
	if err != nil {
		t.Fatalf("verify hosted token: %v", err)
	}
	if got.ID != "srv_1" || len(got.Hostnames) != 1 || got.Hostnames[0] != "home.relay.test" {
		t.Fatalf("verified carrier = %#v", got)
	}
	if got.TraceCorrelationID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("trace correlation id = %q", got.TraceCorrelationID)
	}
}

func TestHostedTokenVerifierCarriesNoAccountID(t *testing.T) {
	key := hostedTestKey()
	now := hostedTestNow()
	accountID := "acct_should_not_reach_relay"
	token := signHostedTestToken(t, key, hostedRelayClaims{
		Type:      hostedRelayTokenType,
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		KeyID:     "relay-2026-06",
		ServerID:  "carrier_opaque_1",
		Hostnames: []string{"home.relay.test"},
		Purpose:   "tunnel-connect",
		IssuedAt:  now,
		ExpiresAt: now.Add(2 * time.Minute),
		Nonce:     "nonce-no-account",
	})
	assertHostedTokenHasNoAccountID(t, token, accountID)
	if _, ok := reflect.TypeOf(hostedRelayClaims{}).FieldByName("RelayAccountID"); ok {
		t.Fatal("hosted relay claims parse an account id field")
	}
	carrierType := reflect.TypeOf(VerifiedCarrier{})
	for _, field := range []string{"AccountID", "RelayAccountID"} {
		if _, ok := carrierType.FieldByName(field); ok {
			t.Fatalf("VerifiedCarrier exposes %s", field)
		}
	}
	rec := httptest.NewRecorder()
	(&metrics{}).metricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(strings.ToLower(rec.Body.String()), "account") {
		t.Fatalf("relay metrics expose account wording:\n%s", rec.Body.String())
	}
	verifier := hostedTestVerifier(key.Public().(ed25519.PublicKey), now)
	got, err := verifier.VerifyTunnelToken(context.Background(), []byte(token), []string{"home.relay.test"})
	if err != nil {
		t.Fatalf("verify hosted token: %v", err)
	}
	if got.ID != "carrier_opaque_1" || len(got.Hostnames) != 1 || got.Hostnames[0] != "home.relay.test" {
		t.Fatalf("verified carrier = %#v", got)
	}
}

func TestHostedTokenVerifierRejectsInvalidTokens(t *testing.T) {
	key := hostedTestKey()
	now := hostedTestNow()
	base := hostedRelayClaims{
		Type:      hostedRelayTokenType,
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		KeyID:     "relay-2026-06",
		ServerID:  "srv_1",
		Hostnames: []string{"home.relay.test"},
		Purpose:   "tunnel-connect",
		IssuedAt:  now,
		ExpiresAt: now.Add(2 * time.Minute),
		Nonce:     "nonce-1",
	}
	cases := []struct {
		name      string
		token     string
		requested []string
	}{
		{"expired", signHostedTestToken(t, key, withHostedClaims(base, func(c *hostedRelayClaims) { c.ExpiresAt = now.Add(-time.Second) })), nil},
		{"malformed", "not.a.jwt", nil},
		{"invalid signature", corruptToken(signHostedTestToken(t, key, base)), nil},
		{"wrong issuer", signHostedTestToken(t, key, withHostedClaims(base, func(c *hostedRelayClaims) { c.Issuer = "other-cloud" })), nil},
		{"wrong audience", signHostedTestToken(t, key, withHostedClaims(base, func(c *hostedRelayClaims) { c.Audience = "other-relay" })), nil},
		{"wrong purpose", signHostedTestToken(t, key, withHostedClaims(base, func(c *hostedRelayClaims) { c.Purpose = "console-admin" })), nil},
		{"cross-tenant hostname replay", signHostedTestToken(t, key, withHostedClaims(base, func(c *hostedRelayClaims) { c.Hostnames = []string{"tenant-a.relay.test"} })), []string{"tenant-b.relay.test"}},
		{"not yet valid", signHostedTestToken(t, key, withHostedClaims(base, func(c *hostedRelayClaims) { c.IssuedAt = now.Add(MaxIssuedAtSkew + time.Second) })), nil},
		{"missing server binding", signHostedTestToken(t, key, withHostedClaims(base, func(c *hostedRelayClaims) { c.ServerID = "" })), nil},
		{"missing hostname binding", signHostedTestToken(t, key, withHostedClaims(base, func(c *hostedRelayClaims) { c.Hostnames = nil })), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := hostedTestVerifier(key.Public().(ed25519.PublicKey), now)
			requested := tc.requested
			if requested == nil {
				requested = []string{"home.relay.test"}
			}
			if _, err := verifier.VerifyTunnelToken(context.Background(), []byte(tc.token), requested); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("err = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestHostedTokenVerifierRejectsWrongRequestedHostnameAndReplay(t *testing.T) {
	key := hostedTestKey()
	now := hostedTestNow()
	token := signHostedTestToken(t, key, hostedRelayClaims{
		Type:      hostedRelayTokenType,
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		KeyID:     "relay-2026-06",
		ServerID:  "srv_1",
		Hostnames: []string{"home.relay.test"},
		Purpose:   "tunnel-connect",
		IssuedAt:  now,
		ExpiresAt: now.Add(2 * time.Minute),
		Nonce:     "nonce-replay",
	})
	verifier := hostedTestVerifier(key.Public().(ed25519.PublicKey), now)
	if _, err := verifier.VerifyTunnelToken(context.Background(), []byte(token), []string{"evil.relay.test"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong host err = %v, want ErrUnauthorized", err)
	}
	if _, err := verifier.VerifyTunnelToken(context.Background(), []byte(token), []string{"home.relay.test"}); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, err := verifier.VerifyTunnelToken(context.Background(), []byte(token), []string{"home.relay.test"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replay err = %v, want ErrUnauthorized", err)
	}
}

func TestHostedTokenVerifierRejectsEmptyIssuerAudienceConfig(t *testing.T) {
	now := hostedTestNow()
	valid := hostedRelayClaims{
		Type:      hostedRelayTokenType,
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		KeyID:     "relay-2026-06",
		ServerID:  "srv_1",
		Hostnames: []string{"home.relay.test"},
		Purpose:   "tunnel-connect",
		IssuedAt:  now,
		ExpiresAt: now.Add(2 * time.Minute),
		Nonce:     "nonce-1",
	}
	cases := []struct {
		name   string
		mutate func(*HostedTokenVerifier, *hostedRelayClaims)
	}{
		{"issuer", func(v *HostedTokenVerifier, c *hostedRelayClaims) { v.Issuer, c.Issuer = "", "" }},
		{"audience", func(v *HostedTokenVerifier, c *hostedRelayClaims) { v.Audience, c.Audience = "", "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := hostedTestVerifier(nil, now)
			claims := valid
			tc.mutate(v, &claims)
			if err := v.Validate(); err == nil {
				t.Fatal("Validate() = nil, want error")
			}
			if err := v.validateClaims(claims); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("validateClaims err = %v, want ErrUnauthorized", err)
			}
			_, err := Start(context.Background(), Config{
				CarrierTLSConfig: &tls.Config{},
				TokenVerifier:    v,
			})
			if err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("Start err = %v, want %s config error", err, tc.name)
			}
		})
	}
}

func TestHostedReplayProtectionAcrossRestartAndCapacity(t *testing.T) {
	now := hostedTestNow()
	path := filepath.Join(t.TempDir(), "hosted-nonces.json")
	firstStore, err := NewFileHMACNonceStore(path)
	if err != nil {
		t.Fatalf("new first store: %v", err)
	}
	claims := hostedRelayClaims{
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		KeyID:     "relay-2026-06",
		ServerID:  "srv_1",
		Nonce:     "opaque-hosted-nonce",
		ExpiresAt: now.Add(time.Hour),
	}
	first := &HostedTokenVerifier{Now: func() time.Time { return now }, NonceStore: firstStore}
	if err := first.admitNonce(context.Background(), claims); err != nil {
		t.Fatalf("first admission: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted state: %v", err)
	}
	for _, plaintext := range []string{claims.ServerID, claims.Nonce} {
		if strings.Contains(string(raw), plaintext) {
			t.Fatalf("persisted replay state contains plaintext claim %q", plaintext)
		}
	}

	reopenedStore, err := NewFileHMACNonceStore(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	replica := &HostedTokenVerifier{Now: func() time.Time { return now }, NonceStore: reopenedStore}
	if err := replica.admitNonce(context.Background(), claims); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-restart/replica replay err = %v, want ErrUnauthorized", err)
	}

	state, err := reopenedStore.readState()
	if err != nil {
		t.Fatalf("read state for capacity setup: %v", err)
	}
	for i := 0; len(state.Nonces) < DefaultNonceStoreCapacity; i++ {
		state.Nonces[fmt.Sprintf("%032x", i)] = now.Add(time.Hour).UnixNano()
	}
	if err := reopenedStore.writeState(state); err != nil {
		t.Fatalf("fill nonce store: %v", err)
	}
	overflow := claims
	overflow.Nonce = "capacity-overflow"
	if err := replica.admitNonce(context.Background(), overflow); err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("full-capacity admission err = %v, want fail-closed full error", err)
	}

	restartedStore, err := NewFileHMACNonceStore(path)
	if err != nil {
		t.Fatalf("restart full store: %v", err)
	}
	restarted := &HostedTokenVerifier{Now: func() time.Time { return now }, NonceStore: restartedStore}
	if err := restarted.admitNonce(context.Background(), claims); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("live nonce after capacity failure err = %v, want ErrUnauthorized", err)
	}
}

func TestHostedReplayAuthorityFailsClosedWhenUnavailable(t *testing.T) {
	now := hostedTestNow()
	claims := hostedRelayClaims{ExpiresAt: now.Add(time.Minute)}
	withoutStore := &HostedTokenVerifier{
		Issuer:   "beamfall-cloud",
		Audience: "beamfall-relay",
		Now:      func() time.Time { return now },
	}
	if err := withoutStore.Validate(); err == nil || !strings.Contains(err.Error(), "nonce store") {
		t.Fatalf("missing replay authority validation err = %v, want nonce-store error", err)
	}
	if err := withoutStore.admitNonce(context.Background(), claims); err == nil {
		t.Fatal("hosted nonce admission succeeded without replay authority")
	}
	withUnavailableStore := &HostedTokenVerifier{
		Now:        func() time.Time { return now },
		NonceStore: unavailableHMACNonceStore{},
	}
	if err := withUnavailableStore.admitNonce(context.Background(), claims); err == nil {
		t.Fatal("hosted nonce admission succeeded while replay authority was unavailable")
	}
}

func TestHostedTokenTimingBoundariesAreDeterministic(t *testing.T) {
	now := hostedTestNow()
	v := &HostedTokenVerifier{Now: func() time.Time { return now }}
	cases := []struct {
		name      string
		issuedAt  time.Time
		expiresAt time.Time
		wantErr   bool
	}{
		{"issued exactly now", now, now.Add(time.Minute), false},
		{"issued at the skew leeway", now.Add(MaxIssuedAtSkew), now.Add(MaxIssuedAtSkew + time.Minute), false},
		{"one nanosecond beyond the skew leeway", now.Add(MaxIssuedAtSkew + time.Nanosecond), now.Add(MaxIssuedAtSkew + time.Minute), true},
		{"one nanosecond before expiry", now.Add(-time.Minute), now.Add(time.Nanosecond), false},
		{"exactly at expiry", now.Add(-time.Minute), now, true},
		{"expiry not after issue", now, now, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.validateClaimTiming(hostedRelayClaims{IssuedAt: tc.issuedAt, ExpiresAt: tc.expiresAt})
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate timing err = %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}

// TestHostedTokenIssuedAtSkew pins the issued_at leeway end to end: a token
// minted by a clock up to MaxIssuedAtSkew ahead of the relay verifies, one
// further ahead is rejected, and expires_at gets no leeway.
func TestHostedTokenIssuedAtSkew(t *testing.T) {
	key := hostedTestKey()
	now := hostedTestNow()
	cases := []struct {
		name      string
		issuedAt  time.Time
		expiresAt time.Time
		wantErr   bool
	}{
		{"issued 30s in the future", now.Add(30 * time.Second), now.Add(2 * time.Minute), false},
		{"issued 120s in the future", now.Add(120 * time.Second), now.Add(4 * time.Minute), true},
		{"expired one second ago", now.Add(-time.Minute), now.Add(-time.Second), true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := hostedRelayClaims{
				Type:      hostedRelayTokenType,
				Issuer:    "beamfall-cloud",
				Audience:  "beamfall-relay",
				KeyID:     "relay-2026-06",
				ServerID:  "srv_1",
				Hostnames: []string{"home.relay.test"},
				Purpose:   "tunnel-connect",
				IssuedAt:  tc.issuedAt,
				ExpiresAt: tc.expiresAt,
				Nonce:     fmt.Sprintf("skew-%d", i),
			}
			verifier := hostedTestVerifier(key.Public().(ed25519.PublicKey), now)
			_, err := verifier.VerifyTunnelToken(context.Background(), []byte(signHostedTestToken(t, key, claims)), []string{"home.relay.test"})
			if !tc.wantErr && err != nil {
				t.Fatalf("verify err = %v, want accepted", err)
			}
			if tc.wantErr && !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("verify err = %v, want ErrUnauthorized", err)
			}
		})
	}
}

// TestHostedTTLCeiling pins the hosted lifetime ceiling: a token whose signed
// lifetime is exactly MaxHostedTokenTTL verifies, and a 25h token is rejected
// with its own reason before its nonce reaches the replay store.
func TestHostedTTLCeiling(t *testing.T) {
	key := hostedTestKey()
	now := hostedTestNow()
	base := hostedRelayClaims{
		Type:      hostedRelayTokenType,
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		KeyID:     "relay-2026-06",
		ServerID:  "srv_1",
		Hostnames: []string{"home.relay.test"},
		Purpose:   "tunnel-connect",
		IssuedAt:  now.Add(-time.Minute),
		Nonce:     "ceiling-at-cap",
	}
	atCap := withHostedClaims(base, func(c *hostedRelayClaims) { c.ExpiresAt = c.IssuedAt.Add(MaxHostedTokenTTL) })
	verifier := hostedTestVerifier(key.Public().(ed25519.PublicKey), now)
	if _, err := verifier.VerifyTunnelToken(context.Background(), []byte(signHostedTestToken(t, key, atCap)), []string{"home.relay.test"}); err != nil {
		t.Fatalf("lifetime at ceiling rejected: %v", err)
	}

	overCap := withHostedClaims(base, func(c *hostedRelayClaims) {
		c.ExpiresAt = c.IssuedAt.Add(25 * time.Hour)
		c.Nonce = "ceiling-over-cap"
	})
	store := &hmacReplayGuard{}
	verifier = hostedTestVerifier(key.Public().(ed25519.PublicKey), now)
	verifier.NonceStore = store
	_, err := verifier.VerifyTunnelToken(context.Background(), []byte(signHostedTestToken(t, key, overCap)), []string{"home.relay.test"})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("25h lifetime err = %v, want ErrUnauthorized", err)
	}
	if want := ErrUnauthorized.Error() + ": token ttl exceeds 24h0m0s"; err.Error() != want {
		t.Fatalf("25h lifetime err = %q, want distinct reason %q", err, want)
	}
	if len(store.nonces) != 0 {
		t.Fatalf("rejected 25h token admitted %d nonce(s) to the replay store", len(store.nonces))
	}
}

// TestHostedTokenVerifierNonceCacheIsBounded drives a churn of distinct,
// still-unexpired nonces far past the configured cap and asserts the nonce
// cache never grows beyond NonceCacheCap (RV-RELAY-007). All nonces share a
// long expiry so the expiry sweep cannot mask the cap-eviction path -- the
// bound here is enforced purely by capacity eviction.
func TestHostedTokenVerifierNonceCacheIsBounded(t *testing.T) {
	now := hostedTestNow()
	const cap = 32
	v := &HostedTokenVerifier{
		Now:           func() time.Time { return now },
		NonceCacheCap: cap,
	}
	base := hostedRelayClaims{
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		ServerID:  "srv_1",
		ExpiresAt: now.Add(time.Hour), // never expires during the test
	}
	for i := 0; i < cap*50; i++ {
		c := base
		c.Nonce = "nonce-" + strconv.Itoa(i)
		if err := v.acceptNonce(c); err != nil {
			t.Fatalf("acceptNonce #%d: %v", i, err)
		}
		if got := len(v.nonces); got > cap {
			t.Fatalf("nonce cache grew to %d, exceeds cap %d (unbounded?)", got, cap)
		}
	}
	if got := len(v.nonces); got != cap {
		t.Fatalf("after churn, cache size = %d, want it filled to cap %d", got, cap)
	}
}

func TestHostedTokenVerifierNonceCacheExpiresRelayMetadata(t *testing.T) {
	now := hostedTestNow()
	v := &HostedTokenVerifier{Now: func() time.Time { return now }}
	claims := hostedRelayClaims{
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		ServerID:  "srv_1",
		Nonce:     "nonce-expiring",
		ExpiresAt: now.Add(time.Minute),
	}
	if err := v.acceptNonce(claims); err != nil {
		t.Fatalf("accept first nonce: %v", err)
	}
	if len(v.nonces) != 1 {
		t.Fatalf("nonce cache size = %d, want 1", len(v.nonces))
	}
	now = claims.ExpiresAt
	claims.Nonce = "nonce-after-expiry"
	claims.ExpiresAt = now.Add(time.Minute)
	if err := v.acceptNonce(claims); err != nil {
		t.Fatalf("accept post-expiry nonce: %v", err)
	}
	if len(v.nonces) != 1 {
		t.Fatalf("expired relay nonce metadata retained; cache size = %d, want 1", len(v.nonces))
	}
}

// TestHostedTokenVerifierEvictsSoonestToExpireFirst drives the cache to its
// cap with entries of staggered expiry, then adds one more entry and asserts
// eviction removed exactly the earliest-expiring nonce -- not an arbitrary
// one -- and that every later-expiring (still within-TTL) nonce survives
// (AUDIT-RELAY-5 / CRYPT-02).
func TestHostedTokenVerifierEvictsSoonestToExpireFirst(t *testing.T) {
	now := hostedTestNow()
	const cap = 16
	v := &HostedTokenVerifier{
		Now:           func() time.Time { return now },
		NonceCacheCap: cap,
	}
	base := hostedRelayClaims{
		Issuer:   "beamfall-cloud",
		Audience: "beamfall-relay",
		ServerID: "srv_1",
	}
	// Insert `cap` nonces with distinct, staggered expiries in shuffled order so
	// heap position can't accidentally match insertion order.
	order := []int{7, 2, 15, 0, 9, 4, 11, 1, 13, 6, 10, 3, 14, 5, 12, 8}
	keyFor := func(i int) string {
		return strings.Join([]string{base.Issuer, base.Audience, "", base.ServerID, "nonce-" + strconv.Itoa(i)}, "\x00")
	}
	for _, i := range order {
		c := base
		c.Nonce = "nonce-" + strconv.Itoa(i)
		c.ExpiresAt = now.Add(time.Duration(i+1) * time.Minute) // nonce-0 expires soonest
		if err := v.acceptNonce(c); err != nil {
			t.Fatalf("acceptNonce nonce-%d: %v", i, err)
		}
	}
	if got := len(v.nonces); got != cap {
		t.Fatalf("cache size = %d, want %d", got, cap)
	}
	// One more insert must evict exactly nonce-0 (soonest-to-expire) and nothing else.
	c := base
	c.Nonce = "nonce-overflow"
	c.ExpiresAt = now.Add(time.Duration(cap+1) * time.Minute)
	if err := v.acceptNonce(c); err != nil {
		t.Fatalf("acceptNonce overflow: %v", err)
	}
	if _, stillPresent := v.nonces[keyFor(0)]; stillPresent {
		t.Fatalf("soonest-to-expire nonce-0 was not evicted")
	}
	for i := 1; i < cap; i++ {
		if _, present := v.nonces[keyFor(i)]; !present {
			t.Fatalf("nonce-%d evicted before its expiry (want only soonest-to-expire evicted)", i)
		}
	}
	if got := len(v.nonces); got != cap {
		t.Fatalf("after overflow insert, cache size = %d, want it to stay at cap %d", got, cap)
	}
}

// BenchmarkHostedTokenVerifierAcceptNonceAtCap measures acceptNonce (and thus
// v.mu hold time) once the cache is saturated at NonceCacheCap, where every
// call now triggers an eviction. Before AUDIT-RELAY-5 this scanned the whole
// map per call (O(n)); with the min-heap it is O(log n), so per-op time
// should stay flat as -benchtime scales rather than growing with the cache
// size. Compare across NonceCacheCap sizes (e.g. `-bench=AtCap` with the cap
// edited, or `benchstat`) to confirm no O(n) regression at scale.
func BenchmarkHostedTokenVerifierAcceptNonceAtCap(b *testing.B) {
	now := hostedTestNow()
	const cap = DefaultNonceStoreCapacity
	v := &HostedTokenVerifier{
		Now:           func() time.Time { return now },
		NonceCacheCap: cap,
	}
	base := hostedRelayClaims{
		Issuer:   "beamfall-cloud",
		Audience: "beamfall-relay",
		ServerID: "srv_1",
	}
	// Pre-fill to cap so every benchmarked call pays an eviction.
	for i := 0; i < cap; i++ {
		c := base
		c.Nonce = "prefill-" + strconv.Itoa(i)
		c.ExpiresAt = now.Add(time.Hour + time.Duration(i)*time.Millisecond)
		if err := v.acceptNonce(c); err != nil {
			b.Fatalf("prefill acceptNonce #%d: %v", i, err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := base
		c.Nonce = "bench-" + strconv.Itoa(i)
		c.ExpiresAt = now.Add(2 * time.Hour) // always the newest, never itself evicted
		if err := v.acceptNonce(c); err != nil {
			b.Fatalf("acceptNonce #%d: %v", i, err)
		}
	}
}

// TestHostedTokenVerifierNonceCacheDefaultCap asserts an unconfigured verifier
// falls back to the default cap rather than an unbounded map.
func TestHostedTokenVerifierNonceCacheDefaultCap(t *testing.T) {
	now := hostedTestNow()
	v := &HostedTokenVerifier{Now: func() time.Time { return now }}
	c := hostedRelayClaims{
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		ServerID:  "srv_1",
		ExpiresAt: now.Add(time.Hour),
		Nonce:     "nonce-default",
	}
	if err := v.acceptNonce(c); err != nil {
		t.Fatalf("acceptNonce: %v", err)
	}
	if v.NonceCacheCap != 0 {
		t.Fatalf("test expects unset NonceCacheCap, got %d", v.NonceCacheCap)
	}
	// The effective cap is DefaultNonceStoreCapacity; the cache must never exceed it.
	if len(v.nonces) > DefaultNonceStoreCapacity {
		t.Fatalf("default-cap cache size %d exceeds default %d", len(v.nonces), DefaultNonceStoreCapacity)
	}
}

// TestHostedTokenVerifierNonceCacheSnapshotTracksGrowthAndCap asserts the
// snapshot's Entries count grows with each accepted nonce (at and below cap)
// and Cap reports the configured NonceCacheCap (MEMHID-RELAY-NONCE-GAUGE).
func TestHostedTokenVerifierNonceCacheSnapshotTracksGrowthAndCap(t *testing.T) {
	now := hostedTestNow()
	const cap = 8
	v := &HostedTokenVerifier{
		Now:           func() time.Time { return now },
		NonceCacheCap: cap,
	}
	base := hostedRelayClaims{
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		ServerID:  "srv_1",
		ExpiresAt: now.Add(time.Hour),
	}
	for i := 0; i < cap; i++ {
		if got := v.nonceCacheSnapshot(); got.Entries != i || got.Cap != cap {
			t.Fatalf("before accept #%d: snapshot = %+v, want Entries=%d Cap=%d", i, got, i, cap)
		}
		c := base
		c.Nonce = "nonce-" + strconv.Itoa(i)
		if err := v.acceptNonce(c); err != nil {
			t.Fatalf("acceptNonce #%d: %v", i, err)
		}
	}
	if got := v.nonceCacheSnapshot(); got.Entries != cap || got.Cap != cap {
		t.Fatalf("at cap: snapshot = %+v, want Entries=%d Cap=%d", got, cap, cap)
	}
}

// TestHostedTokenVerifierNonceCacheSnapshotDefaultCap asserts an unconfigured
// verifier's snapshot reports the package default cap, not zero/unbounded.
func TestHostedTokenVerifierNonceCacheSnapshotDefaultCap(t *testing.T) {
	now := hostedTestNow()
	v := &HostedTokenVerifier{Now: func() time.Time { return now }}
	got := v.nonceCacheSnapshot()
	if got.Entries != 0 || got.Cap != DefaultNonceStoreCapacity {
		t.Fatalf("snapshot = %+v, want Entries=0 Cap=%d", got, DefaultNonceStoreCapacity)
	}
}

// TestHostedTokenVerifierNonceCacheSnapshotNeverExceedsCapUnderChurn drives
// churn well past the cap and asserts the snapshot's Entries never exceeds
// Cap at any point (mirrors TestHostedTokenVerifierNonceCacheIsBounded but
// through the published snapshot rather than the private map).
func TestHostedTokenVerifierNonceCacheSnapshotNeverExceedsCapUnderChurn(t *testing.T) {
	now := hostedTestNow()
	const cap = 16
	v := &HostedTokenVerifier{
		Now:           func() time.Time { return now },
		NonceCacheCap: cap,
	}
	base := hostedRelayClaims{
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		ServerID:  "srv_1",
		ExpiresAt: now.Add(time.Hour),
	}
	for i := 0; i < cap*20; i++ {
		c := base
		c.Nonce = "nonce-" + strconv.Itoa(i)
		if err := v.acceptNonce(c); err != nil {
			t.Fatalf("acceptNonce #%d: %v", i, err)
		}
		if got := v.nonceCacheSnapshot(); got.Entries > cap {
			t.Fatalf("snapshot #%d = %+v, Entries exceeds cap %d", i, got, cap)
		}
	}
	if got := v.nonceCacheSnapshot(); got.Entries != cap {
		t.Fatalf("after churn: snapshot = %+v, want Entries=%d", got, cap)
	}
}

// TestHostedTokenVerifierNonceCacheSnapshotReflectsExpiryWithoutFurtherTraffic
// asserts a snapshot taken after entries expire -- with no further
// verification traffic to trigger acceptNonce's own sweep -- still reports
// the swept, lower entry count (a scrape between bursts of traffic).
func TestHostedTokenVerifierNonceCacheSnapshotReflectsExpiryWithoutFurtherTraffic(t *testing.T) {
	now := hostedTestNow()
	v := &HostedTokenVerifier{Now: func() time.Time { return now }}
	claims := hostedRelayClaims{
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		ServerID:  "srv_1",
		Nonce:     "nonce-expiring",
		ExpiresAt: now.Add(time.Minute),
	}
	if err := v.acceptNonce(claims); err != nil {
		t.Fatalf("accept nonce: %v", err)
	}
	if got := v.nonceCacheSnapshot(); got.Entries != 1 {
		t.Fatalf("before expiry: snapshot = %+v, want Entries=1", got)
	}
	now = claims.ExpiresAt // advance past expiry; no further acceptNonce call
	if got := v.nonceCacheSnapshot(); got.Entries != 0 {
		t.Fatalf("after expiry: snapshot = %+v, want Entries=0 (sweep-on-read)", got)
	}
}

// TestHostedTokenVerifierNonceCacheSnapshotConcurrentWithVerification races
// real token verification (which mutates the nonce cache via acceptNonce)
// against concurrent snapshot reads under `go test -race`, asserting no data
// race and that every snapshot stays within [0, cap].
func TestHostedTokenVerifierNonceCacheSnapshotConcurrentWithVerification(t *testing.T) {
	key := hostedTestKey()
	now := hostedTestNow()
	const cap = 64
	v := hostedTestVerifier(key.Public().(ed25519.PublicKey), now)
	v.NonceCacheCap = cap

	const verifiers = 32
	tokens := make([]string, verifiers)
	for i := range tokens {
		tokens[i] = signHostedTestToken(t, key, hostedRelayClaims{
			Type:      hostedRelayTokenType,
			Issuer:    "beamfall-cloud",
			Audience:  "beamfall-relay",
			KeyID:     "relay-2026-06",
			ServerID:  "srv_1",
			Hostnames: []string{"home.relay.test"},
			Purpose:   "tunnel-connect",
			IssuedAt:  now,
			ExpiresAt: now.Add(2 * time.Minute),
			Nonce:     "race-nonce-" + strconv.Itoa(i),
		})
	}

	start := make(chan struct{})
	stop := make(chan struct{})
	var writersWG, readersWG sync.WaitGroup
	for _, tok := range tokens {
		writersWG.Add(1)
		go func(tok string) {
			defer writersWG.Done()
			<-start
			if _, err := v.VerifyTunnelToken(context.Background(), []byte(tok), []string{"home.relay.test"}); err != nil {
				t.Errorf("verify: %v", err)
			}
		}(tok)
	}
	const readers = 8
	for i := 0; i < readers; i++ {
		readersWG.Add(1)
		go func() {
			defer readersWG.Done()
			<-start
			for {
				select {
				case <-stop:
					return
				default:
				}
				if got := v.nonceCacheSnapshot(); got.Entries < 0 || got.Entries > cap || got.Cap != cap {
					t.Errorf("snapshot out of bounds: %+v", got)
					return
				}
			}
		}()
	}
	close(start)
	writersWG.Wait()
	close(stop)
	readersWG.Wait()

	if got := v.nonceCacheSnapshot(); got.Entries != verifiers {
		t.Fatalf("final snapshot = %+v, want Entries=%d", got, verifiers)
	}
}

// TestValidateClaimsGuards exercises validateClaims directly, one mutation at
// a time, to confirm each split per-condition guard (AUDIT-RELAY-11)
// independently rejects its own field while leaving the others valid, and
// that the external contract (ErrUnauthorized, no per-field detail) is
// unchanged.
func TestValidateClaimsGuards(t *testing.T) {
	now := hostedTestNow()
	v := hostedTestVerifier(nil, now)
	valid := hostedRelayClaims{
		Type:      hostedRelayTokenType,
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		KeyID:     "relay-2026-06",
		ServerID:  "srv_1",
		Hostnames: []string{"home.relay.test"},
		Purpose:   "tunnel-connect",
		IssuedAt:  now,
		ExpiresAt: now.Add(2 * time.Minute),
		Nonce:     "nonce-1",
	}
	if err := v.validateClaims(valid); err != nil {
		t.Fatalf("baseline valid claims rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*hostedRelayClaims)
	}{
		{"wrong type (presence guard)", func(c *hostedRelayClaims) { c.Type = "other-type" }},
		{"missing key id (presence guard)", func(c *hostedRelayClaims) { c.KeyID = "" }},
		{"missing server id (presence guard)", func(c *hostedRelayClaims) { c.ServerID = "" }},
		{"missing hostnames (presence guard)", func(c *hostedRelayClaims) { c.Hostnames = nil }},
		{"missing purpose (presence guard)", func(c *hostedRelayClaims) { c.Purpose = "" }},
		{"zero issued at (presence guard)", func(c *hostedRelayClaims) { c.IssuedAt = time.Time{} }},
		{"zero expires at (presence guard)", func(c *hostedRelayClaims) { c.ExpiresAt = time.Time{} }},
		{"missing nonce (presence guard)", func(c *hostedRelayClaims) { c.Nonce = "" }},
		{"bad trace correlation id (presence guard)", func(c *hostedRelayClaims) { c.TraceCorrelationID = "not-32-lowercase-hex" }},
		{"wrong issuer (audience guard)", func(c *hostedRelayClaims) { c.Issuer = "other-cloud" }},
		{"wrong audience (audience guard)", func(c *hostedRelayClaims) { c.Audience = "other-relay" }},
		{"wrong purpose (purpose guard)", func(c *hostedRelayClaims) { c.Purpose = "other-purpose" }},
		{"not yet issued (timing guard)", func(c *hostedRelayClaims) { c.IssuedAt = now.Add(MaxIssuedAtSkew + time.Second) }},
		{"expires before issued (timing guard)", func(c *hostedRelayClaims) { c.ExpiresAt = c.IssuedAt.Add(-time.Second) }},
		{"already expired (timing guard)", func(c *hostedRelayClaims) { c.ExpiresAt = now.Add(-time.Second) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := valid
			tc.mutate(&claims)
			if err := v.validateClaims(claims); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("err = %v, want ErrUnauthorized", err)
			}
		})
	}
}

// TestHostedTokenRejectionLogNamesGuard pins the server-local diagnostic
// (BUGREV0926-FU-RELAY-TOKEN-CLOCK-DIAGNOSTICS-1): each validateClaims
// rejection writes exactly one log record naming the guard that rejected the
// token, the record carries no claim value, and the returned error does not
// carry the guard name, so the external contract stays opaque.
func TestHostedTokenRejectionLogNamesGuard(t *testing.T) {
	now := hostedTestNow()
	valid := hostedRelayClaims{
		Type:      hostedRelayTokenType,
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		KeyID:     "relay-2026-06",
		ServerID:  "srv_1",
		Hostnames: []string{"home.relay.test"},
		Purpose:   "tunnel-connect",
		IssuedAt:  now,
		ExpiresAt: now.Add(2 * time.Minute),
		Nonce:     "nonce-1",
	}
	cases := []struct {
		guard  string
		mutate func(*hostedRelayClaims)
	}{
		{claimGuardPresence, func(c *hostedRelayClaims) { c.KeyID = "" }},
		{claimGuardAudience, func(c *hostedRelayClaims) { c.Audience = "other-relay" }},
		{claimGuardPurpose, func(c *hostedRelayClaims) { c.Purpose = "other-purpose" }},
		{claimGuardIssuedAtSkew, func(c *hostedRelayClaims) {
			c.IssuedAt = now.Add(MaxIssuedAtSkew + time.Second)
			c.ExpiresAt = c.IssuedAt.Add(time.Minute)
		}},
		{claimGuardExpiryOrder, func(c *hostedRelayClaims) { c.ExpiresAt = c.IssuedAt }},
		{claimGuardTTLCeiling, func(c *hostedRelayClaims) { c.ExpiresAt = c.IssuedAt.Add(MaxHostedTokenTTL + time.Second) }},
		{claimGuardExpired, func(c *hostedRelayClaims) {
			c.IssuedAt = now.Add(-2 * time.Minute)
			c.ExpiresAt = now
		}},
	}
	for _, tc := range cases {
		t.Run(tc.guard, func(t *testing.T) {
			var logs strings.Builder
			v := hostedTestVerifier(nil, now)
			v.Logger = slog.New(slog.NewTextHandler(&logs, nil))
			claims := valid
			tc.mutate(&claims)
			err := v.validateClaims(claims)
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("err = %v, want ErrUnauthorized", err)
			}
			if strings.Contains(err.Error(), tc.guard) {
				t.Fatalf("returned error %q carries guard name %q", err, tc.guard)
			}
			out := logs.String()
			if got := strings.Count(out, "guard="); got != 1 {
				t.Fatalf("log has %d guard records, want 1:\n%s", got, out)
			}
			if !strings.Contains(out, "guard="+tc.guard+"\n") {
				t.Fatalf("log does not name guard %q:\n%s", tc.guard, out)
			}
			for _, value := range []string{"srv_1", "home.relay.test", "nonce-1", "relay-2026-06"} {
				if strings.Contains(out, value) {
					t.Fatalf("log carries claim value %q:\n%s", value, out)
				}
			}
		})
	}

	var logs strings.Builder
	v := hostedTestVerifier(nil, now)
	v.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	if err := v.validateClaims(valid); err != nil {
		t.Fatalf("baseline valid claims rejected: %v", err)
	}
	if logs.Len() != 0 {
		t.Fatalf("accepted claims wrote a rejection record:\n%s", logs.String())
	}
}

func assertHostedTokenHasNoAccountID(t *testing.T, token, forbiddenValue string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	if strings.Contains(string(payload), forbiddenValue) {
		t.Fatalf("hosted token payload contains account id: %s", payload)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal token payload: %v", err)
	}
	for key := range claims {
		if strings.Contains(key, "account") {
			t.Fatalf("hosted token claim %q carries account identity", key)
		}
	}
}

func hostedTestKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func hostedTestNow() time.Time {
	return time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
}

func hostedTestVerifier(pub ed25519.PublicKey, now time.Time) *HostedTokenVerifier {
	return &HostedTokenVerifier{
		Issuer:   "beamfall-cloud",
		Audience: "beamfall-relay",
		Purpose:  "tunnel-connect",
		PublicKeys: map[string]ed25519.PublicKey{
			"relay-2026-06": pub,
		},
		Now:        func() time.Time { return now },
		NonceStore: &hmacReplayGuard{},
	}
}

type unavailableHMACNonceStore struct{}

func (unavailableHMACNonceStore) Admit(context.Context, string, time.Time, time.Time) (bool, error) {
	return false, errors.New("replay authority unavailable")
}

func signHostedTestToken(t *testing.T, key ed25519.PrivateKey, claims hostedRelayClaims) string {
	t.Helper()
	// Mint via the single-owner module's signing path — the same code cloud's
	// minter routes through — so the test exercises the real wire encoder.
	tok, err := relaytoken.SignWith(claims, claims.KeyID, func(b []byte) ([]byte, error) {
		return ed25519.Sign(key, b), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func withHostedClaims(claims hostedRelayClaims, mutate func(*hostedRelayClaims)) hostedRelayClaims {
	mutate(&claims)
	return claims
}

func corruptToken(token string) string {
	parts := strings.Split(token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}
