package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestValidateTokenStrengthAcceptsStrongToken pins the entropy floor's accept
// path: a token at the length floor with ample distinct byte values passes.
func TestValidateTokenStrengthAcceptsStrongToken(t *testing.T) {
	// 32 distinct bytes: clears both the length floor and the distinct-byte floor.
	strong := make([]byte, MinTokenBytes)
	for i := range strong {
		strong[i] = byte(i)
	}
	if err := ValidateTokenStrength(strong); err != nil {
		t.Fatalf("strong token rejected: %v", err)
	}
	// A realistic base64-ish random token also passes.
	if err := ValidateTokenStrength([]byte("Zk9q2L7vR1pX4mB8nT6wC3sY0aH5dF2gJ8kQ1uE7iO4")); err != nil {
		t.Fatalf("base64 token rejected: %v", err)
	}
}

// TestValidateTokenStrengthRejectsWeakTokens covers the entropy-floor rejection
// branches relayd fails fast on: too short, and long-but-low-entropy. The error
// must never echo the token bytes (the relay must not log token material).
func TestValidateTokenStrengthRejectsWeakTokens(t *testing.T) {
	cases := []struct {
		name  string
		token []byte
	}{
		{"empty", nil},
		{"too short", []byte("short-secret")},
		{"at length floor but one repeated byte", bytes.Repeat([]byte("a"), MinTokenBytes)},
		{"long but few distinct bytes", bytes.Repeat([]byte("abc"), MinTokenBytes)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTokenStrength(tc.token)
			if err == nil {
				t.Fatal("expected weak token to be rejected")
			}
			if len(tc.token) > 0 && strings.Contains(err.Error(), string(tc.token)) {
				t.Fatalf("error leaked token bytes: %v", err)
			}
		})
	}
}

// TestStaticTokenVerifierAcceptsExactToken pins the self-hosted default verifier's
// success path: the exact shared token over an allowed host returns a verified
// carrier, and an empty configured CarrierID falls back to the first hostname.
func TestStaticTokenVerifierAcceptsExactToken(t *testing.T) {
	v := StaticTokenVerifier{
		Token:     []byte("shared-secret"),
		Hostnames: []string{"home.relay.test"},
	}
	got, err := v.VerifyTunnelToken(context.Background(), []byte("shared-secret"), []string{"home.relay.test"})
	if err != nil {
		t.Fatalf("verify exact token: %v", err)
	}
	if got.ID != "home.relay.test" { // empty CarrierID -> first hostname
		t.Fatalf("carrier id = %q, want first hostname", got.ID)
	}
	if len(got.Hostnames) != 1 || got.Hostnames[0] != "home.relay.test" {
		t.Fatalf("hostnames = %#v", got.Hostnames)
	}
}

// TestStaticTokenVerifierRejectsBadInput covers the load-bearing rejection
// branches the carrier handshake's token-auth seam depends on: a wrong token, an
// empty configured token (never auto-accept), a token over a host not in the
// allow-list, and an empty hostname request. Each must return ErrUnauthorized and
// no verified carrier.
func TestStaticTokenVerifierRejectsBadInput(t *testing.T) {
	cases := []struct {
		name      string
		verifier  StaticTokenVerifier
		token     []byte
		requested []string
	}{
		{
			name:      "wrong token",
			verifier:  StaticTokenVerifier{Token: []byte("right"), Hostnames: []string{"home.relay.test"}},
			token:     []byte("wrong"),
			requested: []string{"home.relay.test"},
		},
		{
			name:      "empty configured token never auto-accepts",
			verifier:  StaticTokenVerifier{Token: nil, Hostnames: []string{"home.relay.test"}},
			token:     []byte(""),
			requested: []string{"home.relay.test"},
		},
		{
			name:      "host not in allow-list",
			verifier:  StaticTokenVerifier{Token: []byte("right"), Hostnames: []string{"home.relay.test"}},
			token:     []byte("right"),
			requested: []string{"evil.relay.test"},
		},
		{
			name:      "no hostnames requested",
			verifier:  StaticTokenVerifier{Token: []byte("right"), Hostnames: []string{"home.relay.test"}},
			token:     []byte("right"),
			requested: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.verifier.VerifyTunnelToken(context.Background(), tc.token, tc.requested)
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("err = %v, want ErrUnauthorized", err)
			}
			if got.ID != "" || got.Hostnames != nil {
				t.Fatalf("rejected verify returned a carrier: %#v", got)
			}
		})
	}
}

// TestStaticTokenVerifierHonorsCancelledContext asserts the verifier short-circuits
// on a cancelled context before doing token work, matching the carrier handshake's
// shutdown posture.
func TestStaticTokenVerifierHonorsCancelledContext(t *testing.T) {
	v := StaticTokenVerifier{Token: []byte("right"), Hostnames: []string{"home.relay.test"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.VerifyTunnelToken(ctx, []byte("right"), []string{"home.relay.test"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// TestHMACTokenVerifierAcceptsLegacyV1Token pins the dual-accept path: with
// AcceptLegacyV1 set, a legacy bare-HMAC token still verifies (and carries no
// token-driven expiry) so operators can upgrade carriers without a hard cutover.
func TestHMACTokenVerifierAcceptsLegacyV1Token(t *testing.T) {
	verifier := &HMACTokenVerifier{
		Secret:         []byte("secret"),
		CarrierID:      "carrier-1",
		Hostnames:      []string{"home.relay.test"},
		AcceptLegacyV1: true,
	}
	token := MintHMACTestToken([]byte("secret"), []string{"home.relay.test"})
	got, err := verifier.VerifyTunnelToken(context.Background(), token, []string{"home.relay.test"})
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if got.ID != "carrier-1" || len(got.Hostnames) != 1 || got.Hostnames[0] != "home.relay.test" {
		t.Fatalf("verified carrier = %#v", got)
	}
	if !got.ExpiresAt.IsZero() {
		t.Fatalf("legacy token carried an expiry: %v", got.ExpiresAt)
	}
}

// TestHMACTokenVerifierRejectsLegacyWhenDisabled pins that once the dual-accept
// release is over (AcceptLegacyV1 false), a legacy token is refused — only v2
// expiring, replay-resistant tokens are accepted.
func TestHMACTokenVerifierRejectsLegacyWhenDisabled(t *testing.T) {
	verifier := &HMACTokenVerifier{
		Secret:    []byte("secret"),
		Hostnames: []string{"home.relay.test"},
	}
	token := MintHMACTestToken([]byte("secret"), []string{"home.relay.test"})
	if _, err := verifier.VerifyTunnelToken(context.Background(), token, []string{"home.relay.test"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestHMACTokenVerifierRejectsWrongHost(t *testing.T) {
	verifier := &HMACTokenVerifier{
		Secret:         []byte("secret"),
		Hostnames:      []string{"home.relay.test"},
		AcceptLegacyV1: true,
	}
	token := MintHMACTestToken([]byte("secret"), []string{"other.relay.test"})
	if _, err := verifier.VerifyTunnelToken(context.Background(), token, []string{"other.relay.test"}); err == nil {
		t.Fatal("expected wrong host to fail")
	}
}

// TestMintHMACTunnelTokenRejectsNonPositiveTTL pins the mint-time guard: a token
// with no positive lifetime is a caller error, not a token that never expires.
func TestMintHMACTunnelTokenRejectsNonPositiveTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Minute} {
		if _, err := MintHMACTunnelToken([]byte("secret"), []string{"home.relay.test"}, ttl); err == nil {
			t.Fatalf("ttl=%s: expected error, got nil", ttl)
		}
	}
}

// TestHMACTokenVerifierAcceptsV2Token pins the happy path for the expiring,
// replay-resistant v2 format: a freshly minted token verifies and its expiry is
// carried on the VerifiedCarrier (so serveCarrierSession can tear down at expiry).
func TestHMACTokenVerifierAcceptsV2Token(t *testing.T) {
	secret := []byte("secret")
	verifier := &HMACTokenVerifier{
		Secret:     secret,
		CarrierID:  "carrier-1",
		Hostnames:  []string{"home.relay.test"},
		NonceStore: &hmacReplayGuard{},
	}
	token, err := MintHMACTunnelToken(secret, []string{"home.relay.test"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err := verifier.VerifyTunnelToken(context.Background(), token, []string{"home.relay.test"})
	if err != nil {
		t.Fatalf("verify v2 token: %v", err)
	}
	if got.ID != "carrier-1" || len(got.Hostnames) != 1 || got.Hostnames[0] != "home.relay.test" {
		t.Fatalf("verified carrier = %#v", got)
	}
	if got.ExpiresAt.IsZero() {
		t.Fatal("v2 token verified without carrying an expiry")
	}
}

// TestHMACTokenVerifierRejectsExpiredV2Token pins the expiry check: a token whose
// expires-at is in the past (relative to the verifier's clock) is refused.
func TestHMACTokenVerifierRejectsExpiredV2Token(t *testing.T) {
	secret := []byte("secret")
	token, err := MintHMACTunnelToken(secret, []string{"home.relay.test"}, time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	future := time.Now().Add(2 * time.Minute)
	verifier := &HMACTokenVerifier{
		Secret:    secret,
		Hostnames: []string{"home.relay.test"},
		Now:       func() time.Time { return future },
	}
	if _, err := verifier.VerifyTunnelToken(context.Background(), token, []string{"home.relay.test"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized (expired)", err)
	}
}

// TestHMACTokenVerifierRejectsV2TokenAboveTTLCeiling pins the verify-time
// lifetime bound. Mint-time validation alone is insufficient because a peer can
// construct and sign an overlong token directly with the shared secret.
func TestHMACTokenVerifierRejectsV2TokenAboveTTLCeiling(t *testing.T) {
	secret := []byte("secret")
	token, err := MintHMACTunnelToken(secret, []string{"home.relay.test"}, MaxHMACTokenTTL+time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	verifier := &HMACTokenVerifier{
		Secret:    secret,
		Hostnames: []string{"home.relay.test"},
	}
	if _, err := verifier.VerifyTunnelToken(context.Background(), token, []string{"home.relay.test"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized (ttl above %s)", err, MaxHMACTokenTTL)
	}
}

// TestHMACTokenVerifierRejectsFutureIssuedV2Token prevents bypassing the TTL
// ceiling by shifting both signed timestamps far into the future while keeping
// their difference below the ceiling.
func TestHMACTokenVerifierRejectsFutureIssuedV2Token(t *testing.T) {
	secret := []byte("secret")
	hosts := []string{"home.relay.test"}
	now := time.Now().Truncate(time.Second)
	issuedAt := now.Add(time.Hour)
	expiresAt := issuedAt.Add(5 * time.Minute)
	nonce := strings.Repeat("ab", hmacNonceBytes)
	token := []byte(strings.Join([]string{
		hmacTokenV2Prefix,
		strconv.FormatInt(issuedAt.Unix(), 10),
		strconv.FormatInt(expiresAt.Unix(), 10),
		nonce,
		macV2(secret, hosts, issuedAt, expiresAt, nonce),
	}, "."))
	verifier := &HMACTokenVerifier{
		Secret:    secret,
		Hostnames: hosts,
		Now:       func() time.Time { return now },
	}
	if _, err := verifier.VerifyTunnelToken(context.Background(), token, hosts); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized (future issued-at)", err)
	}
}

func TestHMACTokenTimingBoundariesAreDeterministic(t *testing.T) {
	secret := []byte("secret")
	hosts := []string{"home.relay.test"}
	now := time.Unix(1_900_000_000, 0)
	cases := []struct {
		name      string
		issuedAt  time.Time
		expiresAt time.Time
		wantErr   bool
	}{
		{"issued exactly now", now, now.Add(time.Second), false},
		{"issued at the skew leeway", now.Add(MaxIssuedAtSkew), now.Add(MaxIssuedAtSkew + time.Minute), false},
		{"one second beyond the skew leeway", now.Add(MaxIssuedAtSkew + time.Second), now.Add(MaxIssuedAtSkew + time.Minute), true},
		{"one second before expiry", now.Add(-time.Minute), now.Add(time.Second), false},
		{"exactly at expiry", now.Add(-time.Minute), now, true},
		{"ttl exactly at ceiling", now, now.Add(MaxHMACTokenTTL), false},
		{"ttl one second above ceiling", now, now.Add(MaxHMACTokenTTL + time.Second), true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nonce := fmt.Sprintf("%032x", i)
			token := []byte(strings.Join([]string{
				hmacTokenV2Prefix,
				strconv.FormatInt(tc.issuedAt.Unix(), 10),
				strconv.FormatInt(tc.expiresAt.Unix(), 10),
				nonce,
				macV2(secret, hosts, tc.issuedAt, tc.expiresAt, nonce),
			}, "."))
			verifier := &HMACTokenVerifier{
				Secret:     secret,
				Hostnames:  hosts,
				Now:        func() time.Time { return now },
				NonceStore: &hmacReplayGuard{},
			}
			got, err := verifier.VerifyTunnelToken(context.Background(), token, hosts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("verify timing err = %v, wantErr %t", err, tc.wantErr)
			}
			if err == nil && !got.ExpiresAt.Equal(tc.expiresAt) {
				t.Fatalf("verified expiry = %v, want %v", got.ExpiresAt, tc.expiresAt)
			}
		})
	}
}

// TestHMACTokenIssuedAtSkew pins the v2 issued_at leeway: a token minted by a
// clock up to MaxIssuedAtSkew ahead of the relay verifies, one further ahead is
// rejected as not yet valid, and expires_at gets no leeway.
func TestHMACTokenIssuedAtSkew(t *testing.T) {
	secret := []byte("secret")
	hosts := []string{"home.relay.test"}
	now := time.Unix(1_900_000_000, 0)
	cases := []struct {
		name      string
		issuedAt  time.Time
		expiresAt time.Time
		wantErr   string
	}{
		{"issued 30s in the future", now.Add(30 * time.Second), now.Add(90 * time.Second), ""},
		{"issued 120s in the future", now.Add(120 * time.Second), now.Add(180 * time.Second), ErrUnauthorized.Error() + ": token not yet valid"},
		{"expired one second ago", now.Add(-time.Minute), now.Add(-time.Second), ErrUnauthorized.Error() + ": token expired"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nonce := fmt.Sprintf("%032x", i)
			token := []byte(strings.Join([]string{
				hmacTokenV2Prefix,
				strconv.FormatInt(tc.issuedAt.Unix(), 10),
				strconv.FormatInt(tc.expiresAt.Unix(), 10),
				nonce,
				macV2(secret, hosts, tc.issuedAt, tc.expiresAt, nonce),
			}, "."))
			verifier := &HMACTokenVerifier{
				Secret:     secret,
				Hostnames:  hosts,
				Now:        func() time.Time { return now },
				NonceStore: &hmacReplayGuard{},
			}
			_, err := verifier.VerifyTunnelToken(context.Background(), token, hosts)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("verify err = %v, want accepted", err)
			}
			if tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr) {
				t.Fatalf("verify err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestHMACTokenVerifierFailsClosedWithoutReplayAuthority(t *testing.T) {
	secret := []byte("secret")
	hosts := []string{"home.relay.test"}
	token, err := MintHMACTunnelToken(secret, hosts, time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	verifier := &HMACTokenVerifier{Secret: secret, Hostnames: hosts}
	if err := verifier.Validate(); err == nil || !strings.Contains(err.Error(), "nonce store") {
		t.Fatalf("missing replay authority validation err = %v, want nonce-store error", err)
	}
	if _, err := verifier.VerifyTunnelToken(context.Background(), token, hosts); err == nil || !strings.Contains(err.Error(), "replay authority") {
		t.Fatalf("missing replay authority verification err = %v, want fail-closed error", err)
	}
	verifier.NonceStore = unavailableHMACNonceStore{}
	if _, err := verifier.VerifyTunnelToken(context.Background(), token, hosts); err == nil || !strings.Contains(err.Error(), "replay authority unavailable") {
		t.Fatalf("unavailable replay authority verification err = %v, want fail-closed error", err)
	}
}

// TestHMACTokenVerifierRejectsReplayedV2Token pins replay protection: the same
// still-valid token presented a second time to the same verifier is refused, even
// though it is otherwise well-formed and unexpired.
func TestHMACTokenVerifierRejectsReplayedV2Token(t *testing.T) {
	secret := []byte("secret")
	verifier := &HMACTokenVerifier{
		Secret:     secret,
		Hostnames:  []string{"home.relay.test"},
		NonceStore: &hmacReplayGuard{},
	}
	token, err := MintHMACTunnelToken(secret, []string{"home.relay.test"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := verifier.VerifyTunnelToken(context.Background(), token, []string{"home.relay.test"}); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if _, err := verifier.VerifyTunnelToken(context.Background(), token, []string{"home.relay.test"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized (replay)", err)
	}
}

// TestHMACTokenVerifierSharedNonceStoreRejectsCrossInstanceReplay pins the
// multi-instance seam: two otherwise-independent verifiers using one atomic
// nonce store share replay state.
func TestHMACTokenVerifierSharedNonceStoreRejectsCrossInstanceReplay(t *testing.T) {
	secret := []byte("secret")
	shared := &hmacReplayGuard{}
	newVerifier := func() *HMACTokenVerifier {
		return &HMACTokenVerifier{
			Secret:     secret,
			Hostnames:  []string{"home.relay.test"},
			NonceStore: shared,
		}
	}
	token, err := MintHMACTunnelToken(secret, []string{"home.relay.test"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := newVerifier().VerifyTunnelToken(context.Background(), token, []string{"home.relay.test"}); err != nil {
		t.Fatalf("first instance verify failed: %v", err)
	}
	if _, err := newVerifier().VerifyTunnelToken(context.Background(), token, []string{"home.relay.test"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("second instance err = %v, want ErrUnauthorized (shared-store replay)", err)
	}
}

func TestHMACReplayGuardFullCapacityNeverEvictsLiveNonce(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(time.Minute)
	guard := &hmacReplayGuard{nonces: make(map[string]time.Time, DefaultNonceStoreCapacity)}
	for i := 0; i < DefaultNonceStoreCapacity; i++ {
		guard.nonces[strconv.Itoa(i)] = expiresAt
	}
	protected := "0"
	admitted, err := guard.Admit(context.Background(), "overflow", expiresAt, now)
	if admitted || err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("overflow admission = %t, %v; want false, full error", admitted, err)
	}
	if got := guard.nonces[protected]; !got.Equal(expiresAt) {
		t.Fatalf("live nonce was evicted at capacity: expiry = %v", got)
	}
	if admitted, err := guard.Admit(context.Background(), protected, expiresAt, now); admitted || err != nil {
		t.Fatalf("protected replay = %t, %v; want false, nil", admitted, err)
	}
}

// TestHMACTokenVerifierRejectsTamperedV2Token pins that any edit to a v2 token's
// signed fields breaks the MAC. Flipping a byte in the nonce is representative.
func TestHMACTokenVerifierRejectsTamperedV2Token(t *testing.T) {
	secret := []byte("secret")
	verifier := &HMACTokenVerifier{
		Secret:    secret,
		Hostnames: []string{"home.relay.test"},
	}
	token, err := MintHMACTunnelToken(secret, []string{"home.relay.test"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	tampered := []byte(strings.Replace(string(token), "v2.", "v2.9", 1))
	if _, err := verifier.VerifyTunnelToken(context.Background(), tampered, []string{"home.relay.test"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized (tampered)", err)
	}
	// A token minted under a different secret must not verify either.
	otherToken, err := MintHMACTunnelToken([]byte("other-secret"), []string{"home.relay.test"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("mint other: %v", err)
	}
	if _, err := verifier.VerifyTunnelToken(context.Background(), otherToken, []string{"home.relay.test"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized (wrong secret)", err)
	}
}

// TestHMACTokenVerifierRejectsV2WrongHost pins that the hostname set is bound into
// the MAC: a v2 token minted for one host does not verify against another.
func TestHMACTokenVerifierRejectsV2WrongHost(t *testing.T) {
	secret := []byte("secret")
	verifier := &HMACTokenVerifier{
		Secret:    secret,
		Hostnames: []string{"home.relay.test"},
	}
	token, err := MintHMACTunnelToken(secret, []string{"other.relay.test"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := verifier.VerifyTunnelToken(context.Background(), token, []string{"other.relay.test"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized (wrong host)", err)
	}
}

// TestHMACTokenVerifierAcceptsAnyHostnameOrder pins order-insensitivity: mint
// and verify both MAC over the sorted hostname set, so a carrier hello may list
// its hostnames in any order (previously a reversed-order request was rejected
// unauthorized). Covers v1 and v2 formats.
func TestHMACTokenVerifierAcceptsAnyHostnameOrder(t *testing.T) {
	secret := []byte("secret")
	hosts := []string{"a.relay.test", "b.relay.test"}
	reversed := []string{"b.relay.test", "a.relay.test"}
	verifier := &HMACTokenVerifier{
		Secret:         secret,
		Hostnames:      hosts,
		AcceptLegacyV1: true,
		NonceStore:     &hmacReplayGuard{},
	}
	v2, err := MintHMACTunnelToken(secret, hosts, 5*time.Minute)
	if err != nil {
		t.Fatalf("mint v2: %v", err)
	}
	if _, err := verifier.VerifyTunnelToken(context.Background(), v2, reversed); err != nil {
		t.Fatalf("verify v2 with reversed hostname order: %v", err)
	}
	v1 := MintHMACTestToken(secret, hosts)
	if _, err := verifier.VerifyTunnelToken(context.Background(), v1, reversed); err != nil {
		t.Fatalf("verify v1 with reversed hostname order: %v", err)
	}
}
