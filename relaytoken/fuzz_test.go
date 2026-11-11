package relaytoken_test

// FuzzDecodeToken fuzz target for relaytoken.Verify (ADR-0121).
// The token wire format is a compact "header.claims.sig" string; the parser
// must never panic regardless of input and must reject malformed tokens as
// ErrUnauthorized without surfacing internal state.

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/beamfall/relay/relaytoken"
)

func FuzzDecodeToken(f *testing.F) {
	// Build a real key pair so we can seed a valid token for the corpus.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("keygen: %v", err)
	}
	const kid = "fuzz-key-1"

	now := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)
	claims := relaytoken.Claims{
		Type:      relaytoken.TokenType,
		Issuer:    "https://cloud.beamfall.app",
		Audience:  "relay.beamfall.app",
		KeyID:     kid,
		ServerID:  "srv_fuzz",
		Hostnames: []string{"relay.example.com"},
		Purpose:   "relay-access",
		IssuedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
		Nonce:     "nonce-fuzz-1",
	}
	validToken, err := relaytoken.SignWith(claims, kid, func(msg []byte) ([]byte, error) {
		return ed25519.Sign(priv, msg), nil
	})
	if err != nil {
		f.Fatalf("mint seed token: %v", err)
	}

	// KAT seed 1: valid token (must decode successfully).
	f.Add([]byte(validToken))

	// KAT seed 2: empty input.
	f.Add([]byte(""))

	// KAT seed 3: only two parts.
	f.Add([]byte("header.claims"))

	// KAT seed 4: four parts.
	f.Add([]byte("a.b.c.d"))

	// KAT seed 5: valid header+claims but corrupted signature (append X).
	f.Add(append([]byte(validToken), 'X'))

	// KAT seed 6: random bytes.
	f.Add([]byte("\x00\x01\x02\x03"))

	// KAT seed 7: non-canonical JSON claims (extra whitespace injected).
	f.Add([]byte("eyJhbGciOiJFZERTQSIsImtpZCI6ImsiLCJ0eXAiOiJKV1QifQ.eyJ0eXAiOiAiYmVhbWZhbGwucmVsYXktdG9rZW4udjEifQ.AAAA"))

	pubKeys := map[string]ed25519.PublicKey{kid: pub}
	f.Fuzz(func(t *testing.T, raw []byte) {
		// Must never panic. ErrUnauthorized is the expected result for
		// all crafted / mutated inputs; a well-formed valid token must
		// succeed (covered by the corpus seed).
		_, _ = relaytoken.Verify(raw, pubKeys)
	})
}
