package relaytoken_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"github.com/beamfall/relay/relaytoken"
)

// TestMintToVerifyRoundTrip is the ORG-14 acceptance test: a token minted with
// the cloud minter's signing path (SignWith + a custody-seam sign func) is
// accepted by the relay verifier's path (Verify), and the single Claims struct
// survives the wire byte-exact. This module is kept byte-for-byte compatible
// with Cloud's independently owned in-tree copy, so this is Relay's
// authoritative mint-to-verify parity proof.
func TestMintToVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "relay-2026-06"

	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	want := relaytoken.Claims{
		Type:       relaytoken.TokenType,
		Issuer:     "https://cloud.beamfall.app",
		Audience:   "relay.beamfall.app",
		KeyID:      kid,
		ServerID:   "srv_abc",
		Hostnames:  []string{"a.example.com", "b.example.com"},
		NodeRegion: "us-east-1",
		Purpose:    "tunnel-connect",
		IssuedAt:   now,
		ExpiresAt:  now.Add(10 * time.Minute),
		Nonce:      "nonce-xyz",
	}

	// Mint: the sign func stands in for cloud's RV-CLOUD-003 Signer.Sign — the
	// private key stays behind the closure, never passed into relaytoken.
	tok, err := relaytoken.SignWith(want, kid, func(b []byte) ([]byte, error) {
		return ed25519.Sign(priv, b), nil
	})
	if err != nil {
		t.Fatalf("SignWith: %v", err)
	}

	// Verify: relay's verifier path, selecting the key by header kid.
	got, err := relaytoken.Verify([]byte(tok), map[string]ed25519.PublicKey{kid: pub})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("timestamps did not round-trip: got iat=%v exp=%v", got.IssuedAt, got.ExpiresAt)
	}
	// Normalize the monotonic-clock/location difference JSON RFC3339 erases, then
	// compare the whole struct field-for-field.
	want.IssuedAt = want.IssuedAt.UTC()
	want.ExpiresAt = want.ExpiresAt.UTC()
	got.IssuedAt = got.IssuedAt.UTC()
	got.ExpiresAt = got.ExpiresAt.UTC()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("claims did not round-trip:\n got=%+v\nwant=%+v", got, want)
	}
}

// TestVerifyRejectsWrongKey confirms a token signed by one key is rejected when
// verified against a different public key (signature check intact).
func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	const kid = "k1"

	now := time.Now()
	tok, err := relaytoken.SignWith(relaytoken.Claims{
		Type: relaytoken.TokenType, Issuer: "i", Audience: "a", KeyID: kid,
		ServerID: "s", Hostnames: []string{"h"},
		Purpose: "tunnel-connect", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		Nonce: "n",
	}, kid, func(b []byte) ([]byte, error) { return ed25519.Sign(priv, b), nil })
	if err != nil {
		t.Fatalf("SignWith: %v", err)
	}
	if _, err := relaytoken.Verify([]byte(tok), map[string]ed25519.PublicKey{kid: otherPub}); err == nil {
		t.Fatal("Verify accepted a token signed by a different key")
	}
}

// TestVerifyRejectsKidMismatch confirms the header.KeyID == claims.KeyID
// integrity check (preserved from relay's verifier) still rejects a token whose
// header kid and claims kid disagree.
func TestVerifyRejectsKidMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	// Sign with header kid "hdr" but claims kid "body" — Verify must reject.
	claims := relaytoken.Claims{
		Type: relaytoken.TokenType, Issuer: "i", Audience: "a", KeyID: "body",
		ServerID: "s", Hostnames: []string{"h"},
		Purpose: "tunnel-connect", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		Nonce: "n",
	}
	tok, err := relaytoken.SignWith(claims, "hdr", func(b []byte) ([]byte, error) {
		return ed25519.Sign(priv, b), nil
	})
	if err != nil {
		t.Fatalf("SignWith: %v", err)
	}
	if _, err := relaytoken.Verify([]byte(tok), map[string]ed25519.PublicKey{"hdr": pub}); err == nil {
		t.Fatal("Verify accepted a token with header.kid != claims.kid")
	}
}
