package relay

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fuzzHMACClock is the fixed "now" used by FuzzHMACVerifyV2's verifier. It must sit
// inside the "valid" seed's ttl window (below) and under MaxHMACTokenTTL so that a
// well-formed, correctly-MAC'd token actually reaches the property assertions in
// f.Fuzz instead of being rejected earlier by the ttl-cap/expiry checks — otherwise
// the assertions are dead code no matter what the verifier does with the MAC.
var fuzzHMACClock = time.Now().Add(2 * time.Minute)

// FuzzHMACVerifyV2 fuzzes HMACTokenVerifier's v2 token path (isHMACV2 / verifyV2 /
// parseV2Times): hex fields, "."-separated, with a NUL-separated MAC input. The
// verifier is fixed (static secret, fixed clock, fixed hostname set) per call so
// only the token bytes vary; a fresh verifier is used each iteration so the
// replay-nonce cache doesn't reject seeds across runs.
func FuzzHMACVerifyV2(f *testing.F) {
	secret := []byte("fuzz-hmac-secret")
	hosts := []string{"home.relay.test"}

	// ttl must stay under MaxHMACTokenTTL (5m) and land after fuzzHMACClock (now+2m)
	// so this seed clears every check in verifyV2 and actually reaches the property
	// assertions below.
	valid, err := MintHMACTunnelToken(secret, hosts, 4*time.Minute)
	if err != nil {
		f.Fatalf("mint valid v2 token: %v", err)
	}
	f.Add(valid)

	expired, err := MintHMACTunnelToken(secret, hosts, time.Minute)
	if err != nil {
		f.Fatalf("mint expired v2 token: %v", err)
	}
	f.Add(expired)

	f.Add(valid[:len(valid)/2]) // truncated

	f.Add([]byte("v2.100.200.abcd")) // wrong field count (4, want 5)

	f.Add([]byte("v2.100.200.zzzz.gggg")) // non-hex nonce/MAC

	f.Add(MintHMACTestToken(secret, hosts)) // v1-style bare hex token

	f.Add([]byte{})
	f.Add([]byte("v2."))

	f.Fuzz(func(t *testing.T, token []byte) {
		verifier := &HMACTokenVerifier{
			Secret:     secret,
			Hostnames:  hosts,
			Now:        func() time.Time { return fuzzHMACClock },
			NonceStore: &hmacReplayGuard{},
		}
		got, err := verifier.VerifyTunnelToken(context.Background(), token, hosts)
		if err != nil {
			return
		}
		// A token that verifies must equal a canonically minted one for this clock:
		// re-minting with the same secret/hosts/ttl-implied-expiry and checking the
		// verifier accepts its own mint is the cheap oracle available here (the nonce
		// and issued-at are attacker/fuzzer-chosen, so we can't byte-compare against a
		// single canonical token). Instead, assert internal consistency: the verified
		// carrier's hostnames must be exactly the fixed set, and its expiry must be
		// strictly after the fixed clock (verifyV2 already checked this, but a fuzz
		// property should not just trust the code under test).
		if len(got.Hostnames) != len(hosts) {
			t.Fatalf("verified carrier hostnames = %v, want %v", got.Hostnames, hosts)
		}
		for i, h := range hosts {
			if got.Hostnames[i] != h {
				t.Fatalf("verified carrier hostnames = %v, want %v", got.Hostnames, hosts)
			}
		}
		if !got.ExpiresAt.After(fuzzHMACClock) {
			t.Fatalf("verified token expiry %v is not after fixed clock", got.ExpiresAt)
		}
		// A token that was just ACCEPTED must be rejected as replayed if presented
		// again to the SAME verifier: its nonce store admits a given nonce exactly
		// once. This in-iteration double-verify (same verifier, same token) is the
		// only way this corpus can ever reach the "token replayed" branch, since
		// every seed/mutation otherwise runs against a fresh verifier (with an empty
		// nonce store) by design, so cross-seed replay never fires.
		if _, err := verifier.VerifyTunnelToken(context.Background(), token, hosts); err == nil {
			t.Fatalf("verifier accepted replayed token %q on second presentation", token)
		} else if !strings.Contains(err.Error(), "token replayed") {
			t.Fatalf("replayed token %q rejected with unexpected error: %v", token, err)
		}
		// The properties above never actually depend on the MAC being checked (hostnames
		// come from the request parameter, not the token; expiry comes from the token's
		// own claimed field), so they cannot by themselves catch a verifier that accepts
		// tokens without checking the signature. Close that gap directly: an ACCEPTED
		// v2 token, with one bit flipped anywhere in its MAC field, must be REJECTED by
		// a fresh verifier under the identical secret/clock — otherwise the MAC isn't
		// actually being enforced.
		fields := strings.Split(string(token), ".")
		if len(fields) == hmacTokenV2Parts && len(fields[4]) > 0 {
			mutated := append([]byte(nil), token...)
			mutated[len(mutated)-1] ^= 0x01
			fresh := &HMACTokenVerifier{
				Secret:     secret,
				Hostnames:  hosts,
				Now:        func() time.Time { return fuzzHMACClock },
				NonceStore: &hmacReplayGuard{},
			}
			if _, err := fresh.VerifyTunnelToken(context.Background(), mutated, hosts); err == nil {
				t.Fatalf("verifier accepted token %q after flipping a bit in its MAC field", mutated)
			}
		}
	})
}
