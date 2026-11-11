// Package relaytoken owns the hosted-relay token schema (ORG-14 / UF-3). The
// relay-token claims struct and its on-the-wire encoding are shared by
// beamfall-cloud (the minter) and beamfall-relay (the verifier).
//
// It is kept as a private, zero-dependency module nested in the relay
// repository. Relay resolves it only through the root module's in-tree replace,
// without a network fetch or the private cloud source tree.
//
// Scope is the schema and its wire encoding ONLY: the Claims struct, the token
// type string, the JWT/EdDSA header, the canonical-JSON encoding, and the
// signature/type/canonical-re-encode checks. POLICY — expiry, issuer, audience,
// purpose, nonce/replay, revocation — stays with each caller, unchanged. This is
// a de-duplication refactor: the wire format, claims, TTL semantics, and signing
// are preserved exactly.
package relaytoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

// TokenType is the `typ` claim every hosted-relay token carries.
const TokenType = "beamfall.relay-token.v1"

// ErrUnauthorized is returned when a token fails any structural, signature, or
// canonical-encoding check. Callers map it to their own transport error.
var ErrUnauthorized = errors.New("relay token unauthorized")

// Claims is the single definition of the hosted-relay token claim set. The JSON
// tags are load-bearing: they define the wire format, so they must not change
// without updating both the cloud minter and relay verifier. Account identifiers
// are deliberately absent: the relay receives only the opaque carrier ServerID.
type Claims struct {
	Type       string   `json:"typ"`
	Issuer     string   `json:"iss"`
	Audience   string   `json:"aud"`
	KeyID      string   `json:"kid"`
	ServerID   string   `json:"server_id"`
	Hostnames  []string `json:"hostnames"`
	NodeRegion string   `json:"node_region,omitempty"`
	Purpose    string   `json:"purpose"`
	// TraceCorrelationID is a bounded, non-secret observability join key for the
	// cloud mint span and relay carrier-handshake span. It is never an account,
	// carrier, hostname, token, or payload identifier.
	TraceCorrelationID string    `json:"trace_correlation_id,omitempty"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	Nonce              string    `json:"nonce"`
}

// header is the JWT/EdDSA header. The three fields and their fixed values are
// part of the wire contract.
type header struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// SignWith builds the canonical signing input (header + canonical-JSON claims),
// signs it with the supplied sign func, and returns the compact token string.
//
// The sign func is the custody seam (RV-CLOUD-003): the private key is never
// passed in, so cloud's KMS/sealed-file Signer keeps key custody. The caller
// stamps kid into both the header and claims (matching the verifier's
// header.KeyID == claims.KeyID check). SignWith performs NO policy validation —
// the caller validates the claims before signing (cloud does so via
// validateRelayClaims).
func SignWith(claims Claims, kid string, sign func([]byte) ([]byte, error)) (string, error) {
	h := header{Algorithm: "EdDSA", KeyID: kid, Type: "JWT"}
	headerJSON, err := canonicalJSON(h)
	if err != nil {
		return "", err
	}
	claimsJSON, err := canonicalJSON(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(headerJSON) + "." + b64(claimsJSON)
	sig, err := sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
}

// Verify checks a compact token's structure, EdDSA signature, canonical-JSON
// re-encoding, token type, and the header.KeyID == claims.KeyID integrity check,
// then returns the decoded Claims. It does NOT enforce expiry, issuer, audience,
// purpose, or nonce — those are the caller's policy. The public key is selected
// by the header `kid` from pubKeys.
func Verify(raw []byte, pubKeys map[string]ed25519.PublicKey) (Claims, error) {
	parts := splitThree(raw)
	if parts == nil {
		return Claims{}, ErrUnauthorized
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrUnauthorized
	}
	var h header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return Claims{}, ErrUnauthorized
	}
	if h.Algorithm != "EdDSA" || h.Type != "JWT" || h.KeyID == "" {
		return Claims{}, ErrUnauthorized
	}
	pub, ok := pubKeys[h.KeyID]
	if !ok {
		return Claims{}, ErrUnauthorized
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(signingInput), sig) {
		return Claims{}, ErrUnauthorized
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrUnauthorized
	}
	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return Claims{}, ErrUnauthorized
	}
	encoded, err := canonicalJSON(claims)
	if err != nil || b64(encoded) != parts[1] {
		return Claims{}, ErrUnauthorized
	}
	if h.KeyID != claims.KeyID {
		return Claims{}, ErrUnauthorized
	}
	if claims.Type != TokenType {
		return Claims{}, ErrUnauthorized
	}
	return claims, nil
}

// splitThree splits a compact "h.c.s" token into exactly three parts, or returns
// nil. It avoids strings.Split allocations on the hot verify path while keeping
// the exact len==3 semantics both repos relied on.
func splitThree(raw []byte) []string {
	s := string(raw)
	first := -1
	second := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			if first == -1 {
				first = i
			} else if second == -1 {
				second = i
			} else {
				return nil // more than two dots
			}
		}
	}
	if first == -1 || second == -1 {
		return nil
	}
	return []string{s[:first], s[first+1 : second], s[second+1:]}
}

func canonicalJSON(v any) ([]byte, error) {
	var normalized any
	bytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(bytes, &normalized); err != nil {
		return nil, err
	}
	return marshalCanonical(normalized)
}

func marshalCanonical(v any) ([]byte, error) {
	switch value := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, key := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			keyBytes, _ := json.Marshal(key)
			out = append(out, keyBytes...)
			out = append(out, ':')
			child, err := marshalCanonical(value[key])
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
		}
		out = append(out, '}')
		return out, nil
	case []any:
		out := []byte{'['}
		for i, item := range value {
			if i > 0 {
				out = append(out, ',')
			}
			child, err := marshalCanonical(item)
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
		}
		out = append(out, ']')
		return out, nil
	default:
		return json.Marshal(value)
	}
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
