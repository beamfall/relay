package relay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// hmacTokenV2VectorsPath is the committed contract that cmd/gen-vectors mints
// from the PROTOCOL.md "Carrier token v2" text, independently of this package.
var hmacTokenV2VectorsPath = filepath.Join("..", "..", "contracts", "protocol", "v1", "hmac-token-v2-vectors.json")

type hmacTokenV2VectorFile struct {
	SchemaVersion    int                 `json:"schema_version"`
	SharedKeyUTF8    string              `json:"shared_key_utf8"`
	AllowedHostnames []string            `json:"allowed_hostnames"`
	MaxTTLSeconds    int64               `json:"max_ttl_seconds"`
	Vectors          []hmacTokenV2Vector `json:"vectors"`
}

type hmacTokenV2Vector struct {
	Name               string   `json:"name"`
	MintHostnames      []string `json:"mint_hostnames"`
	IssuedAtUnix       int64    `json:"issued_at_unix"`
	ExpiresAtUnix      int64    `json:"expires_at_unix"`
	NonceHex           string   `json:"nonce_hex"`
	MACInputHex        string   `json:"mac_input_hex"`
	MACHex             string   `json:"mac_hex"`
	TokenText          string   `json:"token_text"`
	RequestedHostnames []string `json:"requested_hostnames"`
	NowUnix            int64    `json:"now_unix"`
	ReplayOf           string   `json:"replay_of"`
	Verdict            string   `json:"verdict"`
	Reason             string   `json:"reason"`
	AcceptedHostnames  []string `json:"accepted_hostnames"`
}

// requiredHMACTokenV2Vectors are the cases RELAY-HMAC-V2-TOKEN-SPEC-VECTORS-1
// and RELAY-PROD-TOKEN-CLOCK-TOLERANCE-1 require the published contract to carry.
var requiredHMACTokenV2Vectors = []string{
	"accept_single_host",
	"accept_multi_host",
	"accept_mixed_case_host",
	"accept_trailing_dot_host",
	"reject_expired",
	"reject_ttl_over_cap",
	"accept_issued_at_within_leeway",
	"reject_issued_at_in_future",
	"reject_bad_mac",
	"reject_replayed_nonce",
	"reject_host_not_allowed",
}

func loadHMACTokenV2Vectors(t *testing.T) hmacTokenV2VectorFile {
	t.Helper()
	raw, err := os.ReadFile(hmacTokenV2VectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file hmacTokenV2VectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return file
}

// TestHMACTokenV2VectorsMatchVerifier replays every published vector through the
// verifier relayd builds in hmac mode (strict v2, file-backed nonce store) and
// requires the vector's verdict, reject reason and accepted hostnames.
func TestHMACTokenV2VectorsMatchVerifier(t *testing.T) {
	file := loadHMACTokenV2Vectors(t)
	byName := make(map[string]hmacTokenV2Vector, len(file.Vectors))
	for _, vec := range file.Vectors {
		byName[vec.Name] = vec
	}
	for _, vec := range file.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			verifier := newHMACTokenV2VectorVerifier(t, file, vec.NowUnix)
			ctx := context.Background()
			if vec.ReplayOf != "" {
				first := byName[vec.ReplayOf]
				if _, err := verifier.VerifyTunnelToken(ctx, []byte(first.TokenText), first.RequestedHostnames); err != nil {
					t.Fatalf("first presentation of %s rejected: %v", vec.ReplayOf, err)
				}
			}
			got, err := verifier.VerifyTunnelToken(ctx, []byte(vec.TokenText), vec.RequestedHostnames)
			assertHMACTokenV2Verdict(t, vec, got, err)
		})
	}
}

func newHMACTokenV2VectorVerifier(t *testing.T, file hmacTokenV2VectorFile, nowUnix int64) *HMACTokenVerifier {
	t.Helper()
	store, err := NewFileHMACNonceStore(filepath.Join(t.TempDir(), "hmac-nonces.json"))
	if err != nil {
		t.Fatalf("nonce store: %v", err)
	}
	return &HMACTokenVerifier{
		Secret:     []byte(file.SharedKeyUTF8),
		Hostnames:  file.AllowedHostnames,
		Now:        func() time.Time { return time.Unix(nowUnix, 0) },
		NonceStore: store,
	}
}

func assertHMACTokenV2Verdict(t *testing.T, vec hmacTokenV2Vector, got VerifiedCarrier, err error) {
	t.Helper()
	switch vec.Verdict {
	case "accept":
		if err != nil {
			t.Fatalf("verdict accept, verifier rejected: %v", err)
		}
		if !slices.Equal(got.Hostnames, vec.AcceptedHostnames) {
			t.Fatalf("accepted hostnames = %q, want %q", got.Hostnames, vec.AcceptedHostnames)
		}
		if got.ID != vec.AcceptedHostnames[0] {
			t.Fatalf("carrier id = %q, want first accepted hostname %q", got.ID, vec.AcceptedHostnames[0])
		}
		if got.ExpiresAt.Unix() != vec.ExpiresAtUnix {
			t.Fatalf("expires at = %d, want %d", got.ExpiresAt.Unix(), vec.ExpiresAtUnix)
		}
	case "reject":
		want, ok := hmacTokenV2RejectError(vec)
		if !ok {
			t.Fatalf("unknown reject reason %q", vec.Reason)
		}
		if err == nil {
			t.Fatalf("verdict reject (%s), verifier accepted %+v", vec.Reason, got)
		}
		if !errors.Is(err, ErrUnauthorized) || err.Error() != want {
			t.Fatalf("reject reason %s: verifier error %q, want %q", vec.Reason, err, want)
		}
	default:
		t.Fatalf("unknown verdict %q", vec.Verdict)
	}
}

// hmacTokenV2RejectError is the exact error text the live verifier returns for
// a vector's reject reason. A MAC mismatch returns ErrUnauthorized itself.
func hmacTokenV2RejectError(vec hmacTokenV2Vector) (string, bool) {
	details := map[string]string{
		"bad_mac":          "",
		"expired":          ": token expired",
		"ttl_exceeds_cap":  ": token ttl exceeds " + MaxHMACTokenTTL.String(),
		"issued_in_future": ": token not yet valid",
		"replayed_nonce":   ": token replayed",
		"host_not_allowed": fmt.Sprintf(": hostname %q not allowed", normalizeHost(vec.RequestedHostnames[0])),
	}
	detail, ok := details[vec.Reason]
	return ErrUnauthorized.Error() + detail, ok
}

// TestHMACTokenV2VectorsMACLayout checks that each vector's MAC fields describe
// the relay's own MAC: mac_input_hex is the byte string the relay authenticates
// and mac_hex is its HMAC-SHA256 under the published fixture key.
func TestHMACTokenV2VectorsMACLayout(t *testing.T) {
	file := loadHMACTokenV2Vectors(t)
	key := []byte(file.SharedKeyUTF8)
	for _, vec := range file.Vectors {
		relayMAC := macV2(key, sortNormalizedHosts(vec.MintHostnames), time.Unix(vec.IssuedAtUnix, 0), time.Unix(vec.ExpiresAtUnix, 0), vec.NonceHex)
		if relayMAC != vec.MACHex {
			t.Errorf("%s: relay MAC %s, vector mac_hex %s", vec.Name, relayMAC, vec.MACHex)
		}
		input, err := hex.DecodeString(vec.MACInputHex)
		if err != nil {
			t.Fatalf("%s: mac_input_hex: %v", vec.Name, err)
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(input)
		if got := hex.EncodeToString(mac.Sum(nil)); got != relayMAC {
			t.Errorf("%s: HMAC over mac_input_hex = %s, relay MAC %s", vec.Name, got, relayMAC)
		}
	}
}

// TestHMACTokenV2VectorsCoverContract pins the published file's shape to the
// relay: required cases present, fixture key strong enough for relayd, and the
// TTL cap equal to MaxHMACTokenTTL.
func TestHMACTokenV2VectorsCoverContract(t *testing.T) {
	file := loadHMACTokenV2Vectors(t)
	if file.SchemaVersion != 1 {
		t.Fatalf("schema_version = %d, want 1", file.SchemaVersion)
	}
	if time.Duration(file.MaxTTLSeconds)*time.Second != MaxHMACTokenTTL {
		t.Fatalf("max_ttl_seconds = %d, relay cap %s", file.MaxTTLSeconds, MaxHMACTokenTTL)
	}
	if err := ValidateTokenStrength([]byte(file.SharedKeyUTF8)); err != nil {
		t.Fatalf("fixture key fails relayd strength rule: %v", err)
	}
	names := make([]string, 0, len(file.Vectors))
	for _, vec := range file.Vectors {
		names = append(names, vec.Name)
	}
	for _, name := range requiredHMACTokenV2Vectors {
		if !slices.Contains(names, name) {
			t.Errorf("vector %s missing", name)
		}
	}
}
