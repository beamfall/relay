package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The hmac-token-v2 set is minted here from the PROTOCOL.md "Carrier token v2"
// text, independently of internal/relay, so the relay's replay of this file
// (internal/relay TestHMACTokenV2VectorsMatchVerifier) checks the specification
// against the live verifier rather than the verifier against itself.
//
// Every input is fixed: the shared secret, the relay's clock, the allowed
// hostname set, and the per-vector nonces. The secret is a published fixture
// that satisfies relayd's secret-strength rule; it is not a deployable value.
const (
	hmacV2SharedKey     = "beamfall-relay-hmac-token-v2-golden-vector-fixture-0123456789"
	hmacV2ClockUnix     = int64(1790000000) // 2026-09-21T14:13:20Z, the relay's "now"
	hmacV2MaxTTLSeconds = int64(300)
	hmacV2NonceBytes    = 16
)

var hmacV2AllowedHostnames = []string{"home.relay.example", "media.relay.example"}

// hmacTokenV2File mirrors contracts/protocol/v1/hmac-token-v2-vectors.json.
type hmacTokenV2File struct {
	SchemaVersion    int                 `json:"schema_version"`
	GeneratedBy      string              `json:"generated_by"`
	Spec             string              `json:"spec"`
	SharedKeyUTF8    string              `json:"shared_key_utf8"`
	AllowedHostnames []string            `json:"allowed_hostnames"`
	MaxTTLSeconds    int64               `json:"max_ttl_seconds"`
	Vectors          []hmacTokenV2Vector `json:"vectors"`
}

// hmacTokenV2Vector is one mint-and-verify case. The mint fields are the minter's
// inputs; mac_input_hex and mac_hex are the exact HMAC-SHA256 input and output a
// conforming minter derives from them. token_text is what the carrier presents
// in its hello (it differs from the minted claim only where description says
// so). The relay verifies token_text for requested_hostnames at now_unix with a
// fresh nonce store, after first admitting the token_text of replay_of when set.
type hmacTokenV2Vector struct {
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	MintHostnames      []string `json:"mint_hostnames"`
	IssuedAtUnix       int64    `json:"issued_at_unix"`
	ExpiresAtUnix      int64    `json:"expires_at_unix"`
	NonceHex           string   `json:"nonce_hex"`
	MACInputHex        string   `json:"mac_input_hex"`
	MACHex             string   `json:"mac_hex"`
	TokenText          string   `json:"token_text"`
	RequestedHostnames []string `json:"requested_hostnames"`
	NowUnix            int64    `json:"now_unix"`
	ReplayOf           string   `json:"replay_of,omitempty"`
	Verdict            string   `json:"verdict"`
	Reason             string   `json:"reason,omitempty"`
	AcceptedHostnames  []string `json:"accepted_hostnames,omitempty"`
}

// hmacV2Case is one row of the vector table. Times are offsets in seconds from
// hmacV2ClockUnix. nonceSeed names the nonce: a replay row reuses the seed of the
// row it replays so both rows mint the identical token.
type hmacV2Case struct {
	name, description string
	mintHosts         []string
	issuedOffset, ttl int64
	nonceSeed         string
	alterMAC          bool
	requested         []string
	replayOf          string
	reason            string // empty means the relay accepts the token
}

var hmacV2Cases = []hmacV2Case{
	{
		name:        "accept_single_host",
		description: "Valid token for one allowed hostname, issued 30s before the relay clock with a 120s lifetime.",
		mintHosts:   []string{"home.relay.example"}, issuedOffset: -30, ttl: 120,
		nonceSeed: "accept_single_host", requested: []string{"home.relay.example"},
	},
	{
		name:        "accept_multi_host",
		description: "Valid token for two allowed hostnames. The MAC covers the sorted set, so the hello may list them in any order; accepted hostnames keep the hello order.",
		mintHosts:   []string{"home.relay.example", "media.relay.example"}, issuedOffset: -30, ttl: 120,
		nonceSeed: "accept_multi_host", requested: []string{"media.relay.example", "home.relay.example"},
	},
	{
		name:        "accept_mixed_case_host",
		description: "Mixed-case hostname: both sides lowercase before the MAC, so the MAC input holds the lowercase name.",
		mintHosts:   []string{"Home.Relay.EXAMPLE"}, issuedOffset: -30, ttl: 120,
		nonceSeed: "accept_mixed_case_host", requested: []string{"Home.Relay.EXAMPLE"},
	},
	{
		name:        "accept_trailing_dot_host",
		description: "Fully qualified hostname with a trailing dot and surrounding spaces: both sides trim spaces and strip one trailing dot before the MAC.",
		mintHosts:   []string{" media.relay.example. "}, issuedOffset: -30, ttl: 120,
		nonceSeed: "accept_trailing_dot_host", requested: []string{" media.relay.example. "},
	},
	{
		name:        "accept_ttl_at_cap",
		description: "Signed lifetime exactly 300s (expires_at - issued_at == max_ttl_seconds) is accepted.",
		mintHosts:   []string{"home.relay.example"}, issuedOffset: -10, ttl: 300,
		nonceSeed: "accept_ttl_at_cap", requested: []string{"home.relay.example"},
	},
	{
		name:        "accept_issued_at_now",
		description: "issued_at equal to the relay clock is accepted.",
		mintHosts:   []string{"home.relay.example"}, issuedOffset: 0, ttl: 60,
		nonceSeed: "accept_issued_at_now", requested: []string{"home.relay.example"},
	},
	{
		name:        "accept_issued_at_within_leeway",
		description: "issued_at 30s after the relay clock is accepted: the relay allows issued_at up to 60s ahead of its clock.",
		mintHosts:   []string{"home.relay.example"}, issuedOffset: 30, ttl: 60,
		nonceSeed: "accept_issued_at_within_leeway", requested: []string{"home.relay.example"},
	},
	{
		name:        "reject_expired",
		description: "Token whose expires_at is 20s before the relay clock.",
		mintHosts:   []string{"home.relay.example"}, issuedOffset: -200, ttl: 180,
		nonceSeed: "reject_expired", requested: []string{"home.relay.example"}, reason: "expired",
	},
	{
		name:        "reject_expired_at_expiry_instant",
		description: "expires_at equal to the relay clock is already expired: validity is issued_at - 60 <= now < expires_at.",
		mintHosts:   []string{"home.relay.example"}, issuedOffset: -60, ttl: 60,
		nonceSeed: "reject_expired_at_expiry_instant", requested: []string{"home.relay.example"}, reason: "expired",
	},
	{
		name:        "reject_ttl_over_cap",
		description: "Signed lifetime 301s exceeds max_ttl_seconds even though the relay clock is inside it.",
		mintHosts:   []string{"home.relay.example"}, issuedOffset: -10, ttl: 301,
		nonceSeed: "reject_ttl_over_cap", requested: []string{"home.relay.example"}, reason: "ttl_exceeds_cap",
	},
	{
		name:        "reject_issued_at_in_future",
		description: "issued_at 120s after the relay clock is beyond the 60s issued-at leeway.",
		mintHosts:   []string{"home.relay.example"}, issuedOffset: 120, ttl: 60,
		nonceSeed: "reject_issued_at_in_future", requested: []string{"home.relay.example"}, reason: "issued_in_future",
	},
	{
		name:        "reject_bad_mac",
		description: "Otherwise valid claim whose token carries mac_hex with its last hex digit altered.",
		mintHosts:   []string{"home.relay.example"}, issuedOffset: -30, ttl: 120,
		nonceSeed: "reject_bad_mac", alterMAC: true, requested: []string{"home.relay.example"}, reason: "bad_mac",
	},
	{
		name:        "reject_replayed_nonce",
		description: "The accept_single_host token presented a second time to the same nonce store: each nonce is admitted once.",
		mintHosts:   []string{"home.relay.example"}, issuedOffset: -30, ttl: 120,
		nonceSeed: "accept_single_host", requested: []string{"home.relay.example"},
		replayOf: "accept_single_host", reason: "replayed_nonce",
	},
	{
		name:        "reject_host_not_allowed",
		description: "Correctly signed token for a hostname outside the relay's allowed set.",
		mintHosts:   []string{"other.relay.example"}, issuedOffset: -30, ttl: 120,
		nonceSeed: "reject_host_not_allowed", requested: []string{"other.relay.example"}, reason: "host_not_allowed",
	},
}

func hmacTokenV2Vectors() (any, error) {
	vectors := make([]hmacTokenV2Vector, 0, len(hmacV2Cases))
	for _, c := range hmacV2Cases {
		vectors = append(vectors, buildHMACV2Vector(c))
	}
	return hmacTokenV2File{
		SchemaVersion:    1,
		GeneratedBy:      "cmd/gen-vectors (go run ./cmd/gen-vectors -set hmac-token-v2)",
		Spec:             `PROTOCOL.md, section "Carrier token v2"`,
		SharedKeyUTF8:    hmacV2SharedKey,
		AllowedHostnames: hmacV2AllowedHostnames,
		MaxTTLSeconds:    hmacV2MaxTTLSeconds,
		Vectors:          vectors,
	}, nil
}

func buildHMACV2Vector(c hmacV2Case) hmacTokenV2Vector {
	issuedAt := hmacV2ClockUnix + c.issuedOffset
	expiresAt := issuedAt + c.ttl
	nonce := hmacV2Nonce(c.nonceSeed)
	input := hmacV2MACInput(c.mintHosts, issuedAt, expiresAt, nonce)
	mac := hmacV2MAC(input)
	return hmacTokenV2Vector{
		Name:               c.name,
		Description:        c.description,
		MintHostnames:      c.mintHosts,
		IssuedAtUnix:       issuedAt,
		ExpiresAtUnix:      expiresAt,
		NonceHex:           nonce,
		MACInputHex:        hex.EncodeToString(input),
		MACHex:             mac,
		TokenText:          hmacV2Token(issuedAt, expiresAt, nonce, presentedMAC(mac, c.alterMAC)),
		RequestedHostnames: c.requested,
		NowUnix:            hmacV2ClockUnix,
		ReplayOf:           c.replayOf,
		Verdict:            hmacV2Verdict(c.reason),
		Reason:             c.reason,
		AcceptedHostnames:  acceptedHostnames(c),
	}
}

// hmacV2MACInput is "v2" NUL hosts NUL issued_at NUL expires_at NUL nonce, where
// hosts is the sorted normalized hostname set joined by LF and the times are
// canonical base-10 Unix seconds.
func hmacV2MACInput(hostnames []string, issuedAt, expiresAt int64, nonce string) []byte {
	fields := []string{
		"v2",
		strings.Join(sortedNormalizedHosts(hostnames), "\n"),
		strconv.FormatInt(issuedAt, 10),
		strconv.FormatInt(expiresAt, 10),
		nonce,
	}
	return []byte(strings.Join(fields, "\x00"))
}

func hmacV2MAC(input []byte) string {
	mac := hmac.New(sha256.New, []byte(hmacV2SharedKey))
	mac.Write(input)
	return hex.EncodeToString(mac.Sum(nil))
}

func hmacV2Token(issuedAt, expiresAt int64, nonce, mac string) string {
	return fmt.Sprintf("v2.%d.%d.%s.%s", issuedAt, expiresAt, nonce, mac)
}

// hmacV2Nonce derives a fixed, distinct 16-byte nonce per seed so the file is
// reproducible byte for byte.
func hmacV2Nonce(seed string) string {
	sum := sha256.Sum256([]byte("beamfall relay hmac-token-v2 vector nonce\x00" + seed))
	return hex.EncodeToString(sum[:hmacV2NonceBytes])
}

// presentedMAC returns mac, or mac with its last hex digit changed when alter is set.
func presentedMAC(mac string, alter bool) string {
	if !alter {
		return mac
	}
	last := "0"
	if strings.HasSuffix(mac, "0") {
		last = "1"
	}
	return mac[:len(mac)-1] + last
}

func hmacV2Verdict(reason string) string {
	if reason == "" {
		return "accept"
	}
	return "reject"
}

// acceptedHostnames is the normalized requested set, in hello order, that the
// relay registers for an accepted token; rejected tokens register nothing.
func acceptedHostnames(c hmacV2Case) []string {
	if c.reason != "" {
		return nil
	}
	hosts := make([]string, 0, len(c.requested))
	for _, host := range c.requested {
		hosts = append(hosts, normalizeHostname(host))
	}
	return hosts
}

func sortedNormalizedHosts(hostnames []string) []string {
	hosts := make([]string, 0, len(hostnames))
	for _, host := range hostnames {
		hosts = append(hosts, normalizeHostname(host))
	}
	sort.Strings(hosts)
	return hosts
}

// normalizeHostname trims surrounding white space, lowercases, then strips one
// trailing dot.
func normalizeHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
