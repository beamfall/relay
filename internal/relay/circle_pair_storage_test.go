package relay

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// ADR-0165 §5 (amending ADR-0103): rendezvous metadata falls under the
// session-log retention window and the relay stores no long-lived pairwise
// edge. A "Circle pair" is two parties' relationship (for example a Circle,
// peer, viewer/owner pair or account link). The relay has no such code today,
// so this is a storage-schema guard: every durable surface the relay owns must
// stay on an explicit allowlist of single-tunnel, opaque, expiring fields, and
// nothing may outlive its retention window.

// circlePairVocabulary lists words that name a relationship between two
// parties. A persisted field or key containing one is a pair edge.
var circlePairVocabulary = []string{
	"circle", "pair", "peer", "friend", "member", "buddy", "viewer", "owner",
	"account", "user", "device", "edge", "link", "relation", "invite", "partner",
	"from", "to", "src", "dst", "source", "target",
}

// persistedJSONKeys returns the JSON key of every field reachable from t,
// following pointers, slices, and nested structs. Map-typed fields contribute
// their own key only: the map's keys are data, asserted separately.
func persistedJSONKeys(t reflect.Type) []string {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var keys []string
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" {
			name = field.Name
		}
		keys = append(keys, name)
		keys = append(keys, persistedJSONKeys(field.Type)...)
	}
	return keys
}

func assertNoPairVocabulary(t *testing.T, surface string, names []string) {
	t.Helper()
	for _, name := range names {
		for _, word := range strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return r == '_' || r == ':' || r == '-' || r == '.' }) {
			for _, banned := range circlePairVocabulary {
				if word == banned {
					t.Errorf("%s persists %q, which names a pairwise relationship (%q): ADR-0165 §5 forbids a durable Circle-pair edge", surface, name, banned)
				}
			}
		}
	}
}

func TestPersistedSchemaHasNoCirclePairEdge(t *testing.T) {
	// Every durable record shape the relay owns, with the exact keys it may
	// carry. A new field fails here until it is reviewed against ADR-0165 §5.
	surfaces := []struct {
		name  string
		typ   reflect.Type
		allow []string
	}{
		{"fair-use outbox base state", reflect.TypeOf(fairUseOutboxState{}),
			[]string{"version", "records", "tunnel_digest", "bytes", "batch_id", "created_at", "expires_at"}},
		{"fair-use outbox log entry", reflect.TypeOf(fairUseOutboxLogEntry{}),
			[]string{"op", "record", "batch_id", "tunnel_digest", "bytes", "created_at", "expires_at"}},
		{"hmac nonce store state", reflect.TypeOf(fileHMACNonceState{}),
			[]string{"version", "nonces"}},
	}
	for _, s := range surfaces {
		t.Run(s.name, func(t *testing.T) {
			got := persistedJSONKeys(s.typ)
			assertNoPairVocabulary(t, s.name, got)
			want := append([]string(nil), s.allow...)
			sort.Strings(want)
			sort.Strings(got)
			if !reflect.DeepEqual(dedupe(got), dedupe(want)) {
				t.Fatalf("%s persisted keys = %v, want exactly %v", s.name, dedupe(got), dedupe(want))
			}
		})
	}
}

func dedupe(sorted []string) []string {
	var out []string
	for i, v := range sorted {
		if i == 0 || v != sorted[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// Every persisted record is keyed by exactly one one-way tunnel digest. Two
// tunnels never share a record, so no stored row can join two parties.
func TestPersistedFilesCarryOnlySingleTunnelRecordsAndExpire(t *testing.T) {
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	for i, id := range []string{"tunnel-a", "tunnel-b"} {
		if err := outbox.enqueue(testFairUseOutboxRecord(id, 10, i+1)); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var doc map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			t.Fatalf("outbox line is not JSON: %v", err)
		}
		assertNoPairVocabulary(t, "fair-use outbox file", mapKeys(doc))
	}
	for _, rec := range mustOutboxRecords(t, outbox) {
		if !validLowerHex(rec.TunnelDigest, sha256HexLength) {
			t.Fatalf("outbox record digest %q is not a single opaque sha256", rec.TunnelDigest)
		}
		if rec.ExpiresAt <= rec.CreatedAt || time.Duration(rec.ExpiresAt-rec.CreatedAt)*time.Second > maxFairUseOutboxRetention {
			t.Fatalf("outbox record lifetime %ds is not bounded by the retention ceiling", rec.ExpiresAt-rec.CreatedAt)
		}
	}

	// The nonce store keeps only opaque nonce -> expiry, and sweeps every
	// entry once its expiry passes.
	noncePath := filepath.Join(t.TempDir(), "hmac-nonces.json")
	store, err := NewFileHMACNonceStore(noncePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0)
	ctx := context.Background()
	for _, nonce := range []string{"00000000000000000000000000000001", "00000000000000000000000000000002"} {
		if ok, err := store.Admit(ctx, nonce, now.Add(time.Minute), now); err != nil || !ok {
			t.Fatalf("admit %s = %v, %v", nonce, ok, err)
		}
	}
	if ok, err := store.Admit(ctx, "00000000000000000000000000000003", now.Add(3*time.Minute), now.Add(2*time.Minute)); err != nil || !ok {
		t.Fatalf("admit after expiry = %v, %v", ok, err)
	}
	state, err := store.readState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Nonces) != 1 {
		t.Fatalf("nonce store kept %d entries past their expiry, want only the live one", len(state.Nonces))
	}
}

func mapKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func mustOutboxRecords(t *testing.T, o *fileFairUseOutbox) []fairUseOutboxRecord {
	t.Helper()
	records, err := o.records()
	if err != nil {
		t.Fatal(err)
	}
	return records
}

// The Redis fair-use store is the only shared table. Its keyspace must be one
// fixed-suffix group per single tunnel digest (never a key spanning two
// identifiers), hold no identifier but the digest, and drain completely once
// the retention window passes.
func TestRedisKeyspaceHasNoPairEdgeAndDrainsAfterRetention(t *testing.T) {
	backend := miniredis.RunT(t)
	base := time.Unix(1_800_000_000, 0)
	backend.SetTime(base)
	const windowHours = 24
	store := newTestRedisFairUseStore(t, backend, windowHours)
	ctx := context.Background()
	ids := []string{"tunnel-one", "tunnel-two"}
	for i, id := range ids {
		if _, err := store.Add(ctx, id, string(rune('a'+i))+"-batch", 7); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.Reserve(ctx, id, newTestID(), 3, 100, 1, fairUseLeaseTTL); err != nil {
			t.Fatal(err)
		}
	}

	digests := map[string]bool{}
	for _, id := range ids {
		digests[fairUseTunnelDigest(id)] = true
	}
	suffixes := map[string]bool{"bytes": true, "hours": true, "leases": true, "batches": true}
	keys := backend.Keys()
	if len(keys) == 0 {
		t.Fatal("expected fair-use keys")
	}
	for _, key := range keys {
		rest, ok := strings.CutPrefix(key, store.prefix)
		if !ok {
			t.Fatalf("key %q is outside the fair-use prefix", key)
		}
		parts := strings.Split(rest, ":")
		if len(parts) != 2 || !digests[parts[0]] || !suffixes[parts[1]] {
			t.Fatalf("key %q is not <single tunnel digest>:<fixed suffix>", key)
		}
		assertNoPairVocabulary(t, "redis key suffix", []string{parts[1]})
	}
	for _, key := range keys {
		if strings.HasSuffix(key, ":bytes") {
			fields, _ := backend.HKeys(key)
			for _, f := range fields {
				if f != "total" && !strings.HasPrefix(f, "b:") {
					t.Fatalf("bytes hash %q carries field %q, want only total and b:<hour>", key, f)
				}
			}
		}
	}

	// Past the window (plus the lease TTL) nothing is queryable.
	backend.SetTime(base.Add((windowHours + 2) * time.Hour))
	backend.FastForward((windowHours + 2) * time.Hour)
	if left := backend.Keys(); len(left) != 0 {
		t.Fatalf("keys survived the retention window: %v", left)
	}
}
