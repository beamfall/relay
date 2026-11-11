package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCarrierHandshakeNonceStoreFullHasDistinctReasonAndMetric fills a small
// configured replay store through real carrier handshakes and asserts that the
// refusal fails closed under its own log code, dial outcome, and span outcome,
// never as a rejected token, while the fill gauge tracks the store.
func TestCarrierHandshakeNonceStoreFullHasDistinctReasonAndMetric(t *testing.T) {
	store, err := NewFileHMACNonceStoreWithCapacity(filepath.Join(t.TempDir(), "hmac-nonces.json"), 2)
	if err != nil {
		t.Fatalf("new capacity-2 store: %v", err)
	}
	hosts := []string{testSpanHost}
	sharedKey := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	verifier := &HMACTokenVerifier{Secret: sharedKey, Hostnames: hosts, NonceStore: store}
	s, rec := newHandshakeServer(t, verifier)
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	s.metrics.nonceStore = verifier
	scrape := func() string {
		rr := httptest.NewRecorder()
		s.metrics.metricsHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rr.Body.String()
	}
	dial := func() bool {
		token, err := MintHMACTunnelToken(sharedKey, hosts, MaxHMACTokenTTL)
		if err != nil {
			t.Fatalf("mint token: %v", err)
		}
		_, ok := s.carrierHandshake(context.Background(), &rwPair{r: helloFrame(t, token, hosts), w: &bytes.Buffer{}}, nil)
		return ok
	}

	if got := metricLine(scrape(), "beamfall_relay_nonce_store_fill_ratio"); got != "beamfall_relay_nonce_store_fill_ratio 0" {
		t.Fatalf("empty-store fill gauge = %q, want 0", got)
	}
	if !dial() {
		t.Fatal("first distinct token must be admitted into the empty store")
	}
	if got := metricLine(scrape(), "beamfall_relay_nonce_store_fill_ratio"); got != "beamfall_relay_nonce_store_fill_ratio 0.5" {
		t.Fatalf("half-full fill gauge = %q, want 0.5", got)
	}
	if !dial() {
		t.Fatal("second distinct token must be admitted up to capacity")
	}
	if dial() {
		t.Fatal("a distinct valid token must be refused once the store is full (fail closed)")
	}

	logged := logs.String()
	if !strings.Contains(logged, "code="+dialOutcomeNonceStoreFull) {
		t.Errorf("full-store refusal log lacks code=%s:\n%s", dialOutcomeNonceStoreFull, logged)
	}
	if strings.Contains(logged, "code=unauthorized") || strings.Contains(logged, "code=verifier_error") {
		t.Errorf("full-store refusal logged under a generic code:\n%s", logged)
	}
	body := scrape()
	full := `beamfall_relay_tunnel_dials_total{outcome="nonce_store_full"}`
	if got := metricLine(body, full); got != full+" 1" {
		t.Errorf("dial outcome line = %q, want %q", got, full+" 1")
	}
	if strings.Contains(body, `beamfall_relay_tunnel_dials_total{outcome="unauthorized"}`) {
		t.Errorf("full-store refusal was counted as an unauthorized dial:\n%s", body)
	}
	if got := metricLine(body, "beamfall_relay_nonce_store_fill_ratio"); got != "beamfall_relay_nonce_store_fill_ratio 1" {
		t.Errorf("full-store fill gauge = %q, want 1", got)
	}
	spans := rec.Ended()
	var outcome string
	for _, a := range spans[len(spans)-1].Attributes() {
		if string(a.Key) == "relay.handshake.outcome" {
			outcome = a.Value.AsString()
		}
	}
	if outcome != dialOutcomeNonceStoreFull {
		t.Errorf("refused handshake span outcome = %q, want %q", outcome, dialOutcomeNonceStoreFull)
	}
}

func TestFileHMACNonceStoreCapacityBounds(t *testing.T) {
	dir := t.TempDir()
	for _, capacity := range []int{-1, 0, MaxNonceStoreCapacity + 1} {
		if _, err := NewFileHMACNonceStoreWithCapacity(filepath.Join(dir, "refused.json"), capacity); err == nil {
			t.Errorf("capacity %d accepted, want refusal", capacity)
		}
	}
	store, err := NewFileHMACNonceStore(filepath.Join(dir, "default.json"))
	if err != nil {
		t.Fatalf("default store: %v", err)
	}
	if fill := store.fill(time.Now()); fill.Capacity != DefaultNonceStoreCapacity || fill.Entries != 0 {
		t.Fatalf("default store fill = %+v, want 0 of %d", fill, DefaultNonceStoreCapacity)
	}
	if DefaultNonceStoreCapacity != 259_200 {
		t.Fatalf("DefaultNonceStoreCapacity = %d, want 24h x 2 tokens/s x 150%% = 259200", DefaultNonceStoreCapacity)
	}
}

// TestFileHMACNonceStoreLoweredCapacityRefusesUntilExpiry reopens state written
// under a larger capacity with a smaller one: startup succeeds, admissions are
// refused with ErrNonceStoreFull while live entries exceed the new capacity, and
// they resume once enough entries expire.
func TestFileHMACNonceStoreLoweredCapacityRefusesUntilExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac-nonces.json")
	now := time.Now()
	large, err := NewFileHMACNonceStoreWithCapacity(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		expiresAt := now.Add(time.Duration(i+1) * time.Minute)
		if admitted, err := large.Admit(context.Background(), fmt.Sprintf("%032x", i), expiresAt, now); !admitted || err != nil {
			t.Fatalf("seed admission %d = %t, %v", i, admitted, err)
		}
	}

	small, err := NewFileHMACNonceStoreWithCapacity(path, 2)
	if err != nil {
		t.Fatalf("reopen with lower capacity: %v", err)
	}
	if fill := small.fill(now); fill.Entries != 3 || fill.ratio() != 1.5 {
		t.Fatalf("over-capacity fill = %+v ratio %v, want 3 entries ratio 1.5", fill, fill.ratio())
	}
	next := strings.Repeat("ff", hmacNonceBytes)
	admitted, err := small.Admit(context.Background(), next, now.Add(time.Hour), now)
	if admitted || !errors.Is(err, ErrNonceStoreFull) || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("over-capacity admission = %t, %v; want false, ErrNonceStoreFull not ErrUnauthorized", admitted, err)
	}

	later := now.Add(2*time.Minute + time.Second)
	if admitted, err := small.Admit(context.Background(), next, later.Add(time.Hour), later); !admitted || err != nil {
		t.Fatalf("admission after expiry = %t, %v; want true, nil", admitted, err)
	}
	if fill := small.fill(later); fill.Entries != 2 {
		t.Fatalf("post-expiry fill = %+v, want 2 live entries", fill)
	}
}

func TestNonceStoreFillGaugeOmittedWithoutFillSource(t *testing.T) {
	m := &metrics{nonceStore: &HMACTokenVerifier{NonceStore: &hmacReplayGuard{}}}
	rr := httptest.NewRecorder()
	m.metricsHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(rr.Body.String(), "beamfall_relay_nonce_store_fill_ratio") {
		t.Fatalf("fill gauge published for a store that cannot report its fill:\n%s", rr.Body.String())
	}
}
