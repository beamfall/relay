package relay

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestHealthzReturns200WithOKBody verifies the /healthz handler returns HTTP 200
// with content-type text/plain and a body containing "ok". This is the contract
// that cmd/relay-healthcheck relies on (it exits non-zero on any non-200 status).
func TestHealthzReturns200WithOKBody(t *testing.T) {
	m := &metrics{}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	m.healthz(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want %d", rr.Code, http.StatusOK)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", ct)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), "ok") {
		t.Errorf("healthz body = %q, want it to contain \"ok\"", string(body))
	}
}

// TestHealthzHandlerViaHTTPTest verifies the healthz handler works correctly
// when wired through a real *http.ServeMux (as it is in relay.Start).
func TestHealthzHandlerViaHTTPTest(t *testing.T) {
	m := &metrics{}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", m.healthz)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test response cleanup.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ok") {
		t.Errorf("body = %q, want it to contain \"ok\"", string(body))
	}
}

func TestReadyzRequiresServingPassthroughTopology(t *testing.T) {
	tests := []struct {
		name                string
		configured          bool
		publicServing       bool
		carrierServing      bool
		passthroughCarriers int64
		cacheCarriers       int64
		want                int
	}{
		{
			name:           "cache-only",
			configured:     true,
			publicServing:  true,
			carrierServing: true,
			cacheCarriers:  1,
			want:           http.StatusServiceUnavailable,
		},
		{
			name:           "carrier-down",
			configured:     true,
			publicServing:  true,
			carrierServing: true,
			want:           http.StatusServiceUnavailable,
		},
		{
			name:                "partial-start",
			configured:          true,
			publicServing:       true,
			passthroughCarriers: 1,
			want:                http.StatusServiceUnavailable,
		},
		{
			name:                "serving-topology",
			configured:          true,
			publicServing:       true,
			carrierServing:      true,
			passthroughCarriers: 1,
			want:                http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readiness := &relayReadinessState{}
			if tt.configured {
				readiness.configure()
			}
			if tt.publicServing {
				readiness.listenerStarted(readinessPublicServing)
			}
			if tt.carrierServing {
				readiness.listenerStarted(readinessCarrierServing)
			}
			m := &metrics{carrierReadiness: readiness}
			m.carriersConnected.Store(tt.passthroughCarriers)
			m.nonServingCarriersConnected.Store(tt.cacheCarriers)

			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			rr := httptest.NewRecorder()
			m.readyz(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("readyz status = %d, want %d", rr.Code, tt.want)
			}
			body := rr.Body.String()
			if tt.want == http.StatusOK && body != "ok\n" {
				t.Fatalf("readyz body = %q, want %q", body, "ok\n")
			}
			if tt.want != http.StatusOK && body != "not ready\n" {
				t.Fatalf("readyz body = %q, want %q", body, "not ready\n")
			}
		})
	}
}

func TestAcceptLoopsClosedListenerTracksProductionReadiness(t *testing.T) {
	t.Run("unexpected public listener exit", func(t *testing.T) {
		s := startReadyLifecycleTestServer(t)
		if err := s.publicListener.Close(); err != nil {
			t.Fatalf("close public listener: %v", err)
		}
		waitForReadinessStatus(t, &s.metrics, http.StatusServiceUnavailable)
		if state := s.readiness.lifecycle.Load(); state&readinessPublicServing != 0 {
			t.Fatalf("public accept loop remained serving after listener failure: lifecycle=%04b", state)
		}
	})

	t.Run("unexpected carrier listener exit", func(t *testing.T) {
		s := startReadyLifecycleTestServer(t)
		if err := s.carrierListener.Close(); err != nil {
			t.Fatalf("close carrier listener: %v", err)
		}
		waitForReadinessStatus(t, &s.metrics, http.StatusServiceUnavailable)
		if state := s.readiness.lifecycle.Load(); state&readinessCarrierServing != 0 {
			t.Fatalf("carrier accept loop remained serving after listener failure: lifecycle=%04b", state)
		}
	})

	t.Run("shutdown is immediate and cannot re-enable", func(t *testing.T) {
		s := startReadyLifecycleTestServer(t)
		s.Shutdown(0)

		state := s.readiness.lifecycle.Load()
		if state&readinessStopping == 0 {
			t.Fatalf("Shutdown did not transition readiness to stopping: lifecycle=%04b", state)
		}
		if s.readiness.listenerStarted(readinessPublicServing) {
			t.Fatal("late public accept-loop start re-enabled readiness after shutdown")
		}
		if s.readiness.listenerStarted(readinessCarrierServing) {
			t.Fatal("late carrier accept-loop start re-enabled readiness after shutdown")
		}
		assertReadinessStatus(t, &s.metrics, http.StatusServiceUnavailable)
	})
}

func startReadyLifecycleTestServer(t *testing.T) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := startBackoffTestRelay(t, ctx)
	// Route registration/Ack accounting is separately covered. This fixture
	// isolates the production Server lifecycle wiring that gates that route.
	s.metrics.carriersConnected.Store(1)
	waitForReadinessStatus(t, &s.metrics, http.StatusOK)
	return s
}

func waitForReadinessStatus(t *testing.T, m *metrics, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if readinessStatus(m) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("readyz did not reach status %d before deadline; last status=%d", want, readinessStatus(m))
		}
		time.Sleep(time.Millisecond)
	}
}

func assertReadinessStatus(t *testing.T, m *metrics, want int) {
	t.Helper()
	if got := readinessStatus(m); got != want {
		t.Fatalf("readyz status = %d, want %d", got, want)
	}
}

func readinessStatus(m *metrics) int {
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	m.readyz(rr, req)
	return rr.Code
}

func TestCarrierMetricIncludesNonServingCarriers(t *testing.T) {
	m := &metrics{}
	m.carriersConnected.Store(2)
	m.nonServingCarriersConnected.Store(3)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	m.metricsHandler().ServeHTTP(rr, req)
	if line := metricLine(rr.Body.String(), "beamfall_relay_carriers_connected"); line != "beamfall_relay_carriers_connected 5" {
		t.Fatalf("carriers_connected line = %q, want aggregate value 5", line)
	}
}

func metricLine(body, name string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name+" ") {
			return line
		}
	}
	return ""
}

// TestPrometheusHandlerReturnsExpectedMetricNames verifies /metrics exposes
// the mandatory relay metric names documented in ADR-0103.
func TestPrometheusHandlerReturnsExpectedMetricNames(t *testing.T) {
	m := &metrics{}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	m.metricsHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("prometheus status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	required := []string{
		"beamfall_relay_carriers_connected",
		"beamfall_relay_active_tunnels",
		"beamfall_relay_streams_active",
		"beamfall_relay_bytes_relayed_total",
		"beamfall_relay_handshake_failures_total",
		"beamfall_relay_log_retention_seconds",
		// The SLI histogram (ADR-0146 §8) always exposes its bucket/sum/count
		// series even with zero observations. The dial counter is a CounterVec and
		// only surfaces once a labelled outcome is observed — TestTunnelDialSLIsExposed
		// covers that after real handshakes.
		"beamfall_relay_tunnel_setup_seconds",
	}
	for _, name := range required {
		if !strings.Contains(body, name) {
			t.Errorf("metrics body missing %q", name)
		}
	}
	// ADR-0146 §6: client_golang exposition carries # HELP/# TYPE metadata that
	// the hand-rolled writer omitted.
	if !strings.Contains(body, "# HELP beamfall_relay_bytes_relayed_total") {
		t.Error("metrics body missing # HELP metadata (client_golang exposition)")
	}
	if !strings.Contains(body, "# TYPE beamfall_relay_bytes_relayed_total counter") {
		t.Error("metrics body missing # TYPE metadata (client_golang exposition)")
	}
}

// TestNonceCacheGaugesOmittedWithoutSnapshotter verifies non-hosted verifiers
// (m.nonceCache left nil, mirroring StaticTokenVerifier/HMACTokenVerifier,
// which don't implement nonceCacheSnapshotter) omit the hosted nonce-cache
// gauge series entirely rather than publishing zeros (MEMHID-RELAY-NONCE-GAUGE).
func TestNonceCacheGaugesOmittedWithoutSnapshotter(t *testing.T) {
	m := &metrics{}
	rec := httptest.NewRecorder()
	m.metricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, name := range []string{"beamfall_relay_hosted_nonce_cache_entries", "beamfall_relay_hosted_nonce_cache_cap"} {
		if strings.Contains(body, name) {
			t.Errorf("metrics body unexpectedly contains %q for a verifier with no nonce-cache snapshot", name)
		}
	}
}

// TestNonceCacheGaugesReflectHostedVerifierPressure verifies that once a
// HostedTokenVerifier is wired in as m.nonceCache, the entries/cap gauges
// are published, carry no labels, and track cache growth/eviction at and
// below cap (MEMHID-RELAY-NONCE-GAUGE acceptance criteria).
func TestNonceCacheGaugesReflectHostedVerifierPressure(t *testing.T) {
	now := hostedTestNow()
	const cap = 4
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
	m := &metrics{nonceCache: v}
	scrape := func() string {
		rec := httptest.NewRecorder()
		m.metricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}

	if body := scrape(); !strings.Contains(body, "beamfall_relay_hosted_nonce_cache_entries 0") ||
		!strings.Contains(body, "beamfall_relay_hosted_nonce_cache_cap 4") {
		t.Fatalf("empty-cache scrape missing expected gauge values:\n%s", body)
	}

	// Fill to cap: entries tracks growth up to and including cap.
	for i := 0; i < cap; i++ {
		c := base
		c.Nonce = "nonce-" + strconv.Itoa(i)
		if err := v.acceptNonce(c); err != nil {
			t.Fatalf("acceptNonce #%d: %v", i, err)
		}
	}
	if body := scrape(); !strings.Contains(body, "beamfall_relay_hosted_nonce_cache_entries 4") {
		t.Fatalf("at-cap scrape missing expected entries value:\n%s", body)
	}

	// One more insert past cap must evict, so entries stays pinned at cap.
	overflow := base
	overflow.Nonce = "nonce-overflow"
	if err := v.acceptNonce(overflow); err != nil {
		t.Fatalf("acceptNonce overflow: %v", err)
	}
	body := scrape()
	if !strings.Contains(body, "beamfall_relay_hosted_nonce_cache_entries 4") {
		t.Fatalf("post-eviction scrape entries should stay at cap:\n%s", body)
	}
	if !strings.Contains(body, "# HELP beamfall_relay_hosted_nonce_cache_entries") ||
		!strings.Contains(body, "# TYPE beamfall_relay_hosted_nonce_cache_entries gauge") {
		t.Errorf("metrics body missing HELP/TYPE metadata for the nonce-cache entries gauge:\n%s", body)
	}
	// Label-free: the gauge line has no `{...}` label block before the value.
	if strings.Contains(body, "beamfall_relay_hosted_nonce_cache_entries{") {
		t.Errorf("nonce-cache entries gauge unexpectedly carries labels:\n%s", body)
	}
}

// TestNonceCacheGaugesExposeNoPlantedIdentifiers plants distinguishable
// nonce/server-id strings through a real VerifyTunnelToken call and asserts
// none of them appear anywhere in the scraped exposition — the nonce-cache
// gauges are aggregate counts only, never nonce values or claim identifiers
// (bounded-cardinality/privacy invariant, MEMHID-RELAY-NONCE-GAUGE).
func TestNonceCacheGaugesExposeNoPlantedIdentifiers(t *testing.T) {
	key := hostedTestKey()
	now := hostedTestNow()
	plantedNonce := "planted-nonce-should-not-leak-9f3c"
	plantedServer := "planted-server-should-not-leak-a71e"
	token := signHostedTestToken(t, key, hostedRelayClaims{
		Type:      hostedRelayTokenType,
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		KeyID:     "relay-2026-06",
		ServerID:  plantedServer,
		Hostnames: []string{"home.relay.test"},
		Purpose:   "tunnel-connect",
		IssuedAt:  now,
		ExpiresAt: now.Add(2 * time.Minute),
		Nonce:     plantedNonce,
	})
	v := hostedTestVerifier(key.Public().(ed25519.PublicKey), now)
	if _, err := v.VerifyTunnelToken(context.Background(), []byte(token), []string{"home.relay.test"}); err != nil {
		t.Fatalf("verify hosted token: %v", err)
	}

	m := &metrics{nonceCache: v}
	rec := httptest.NewRecorder()
	m.metricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "beamfall_relay_hosted_nonce_cache_entries 1") {
		t.Fatalf("scrape missing expected entries=1 after one accepted nonce:\n%s", body)
	}
	for _, forbidden := range []string{plantedNonce, plantedServer} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metrics body leaked planted identifier %q:\n%s", forbidden, body)
		}
	}
}
