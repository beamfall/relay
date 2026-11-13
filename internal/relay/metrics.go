package relay

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// tunnel-dial outcome label values (ADR-0146 §8 relay SLI: tunnel dial success
// rate). Bounded, low-cardinality set (ADR-0146 §9): the label is an error
// class, never an identifier, hostname, token, or IP.
const (
	dialOutcomeSuccess      = "success"      // handshake verified and acked
	dialOutcomeUnauthorized = "unauthorized" // token rejected by the verifier
	dialOutcomeInvalid      = "invalid"      // malformed / wrong-version hello
	dialOutcomeError        = "error"        // transport read failure before verify

	// dialOutcomeNonceStoreFull: the replay nonce store is at capacity, so the
	// relay refused the dial without judging the token (fails closed).
	dialOutcomeNonceStoreFull = "nonce_store_full"
)

// carrierDialOutcome classifies a failed token verification: a full replay
// nonce store is reported apart from a rejected token.
func carrierDialOutcome(err error) string {
	if errors.Is(err, ErrNonceStoreFull) {
		return dialOutcomeNonceStoreFull
	}
	return dialOutcomeUnauthorized
}

// nonceStoreFill is a label-free aggregate of a replay nonce store: live
// entries and the capacity at which it refuses new admissions.
type nonceStoreFill struct {
	Entries  int
	Capacity int
}

// ratio is Entries/Capacity. It reaches 1 when the store refuses new
// admissions and can exceed 1 after the capacity is lowered below the live
// entry count.
func (f nonceStoreFill) ratio() float64 {
	return float64(f.Entries) / float64(f.Capacity)
}

// nonceStoreFillReporter is implemented by a TokenVerifier whose replay nonce
// store may report its fill. ok is false when the configured store cannot, in
// which case newMetricsRegistry omits the fill gauge.
type nonceStoreFillReporter interface {
	nonceStoreFill() (fill nonceStoreFill, ok bool)
}

// nonceCacheSnapshotter is implemented by a TokenVerifier that exposes a
// concurrency-safe, label-free aggregate snapshot of its in-memory
// replay-protection nonce cache (MEMHID-RELAY-NONCE-GAUGE). Only
// HostedTokenVerifier implements it today; verifiers with no such cache (e.g.
// StaticTokenVerifier) simply don't satisfy the interface, and
// newMetricsRegistry omits the series entirely rather than publishing zeros.
type nonceCacheSnapshotter interface {
	nonceCacheSnapshot() nonceCacheSnapshot
}

// carrierReadiness is the deterministic seam used by /readyz. Production wires
// a relayReadinessState before the admin listener is exposed; tests can supply
// topology fixtures without opening sockets or probing production listeners.
type carrierReadiness interface {
	ready() bool
}

const (
	readinessConfigured uint32 = 1 << iota
	readinessPublicServing
	readinessCarrierServing
	readinessStopping

	readinessMandatoryServing = readinessPublicServing | readinessCarrierServing
)

// relayReadinessState separates a fully configured, serving relay topology
// from carrier connection accounting. The lifecycle is one atomic word so
// shutdown cannot race a late-starting accept goroutine into re-enabling
// readiness. Carrier route readiness is tracked by metrics.carriersConnected
// after route registration and Ack succeed.
type relayReadinessState struct {
	lifecycle atomic.Uint32
}

func (s *relayReadinessState) ready() bool {
	if s == nil {
		return false
	}
	state := s.lifecycle.Load()
	required := readinessConfigured | readinessMandatoryServing
	return state&readinessStopping == 0 && state&required == required
}

func (s *relayReadinessState) configure() bool {
	return s.addUnlessStopping(readinessConfigured)
}

func (s *relayReadinessState) listenerStarted(listener uint32) bool {
	return s.addUnlessStopping(listener)
}

func (s *relayReadinessState) listenerStopped(listener uint32) {
	for {
		state := s.lifecycle.Load()
		if s.lifecycle.CompareAndSwap(state, state&^listener) {
			return
		}
	}
}

func (s *relayReadinessState) stop() {
	for {
		state := s.lifecycle.Load()
		next := (state | readinessStopping) &^ readinessMandatoryServing
		if s.lifecycle.CompareAndSwap(state, next) {
			return
		}
	}
}

func (s *relayReadinessState) addUnlessStopping(flag uint32) bool {
	for {
		state := s.lifecycle.Load()
		if state&readinessStopping != 0 {
			return false
		}
		if s.lifecycle.CompareAndSwap(state, state|flag) {
			return true
		}
	}
}

type metrics struct {
	// carriersConnected counts live passthrough carriers with at least one
	// registered public route. Cache carriers and passthrough carriers with no
	// accepted routes are tracked separately so /readyz cannot mistake either
	// for a serving public route; the exported metric sums both counters.
	carriersConnected              atomic.Int64
	nonServingCarriersConnected    atomic.Int64
	tunnelsActive                  atomic.Int64
	streamsActive                  atomic.Int64
	bytesRelayed                   atomic.Int64
	handshakeFailures              atomic.Int64
	fairUseRefusals                atomic.Int64
	publicOverCap                  atomic.Int64
	publicPerIPOverCap             atomic.Int64
	carrierOverCap                 atomic.Int64
	carrierPendingPerSourceOverCap atomic.Int64
	fairUse                        *fairUseLimiter
	carrierReadiness               carrierReadiness
	// nonceCache is set (relay.go Start) only when the configured
	// TokenVerifier implements nonceCacheSnapshotter. Nil means the running
	// verifier has no such cache; the gauges are then omitted from the
	// registry rather than published as zero (avoids implying a cache exists
	// when it doesn't).
	nonceCache nonceCacheSnapshotter
	// nonceStore is set (relay.go Start) only when the configured
	// TokenVerifier implements nonceStoreFillReporter.
	nonceStore nonceStoreFillReporter

	// SLI instruments (ADR-0146 §8): tunnel dial success rate + tunnel-setup
	// latency, additive to ADR-0018's metadata-only set. Registered on the
	// private registry built by newMetricsRegistry; observed at the carrier
	// handshake site. Nil until the registry is built (tests that never call
	// newMetricsRegistry still exercise the atomics).
	tunnelDials     *prometheus.CounterVec
	tunnelSetupSecs prometheus.Histogram
}

// initSLIs lazily constructs the SLI instruments so they exist even before a
// registry is built (defensive: the handshake path records against them).
func (m *metrics) initSLIs() {
	if m.tunnelDials != nil {
		return
	}
	m.tunnelDials = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "beamfall_relay_tunnel_dials_total",
		Help: "Carrier tunnel dial (handshake) attempts by outcome (success/unauthorized/nonce_store_full/invalid/error).",
	}, []string{"outcome"})
	m.tunnelSetupSecs = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "beamfall_relay_tunnel_setup_seconds",
		Help:    "Carrier tunnel setup latency: first handshake frame read to verified+acked, in seconds.",
		Buckets: prometheus.DefBuckets,
	})
}

// recordDial records the outcome of one carrier handshake attempt (ADR-0146 §8).
// outcome is one of the dialOutcome* constants — a bounded error class only.
func (m *metrics) recordDial(outcome string) {
	if m.tunnelDials != nil {
		m.tunnelDials.WithLabelValues(outcome).Inc()
	}
}

// observeSetupLatency records tunnel-setup latency for a successful dial
// (ADR-0146 §8). Only the duration is recorded — no per-carrier identity.
func (m *metrics) observeSetupLatency(d time.Duration) {
	if m.tunnelSetupSecs != nil {
		m.tunnelSetupSecs.Observe(d.Seconds())
	}
}

// newMetricsRegistry builds the private Prometheus registry exposed on /metrics.
// It uses prometheus/client_golang for spec-correct # HELP/# TYPE exposition
// (ADR-0146 §6), replacing the hand-rolled text writer. The pre-existing
// aggregate series are exposed via CounterFunc/GaugeFunc reading the atomic
// counters that the hot path already maintains — no double-accounting and no
// hot-path change (ADR-0146 §10). The pre-existing series stay label-free
// aggregates (ADR-0103); the only labels are on the SLI set (ADR-0146 §8): the
// dial counter's bounded `outcome` error class and the setup-latency histogram's
// `le` buckets — both low-cardinality and free of any identifier/secret
// (ADR-0146 §9). Go/process collectors are deliberately not registered to keep
// the surface minimal and deterministic.
func (m *metrics) newMetricsRegistry() *prometheus.Registry {
	m.initSLIs()
	reg := prometheus.NewRegistry()

	counter := func(name, help string, read func() int64) {
		reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: name, Help: help,
		}, func() float64 { return float64(read()) }))
	}
	gauge := func(name, help string, read func() float64) {
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: name, Help: help,
		}, read))
	}
	gaugeInt := func(name, help string, read func() int64) {
		gauge(name, help, func() float64 { return float64(read()) })
	}

	gaugeInt("beamfall_relay_carriers_connected",
		"Carriers currently connected (handshaked), whether idle or relaying.",
		func() int64 {
			return m.carriersConnected.Load() + m.nonServingCarriersConnected.Load()
		})
	// active_tunnels = carriers currently relaying at least one in-flight stream,
	// distinct from carriers_connected (carriers merely handshaked/idle).
	gaugeInt("beamfall_relay_active_tunnels",
		"Carriers currently relaying at least one in-flight stream.",
		m.tunnelsActive.Load)
	gaugeInt("beamfall_relay_streams_active",
		"Relayed streams currently in flight across all carriers.",
		m.streamsActive.Load)
	counter("beamfall_relay_bytes_relayed_total",
		"Total bytes relayed across all carrier tunnels.",
		m.bytesRelayed.Load)
	counter("beamfall_relay_handshake_failures_total",
		"Carrier handshake attempts that failed before a verified session.",
		m.handshakeFailures.Load)
	counter("beamfall_relay_public_over_cap_total",
		"Public connections rejected for exceeding the global concurrency cap.",
		m.publicOverCap.Load)
	counter("beamfall_relay_public_per_ip_over_cap_total",
		"Public connections rejected for exceeding the per-source-IP concurrency cap.",
		m.publicPerIPOverCap.Load)
	counter("beamfall_relay_carrier_over_cap_total",
		"Carrier connections rejected for exceeding the pending or authenticated carrier cap.",
		m.carrierOverCap.Load)
	counter("beamfall_relay_carrier_pending_per_source_over_cap_total",
		"Unauthenticated carrier connections rejected for exceeding the per-source pending cap.",
		m.carrierPendingPerSourceOverCap.Load)
	counter("beamfall_relay_fairuse_refused_connections_total",
		"New connections refused because a tunnel was over its hard fair-use limit.",
		m.fairUseRefusals.Load)
	// ADR-0103 Decision 2: publish the bounded operational-log retention window
	// so "retention is bounded by policy" is externally verifiable.
	gaugeInt("beamfall_relay_log_retention_seconds",
		"Bounded operational-log retention window in seconds (ADR-0103).",
		func() int64 { return int64(OperationalLogRetentionWindow / time.Second) })

	if m.fairUse != nil {
		gaugeInt("beamfall_relay_fairuse_window_bytes",
			"Bytes accounted in the current rolling fair-use window.",
			func() int64 { return m.fairUse.snapshot().windowBytes })
		gaugeInt("beamfall_relay_fairuse_soft_limited_tunnels",
			"Tunnels currently over the soft fair-use limit.",
			func() int64 { return m.fairUse.snapshot().softTunnels })
		gaugeInt("beamfall_relay_fairuse_throttled_tunnels",
			"Tunnels currently throttled for exceeding the hard fair-use limit.",
			func() int64 { return m.fairUse.snapshot().throttledTunnels })
		if m.fairUse.store != nil {
			gaugeInt("beamfall_relay_fairuse_shared_store_available",
				"Whether the shared fair-use store is currently available (1=yes, 0=no).",
				func() int64 {
					if m.fairUse.ready() {
						return 1
					}
					return 0
				})
			gaugeInt("beamfall_relay_fairuse_pending_bytes",
				"Aggregate bytes waiting to flush to the shared fair-use store.",
				func() int64 { pending, _ := m.fairUse.sharedPressure(); return pending })
			gaugeInt("beamfall_relay_fairuse_active_reservations",
				"Aggregate live fleet-cap reservations owned by this relay instance.",
				func() int64 { _, reservations := m.fairUse.sharedPressure(); return reservations })
		}
	}

	// Hosted-token replay-protection nonce-cache pressure (MEMHID-RELAY-NONCE-GAUGE):
	// label-free current-entry and effective-cap aggregates only, omitted
	// entirely when the configured verifier has no nonce cache (e.g. a
	// self-hosted StaticTokenVerifier/HMACTokenVerifier deployment).
	if m.nonceCache != nil {
		gaugeInt("beamfall_relay_hosted_nonce_cache_entries",
			"Current unexpired entries in the hosted-token replay-protection nonce cache.",
			func() int64 { return int64(m.nonceCache.nonceCacheSnapshot().Entries) })
		gaugeInt("beamfall_relay_hosted_nonce_cache_cap",
			"Effective capacity of the hosted-token replay-protection nonce cache.",
			func() int64 { return int64(m.nonceCache.nonceCacheSnapshot().Cap) })
	}

	// Replay nonce store fill: live entries / capacity, label-free. New carrier
	// dials are refused (outcome nonce_store_full) once it reaches 1.
	if m.nonceStore != nil {
		if _, ok := m.nonceStore.nonceStoreFill(); ok {
			gauge("beamfall_relay_nonce_store_fill_ratio",
				"Live replay nonce-store entries divided by the store capacity; new carrier dials are refused at 1.",
				func() float64 { fill, _ := m.nonceStore.nonceStoreFill(); return fill.ratio() })
		}
	}

	reg.MustRegister(m.tunnelDials, m.tunnelSetupSecs)
	return reg
}

// healthz is a liveness probe only: it reports the admin listener is up and
// serving, not that the relay is ready to carry traffic. A relay with zero
// connected carriers still returns "ok" here (RO-02/RO-06); use /readyz for
// readiness.
func (m *metrics) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// readyz is a readiness probe: it requires the configured relay topology to be
// serving, at least one acknowledged passthrough carrier, and every mandatory
// dependency (currently the shared fair-use store, when enabled). Cache-only
// carrier connectivity cannot make the public passthrough route ready.
func (m *metrics) readyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Direct metrics fixtures do not expose a listener lifecycle. Start always
	// wires carrierReadiness before exposing /readyz, so production must also
	// prove that every mandatory listener is serving.
	topologyReady := true
	if m.carrierReadiness != nil {
		topologyReady = m.carrierReadiness.ready()
	}
	if topologyReady &&
		m.carriersConnected.Load() > 0 &&
		(m.fairUse == nil || m.fairUse.ready()) {
		_, _ = w.Write([]byte("ok\n"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("not ready\n"))
}

// metricsHandler returns the /metrics handler backed by the private registry.
func (m *metrics) metricsHandler() http.Handler {
	return promhttp.HandlerFor(m.newMetricsRegistry(), promhttp.HandlerOpts{})
}

// requireBearerToken wraps next so it serves only requests bearing the operator
// credential as "Authorization: Bearer <token>" (ADR-0146 §5, non-loopback
// /metrics gate). The comparison hashes both sides to a fixed-width digest
// before comparing, so it runs in constant time regardless of the presented
// token's length — ConstantTimeCompare alone would still short-circuit on a
// length mismatch, leaking the configured token's byte-length via timing. A
// missing or non-matching token yields 401 with a WWW-Authenticate challenge;
// the body carries no detail.
func requireBearerToken(token string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		got, ok := strings.CutPrefix(auth, "Bearer ")
		gotSum := sha256.Sum256([]byte(got))
		if !ok || subtle.ConstantTimeCompare(gotSum[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="relay-metrics"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
