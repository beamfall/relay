package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quic-go/quic-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/beamfall/relay/internal/cache"
	"github.com/beamfall/relay/internal/config"
	"github.com/beamfall/relay/internal/protocol"
	"github.com/beamfall/relay/internal/sni"
)

type quicListener interface {
	Accept(context.Context) (*quic.Conn, error)
	Addr() net.Addr
	Close() error
}

const (
	acceptRetryInitialDelay = 5 * time.Millisecond
	acceptRetryMaxDelay     = time.Second
	// publicRejectLogSampleInterval bounds how often handlePublicConn logs a
	// repeated "public rejected" Warn for the same reason, mirroring
	// FairUseConfig's default LogSampleInterval (fairuse.go) so a scan/flood
	// hitting one rejection reason cannot spam the log at one line per
	// connection.
	publicRejectLogSampleInterval = time.Minute
)

type Config struct {
	PublicAddr  string
	CarrierAddr string
	// QUICAddr is the UDP address for the ADR-0018 §1 v2 QUIC carrier listener.
	// Empty disables it: the relay serves only the v1 TLS/TCP+yamux carrier.
	// Both listeners can run at once so carriers migrate independently.
	QUICAddr  string
	AdminAddr string
	// AdminAllowPublic opts in to binding AdminAddr to a non-loopback,
	// non-private address (SECREV-RELAY-5). Without it, Start refuses to run
	// when AdminAddr classifies as public.
	AdminAllowPublic bool
	// AdminMetricsToken is the operator-set bearer credential that guards
	// /metrics when AdminAddr binds a non-loopback interface (ADR-0146 §5). A
	// loopback bind serves /metrics unauthenticated (unchanged posture); a
	// non-loopback bind with an empty token is refused at Start (fail-closed) —
	// the richer observability surface is never exposed off-host without a
	// credential. The token is compared in constant time. /healthz and /readyz
	// remain unauthenticated liveness/readiness probes regardless.
	AdminMetricsToken string
	// TracerProvider supplies the OpenTelemetry tracer for the metadata-only
	// mint→relay span (ADR-0146 §7). Nil selects a no-op provider: default-off,
	// local-first (Invariant #5, ADR-0146 §3) — no exporter runs, nothing is
	// written off-process. The operator wires a real provider to opt in.
	TracerProvider   trace.TracerProvider
	CarrierTLSConfig *tls.Config
	TokenVerifier    TokenVerifier
	StreamCap        int
	RateBytesPerSec  int64
	RateBurstBytes   int64
	FairUse          FairUseConfig
	Logger           *slog.Logger
	// RedactConnectionLogs omits public remote address, SNI hostname, and
	// carrier id from connection logs. Nil defaults to true.
	RedactConnectionLogs *bool
	// MaxPublicConns bounds the number of concurrently-handled public
	// connections across all carriers. Over the cap, accepts are immediately
	// closed so a connection flood cannot exhaust goroutines/FDs. <=0 uses a
	// default.
	MaxPublicConns int
	// MaxPublicConnsPerIP bounds the number of concurrently-handled public
	// connections from one IPv4 /32 or IPv6 /64 (defense-in-depth,
	// SECREV-RELAY-9).
	// A partial-record flood — TCP-connect then dribble ClientHello bytes — can
	// otherwise hold a public slot for the whole PublicPeekTimeout window; without
	// a per-IP cap one source could occupy the entire MaxPublicConns pool and
	// starve legitimate clients. Over the per-IP cap the accept is closed
	// immediately. <=0 uses a default; set very high to effectively disable.
	MaxPublicConnsPerIP int
	// MaxStreamsPerIPPerCarrier bounds concurrent relayed streams from one
	// source prefix to one carrier. This prevents one source from consuming a
	// carrier's full StreamCap while leaving other carriers unaffected. <=0 uses
	// one quarter of StreamCap, with a minimum of one.
	MaxStreamsPerIPPerCarrier int
	// PublicPeekTimeout bounds how long the public listener waits to read a
	// client's TLS ClientHello (for SNI-blind routing) before reaping the
	// connection. A shorter deadline shrinks the window a partial-record flood
	// can pin a public slot. <=0 uses a default.
	PublicPeekTimeout time.Duration
	// MaxCarrierConns bounds the number of concurrently-handled carrier
	// connections. Carriers are few and known, so a modest cap suffices; over it
	// accepts are immediately closed so a flood on the carrier port cannot
	// exhaust goroutines/FDs (the public path is already gated this way). <=0
	// uses a default.
	MaxCarrierConns int
	// CarrierHandshakeTimeout bounds how long the server waits for the first
	// carrier frame before reaping the connection. <=0 uses a default.
	CarrierHandshakeTimeout time.Duration
	// ShutdownGrace bounds how long shutdown waits for in-flight relayed
	// streams to finish before force-closing carrier sessions. On shutdown the
	// public listener is closed first (no new connections accepted), then active
	// streams are given up to this window to drain. Zero means immediate
	// force-close (the pre-drain behaviour). Negative is treated as zero.
	ShutdownGrace time.Duration
	// ExpiredSessionDrain is the additional time a superseded carrier may stay
	// open after its token expires so streams already assigned to it can finish.
	// New streams route to the replacement immediately. Unsuperseded carriers
	// still close at token expiry. Negative values are treated as zero.
	ExpiredSessionDrain time.Duration
	// SupersededStreamMaxAge is how long past its own token expiry a superseded
	// carrier may keep its existing streams while a live carrier of the same
	// identity still holds one of its hostnames. Core rotates carriers well
	// inside the token TTL, so this lets a long relayed connection outlive the
	// token that admitted its carrier. When no live same-identity carrier
	// remains, ExpiredSessionDrain applies from that moment. Zero (the default)
	// disables the extension; negative values are treated as zero.
	SupersededStreamMaxAge time.Duration
	// YamuxStreamWindowBytes overrides the v1 (TLS/TCP+yamux) carrier's
	// per-stream flow-control window. <=0 uses
	// protocol.DefaultYamuxStreamWindowBytes (1 MiB). The tunnel client MUST be
	// configured with the same value, since yamux requires both ends of a
	// session to agree on window size.
	YamuxStreamWindowBytes int
}

type Server struct {
	publicListener         net.Listener
	carrierListener        net.Listener
	quicListener           quicListener // nil when QUICAddr is unset
	adminListener          net.Listener
	adminServer            *http.Server
	registry               *registry
	cacheKeys              *cacheKeyRegistry
	cacheCarriers          *cacheCarrierRegistry
	verifier               TokenVerifier
	streamCap              int
	rateBytes              int64
	rateBurst              int64
	fairUse                *fairUseLimiter
	handshakeThrottle      *handshakeThrottle
	logger                 *slog.Logger
	redactConnLogs         bool
	metrics                metrics
	acceptRetries          atomic.Int64
	readiness              *relayReadinessState
	publicSlots            chan struct{}         // semaphore bounding concurrent public conns
	carrierAdmissions      chan struct{}         // semaphore bounding carrier conns waiting before slot reservation
	carrierSlots           chan struct{}         // semaphore bounding concurrent carrier conns
	publicPerIP            *perIPLimiter         // bounds public conns per IPv4 /32 or IPv6 /64
	publicPerCarrier       *sourceCarrierLimiter // bounds streams per source prefix and carrier
	publicPeekT            time.Duration         // TLS ClientHello peek deadline (SNI-blind routing)
	carrierHandshakeT      time.Duration
	streamWG               sync.WaitGroup // tracks in-flight relayed public streams (for drain)
	shutdownGrace          time.Duration
	expiredSessionDrain    time.Duration
	supersededMaxAge       time.Duration
	supersededPoll         time.Duration      // how often an expired superseded carrier rechecks for a live successor
	cancelInternal         context.CancelFunc // cancels internalCtx; unblocks accept-loop backoff sleeps on Close
	closeOnce              sync.Once
	wg                     sync.WaitGroup
	yamuxStreamWindowBytes int
	tracer                 trace.Tracer // metadata-only mint→relay span (ADR-0146 §7); no-op unless operator opts in
	publicRejectLog        *publicRejectSampler
}

// publicRejectSampler rate-limits repeated "public rejected" Warn logs per
// rejection reason, the same sample-and-reset approach tunnelUsage.
// shouldLogRefusal (fairuse.go) uses for fair-use refusals. handlePublicConn's
// other rejection paths have no per-tunnel usage tracker to sample against, so
// this samples per reason instead; the reason is always one of a small fixed
// set of call-site labels, so the tracked map stays bounded under any flood
// volume.
type publicRejectSampler struct {
	interval time.Duration
	now      func() time.Time

	mu   sync.Mutex
	last map[string]time.Time
}

func newPublicRejectSampler(interval time.Duration, now func() time.Time) *publicRejectSampler {
	return &publicRejectSampler{interval: interval, now: now, last: make(map[string]time.Time)}
}

// shouldLog reports whether a rejection with the given reason should be
// logged now. A nil receiver always logs, so a Server built without going
// through Start (a common pattern in this package's white-box tests) fails
// open to today's unsampled behaviour instead of panicking.
func (p *publicRejectSampler) shouldLog(reason string) bool {
	if p == nil {
		return true
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if last, ok := p.last[reason]; ok && now.Sub(last) < p.interval {
		return false
	}
	p.last[reason] = now
	return true
}

// ApplyStreamCapDefault returns cfg with the relay-owned stream cap default applied.
func ApplyStreamCapDefault(cfg Config) Config {
	if cfg.StreamCap <= 0 {
		cfg.StreamCap = 64
	}
	return cfg
}

func Start(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.PublicAddr == "" {
		cfg.PublicAddr = "127.0.0.1:8443"
	}
	if cfg.CarrierAddr == "" {
		cfg.CarrierAddr = "127.0.0.1:9443"
	}
	if cfg.CarrierTLSConfig == nil {
		return nil, errors.New("carrier TLS config is required")
	}
	if cfg.TokenVerifier == nil {
		return nil, errors.New("token verifier is required")
	}
	if v, ok := cfg.TokenVerifier.(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return nil, fmt.Errorf("token verifier: %w", err)
		}
	}
	cfg = ApplyStreamCapDefault(cfg)
	if cfg.MaxPublicConns <= 0 {
		cfg.MaxPublicConns = 1024
	}
	if cfg.MaxPublicConnsPerIP <= 0 {
		cfg.MaxPublicConnsPerIP = 64
	}
	if cfg.MaxStreamsPerIPPerCarrier <= 0 {
		cfg.MaxStreamsPerIPPerCarrier = max(1, cfg.StreamCap/4)
	}
	if cfg.PublicPeekTimeout <= 0 {
		cfg.PublicPeekTimeout = 3 * time.Second
	}
	if cfg.MaxCarrierConns <= 0 {
		cfg.MaxCarrierConns = 64
	}
	if cfg.CarrierHandshakeTimeout <= 0 {
		cfg.CarrierHandshakeTimeout = 10 * time.Second
	}
	if cfg.ShutdownGrace < 0 {
		cfg.ShutdownGrace = 0
	}
	if cfg.ExpiredSessionDrain < 0 {
		cfg.ExpiredSessionDrain = 0
	}
	if cfg.SupersededStreamMaxAge < 0 {
		cfg.SupersededStreamMaxAge = 0
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	fairUse, err := newFairUseLimiterContext(ctx, cfg.FairUse, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("initialize fair-use store: %w", err)
	}

	publicListener, err := net.Listen("tcp", cfg.PublicAddr)
	if err != nil {
		fairUse.close()
		return nil, fmt.Errorf("listen public: %w", err)
	}
	carrierTCP, err := net.Listen("tcp", cfg.CarrierAddr)
	if err != nil {
		publicListener.Close() //nolint:errcheck // best-effort cleanup after carrier listen failure.
		fairUse.close()
		return nil, fmt.Errorf("listen carrier: %w", err)
	}

	var quicListener quicListener
	if cfg.QUICAddr != "" {
		quicTLSConfig := cfg.CarrierTLSConfig.Clone()
		if len(quicTLSConfig.NextProtos) == 0 {
			quicTLSConfig.NextProtos = []string{"beamfall-relay-carrier/1"}
		}
		quicListener, err = quic.ListenAddr(cfg.QUICAddr, quicTLSConfig, protocol.QUICConfig())
		if err != nil {
			publicListener.Close() //nolint:errcheck // best-effort cleanup after QUIC listen failure.
			carrierTCP.Close()     //nolint:errcheck // best-effort cleanup after QUIC listen failure.
			fairUse.close()
			return nil, fmt.Errorf("listen quic carrier: %w", err)
		}
	}

	readiness := &relayReadinessState{}
	s := &Server{
		publicListener:         publicListener,
		carrierListener:        tls.NewListener(carrierTCP, cfg.CarrierTLSConfig),
		quicListener:           quicListener,
		registry:               newRegistry(),
		cacheKeys:              newCacheKeyRegistry(),
		cacheCarriers:          newCacheCarrierRegistry(),
		verifier:               cfg.TokenVerifier,
		streamCap:              cfg.StreamCap,
		rateBytes:              cfg.RateBytesPerSec,
		rateBurst:              cfg.RateBurstBytes,
		fairUse:                fairUse,
		logger:                 cfg.Logger,
		redactConnLogs:         cfg.RedactConnectionLogs == nil || *cfg.RedactConnectionLogs,
		readiness:              readiness,
		publicSlots:            make(chan struct{}, cfg.MaxPublicConns),
		carrierAdmissions:      make(chan struct{}, cfg.MaxCarrierConns),
		carrierSlots:           make(chan struct{}, cfg.MaxCarrierConns),
		publicPerIP:            newPerIPLimiter(cfg.MaxPublicConnsPerIP),
		publicPerCarrier:       newSourceCarrierLimiter(cfg.MaxStreamsPerIPPerCarrier),
		publicPeekT:            cfg.PublicPeekTimeout,
		carrierHandshakeT:      cfg.CarrierHandshakeTimeout,
		shutdownGrace:          cfg.ShutdownGrace,
		expiredSessionDrain:    cfg.ExpiredSessionDrain,
		supersededMaxAge:       cfg.SupersededStreamMaxAge,
		supersededPoll:         supersededSuccessorPoll,
		yamuxStreamWindowBytes: cfg.YamuxStreamWindowBytes,
		publicRejectLog:        newPublicRejectSampler(publicRejectLogSampleInterval, time.Now),
	}
	s.metrics.carrierReadiness = readiness
	tp := cfg.TracerProvider
	if tp == nil {
		// Default-off, local-first (Invariant #5, ADR-0146 §3): a no-op provider
		// runs no exporter and writes nothing off-process until the operator opts
		// in by supplying a real TracerProvider.
		tp = noop.NewTracerProvider()
	}
	s.tracer = tp.Tracer("github.com/beamfall/relay")
	s.logger.Info("connection log redaction", "mode", connectionLogMode(s.redactConnLogs))
	s.metrics.fairUse = s.fairUse
	// Wire the nonce-cache pressure gauges only when the configured verifier
	// exposes a snapshot (MEMHID-RELAY-NONCE-GAUGE); other verifiers simply
	// omit the series.
	if snap, ok := cfg.TokenVerifier.(nonceCacheSnapshotter); ok {
		s.metrics.nonceCache = snap
	}
	if reporter, ok := cfg.TokenVerifier.(nonceStoreFillReporter); ok {
		s.metrics.nonceStore = reporter
	}
	s.handshakeThrottle = newHandshakeThrottle()

	if cfg.AdminAddr != "" {
		warning, err := config.AdminExposureCheck(cfg.AdminAddr, cfg.AdminAllowPublic)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("admin listener: %w", err)
		}
		if warning != "" {
			s.logger.Warn("admin listener exposure", "warning", warning)
		}
		// ADR-0146 §5: /metrics binds loopback unauthenticated; any non-loopback
		// bind requires an operator-set bearer credential. Fail closed — refuse to
		// start a non-loopback admin listener with no token rather than expose the
		// richer surface unauthenticated.
		loopbackOnly := config.AdminAddrIsLoopback(cfg.AdminAddr)
		if !loopbackOnly && cfg.AdminMetricsToken == "" {
			s.Close()
			return nil, fmt.Errorf("admin listener %q is not loopback-only; /metrics requires an operator credential (set --admin-metrics-token / RELAYD_ADMIN_METRICS_TOKEN)", cfg.AdminAddr)
		}
		metricsHandler := s.metricsHandler()
		if !loopbackOnly {
			metricsHandler = requireBearerToken(cfg.AdminMetricsToken, metricsHandler)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", s.metrics.healthz)
		mux.HandleFunc("/readyz", s.metrics.readyz)
		mux.Handle("/metrics", metricsHandler)
		admin := &http.Server{
			Addr:              cfg.AdminAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		adminListener, err := net.Listen("tcp", cfg.AdminAddr)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("listen admin: %w", err)
		}
		s.adminServer = admin
		s.adminListener = adminListener
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := admin.Serve(adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error("admin server stopped", "err", err)
			}
		}()
	}

	// Derive an internal context so Close/Shutdown can unblock accept-loop
	// backoff sleeps (handshakeThrottle.backoffBefore) immediately instead of
	// leaving them to park out up to handshakeBackoffMax after the listeners
	// are closed. This only shortens sleeps; it doesn't change shutdown
	// ordering (listeners/registry are still torn down in forceClose).
	internalCtx, cancel := context.WithCancel(ctx)
	s.cancelInternal = cancel

	// Configuration is complete before the loops are launched, but readiness
	// remains false until each mandatory accept goroutine marks itself live.
	// listenerStarted is stopping-aware, so a concurrent shutdown cannot let a
	// late-scheduled goroutine re-enable readiness.
	s.readiness.configure()
	s.wg.Add(2)
	go s.acceptPublic(internalCtx)
	go s.acceptCarriers(internalCtx)
	if s.quicListener != nil {
		s.wg.Add(1)
		go s.acceptQUICCarriers(internalCtx)
	}
	go func() {
		<-ctx.Done()
		s.Shutdown(s.shutdownGrace)
	}()
	return s, nil
}

func (s *Server) metricsHandler() http.Handler {
	reg := s.metrics.newMetricsRegistry()
	reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "beamfall_relay_accept_retries_total",
		Help: "Listener accept failures retried without stopping the relay.",
	}, func() float64 { return float64(s.acceptRetries.Load()) }))
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

func (s *Server) PublicAddr() string  { return s.publicListener.Addr().String() }
func (s *Server) CarrierAddr() string { return s.carrierListener.Addr().String() }
func (s *Server) QUICAddr() string {
	if s.quicListener == nil {
		return ""
	}
	return s.quicListener.Addr().String()
}
func (s *Server) AdminAddr() string {
	if s.adminListener == nil {
		return ""
	}
	return s.adminListener.Addr().String()
}

// Shutdown stops accepting new public connections, waits up to grace for
// in-flight relayed streams to drain, then force-closes carrier sessions and the
// remaining listeners. A grace of zero (or negative) force-closes immediately,
// preserving the pre-drain behaviour. Idempotent and safe to call concurrently
// with Close; the first call wins.
func (s *Server) Shutdown(grace time.Duration) {
	s.closeOnce.Do(func() {
		// Fail readiness before stopping public accepts so load balancers stop
		// sending new work while existing streams drain.
		if s.readiness != nil {
			s.readiness.stop()
		}
		// Stop accepting new public connections first. The accept loop returns
		// on the listener error; in-flight handlers keep running.
		_ = s.publicListener.Close()

		if grace > 0 {
			drained := make(chan struct{})
			go func() {
				s.streamWG.Wait()
				close(drained)
			}()
			timer := time.NewTimer(grace)
			select {
			case <-drained:
				timer.Stop()
				s.logger.Info("shutdown: in-flight streams drained within grace")
			case <-timer.C:
				s.logger.Info("shutdown: grace window elapsed, force-closing remaining streams")
			}
		}

		s.forceClose()
	})
}

// Close force-closes the server immediately, cutting any in-flight relayed
// streams. It is the zero-grace shutdown path. Idempotent.
func (s *Server) Close() {
	s.Shutdown(0)
}

// forceClose tears down remaining listeners, carrier sessions, and the admin server.
// It is only ever invoked through closeOnce after the public listener is closed.
func (s *Server) forceClose() {
	if s.cancelInternal != nil {
		s.cancelInternal()
	}
	_ = s.carrierListener.Close()
	if s.quicListener != nil {
		_ = s.quicListener.Close()
	}
	if s.adminServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.adminServer.Shutdown(ctx)
	}
	if s.adminListener != nil {
		_ = s.adminListener.Close()
	}
	s.registry.close()
	if s.fairUse != nil {
		s.fairUse.close()
	}
}

func (s *Server) Wait() {
	s.wg.Wait()
}

func (s *Server) acceptPublic(ctx context.Context) {
	defer s.wg.Done()
	if s.readiness != nil {
		if !s.readiness.listenerStarted(readinessPublicServing) {
			return
		}
		defer s.readiness.listenerStopped(readinessPublicServing)
	}
	var retryDelay time.Duration
	for {
		conn, err := s.publicListener.Accept()
		if err != nil {
			var retry bool
			retryDelay, retry = s.waitAcceptRetry(ctx, "public", err, retryDelay)
			if !retry {
				return
			}
			continue
		}
		retryDelay = 0
		// Bound concurrently-handled public connections. Over the cap, close
		// immediately so a flood cannot exhaust goroutines/FDs; the accept loop
		// stays responsive and reclaims the slot as soon as a handler finishes.
		select {
		case s.publicSlots <- struct{}{}:
		default:
			s.metrics.publicOverCap.Add(1)
			_ = conn.Close()
			continue
		}
		// Defense-in-depth (SECREV-RELAY-9): a partial-record flood can hold a
		// public slot for the whole PublicPeekTimeout window. Cap concurrent
		// public conns per source IP so no single source can monopolise the slot
		// pool regardless of peek duration. Over the per-IP cap, release the
		// global slot and close immediately.
		ip := sourcePrefix(conn.RemoteAddr())
		if !s.publicPerIP.acquire(ip) {
			s.metrics.publicPerIPOverCap.Add(1)
			<-s.publicSlots
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.publicSlots }()
			defer s.publicPerIP.release(ip)
			s.handlePublicConn(ctx, conn)
		}()
	}
}

func (s *Server) acceptCarriers(ctx context.Context) {
	defer s.wg.Done()
	if s.readiness != nil {
		if !s.readiness.listenerStarted(readinessCarrierServing) {
			return
		}
		defer s.readiness.listenerStopped(readinessCarrierServing)
	}
	var retryDelay time.Duration
	for {
		conn, err := s.carrierListener.Accept()
		if err != nil {
			var retry bool
			retryDelay, retry = s.waitAcceptRetry(ctx, "carrier", err, retryDelay)
			if !retry {
				return
			}
			continue
		}
		retryDelay = 0
		// Bound connections before spawning their backoff goroutine. The separate
		// admission semaphore preserves the guarantee that backoff sleeps hold no
		// carrier slot while preventing those sleeps from accumulating unbounded
		// goroutines and file descriptors.
		select {
		case s.carrierAdmissions <- struct{}{}:
		default:
			s.metrics.carrierOverCap.Add(1)
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.carrierAdmissions }()
			// Back off a repeat-offender source BEFORE reserving a carrier slot,
			// so a bad-token flood cannot pin the slots for the backoff-sleep
			// duration (SECREV-RELAY-8). The sleep holds no slot; slots are
			// reserved only for connections about to attempt a real handshake.
			s.handshakeThrottle.backoffBefore(ctx, conn.RemoteAddr())
			// Bound concurrently-handled carrier connections, mirroring acceptPublic.
			// Carrier handlers are long-lived (they block until the yamux session
			// closes), so the slot is held for the carrier's lifetime — exactly the
			// cap we want. Over the cap, close immediately so a flood on the carrier
			// port cannot exhaust goroutines/FDs.
			select {
			case s.carrierSlots <- struct{}{}:
			default:
				s.metrics.carrierOverCap.Add(1)
				_ = conn.Close()
				return
			}
			defer func() { <-s.carrierSlots }()
			s.handleCarrierConn(ctx, conn)
		}()
	}
}

func (s *Server) handleCarrierConn(ctx context.Context, conn net.Conn) {
	defer conn.Close() //nolint:errcheck // carrier connection cleanup.
	// Bound the handshake: a carrier that connects and sends nothing must not
	// hold a goroutine indefinitely. Mirrors the public SNI-peek deadline posture.
	if s.carrierHandshakeT > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(s.carrierHandshakeT))
	}
	verified, ok := s.carrierHandshake(ctx, conn, conn.RemoteAddr())
	if !ok {
		return
	}
	// Handshake frame read; clear the deadline so the long-lived yamux session
	// is not subject to the handshake timeout.
	_ = conn.SetReadDeadline(time.Time{})
	session, err := yamux.Server(conn, protocol.YamuxConfig(s.yamuxStreamWindowBytes))
	if err != nil {
		s.metrics.handshakeFailures.Add(1)
		return
	}
	s.serveCarrierSession(ctx, conn, session, verified)
}

// acceptQUICCarriers mirrors acceptCarriers for the ADR-0018 §1 v2 QUIC
// carrier listener: each accepted QUIC connection becomes one carrier session
// once its handshake stream completes the Hello/Ack exchange.
func (s *Server) acceptQUICCarriers(ctx context.Context) {
	defer s.wg.Done()
	var retryDelay time.Duration
	for {
		conn, err := s.quicListener.Accept(ctx)
		if err != nil {
			var retry bool
			retryDelay, retry = s.waitAcceptRetry(ctx, "quic_carrier", err, retryDelay)
			if !retry {
				return
			}
			continue
		}
		retryDelay = 0
		// Share the TCP carrier admission budget so neither transport can build an
		// unbounded queue of pre-slot backoff goroutines or connections.
		select {
		case s.carrierAdmissions <- struct{}{}:
		default:
			s.metrics.carrierOverCap.Add(1)
			_ = conn.CloseWithError(0, "carrier admission over cap")
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.carrierAdmissions }()
			// Back off a repeat-offender source BEFORE reserving a carrier slot,
			// so a bad-token flood cannot pin the slots for the backoff-sleep
			// duration (SECREV-RELAY-8). Mirrors the TCP acceptCarriers posture.
			s.handshakeThrottle.backoffBefore(ctx, conn.RemoteAddr())
			select {
			case s.carrierSlots <- struct{}{}:
			default:
				s.metrics.carrierOverCap.Add(1)
				_ = conn.CloseWithError(0, "carrier over cap")
				return
			}
			defer func() { <-s.carrierSlots }()
			s.handleQUICCarrierConn(ctx, conn)
		}()
	}
}

func (s *Server) waitAcceptRetry(ctx context.Context, listener string, err error, delay time.Duration) (time.Duration, bool) {
	if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
		return 0, false
	}

	temporary := false
	if netErr, ok := err.(net.Error); ok {
		// The listener contract explicitly distinguishes temporary accept errors,
		// despite Temporary being deprecated for new general-purpose error APIs.
		temporary = netErr.Temporary() //nolint:staticcheck // Required compatibility with net.Listener accept errors.
	}
	delay = nextAcceptRetryDelay(delay)
	s.acceptRetries.Add(1)
	s.logger.Warn("listener accept failed; retrying", "listener", listener, "temporary", temporary, "retry_in", delay, "err", err)

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return delay, true
	case <-ctx.Done():
		return 0, false
	}
}

func nextAcceptRetryDelay(delay time.Duration) time.Duration {
	if delay == 0 {
		return acceptRetryInitialDelay
	}
	delay *= 2
	if delay > acceptRetryMaxDelay {
		return acceptRetryMaxDelay
	}
	return delay
}

func (s *Server) handleQUICCarrierConn(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "") //nolint:errcheck // carrier connection cleanup.
	// The handshake Hello/Ack exchange happens on the first stream the client
	// opens (a QUIC connection has no connection-level byte stream of its own).
	hsCtx := ctx
	if s.carrierHandshakeT > 0 {
		var cancel context.CancelFunc
		hsCtx, cancel = context.WithTimeout(ctx, s.carrierHandshakeT)
		defer cancel()
	}
	hsStream, err := conn.AcceptStream(hsCtx)
	if err != nil {
		s.metrics.handshakeFailures.Add(1)
		if s.redactConnLogs {
			s.logger.Warn("quic carrier handshake stream failed", "err", err)
		} else {
			s.logger.Warn("quic carrier handshake stream failed", "remote", conn.RemoteAddr(), "err", err)
		}
		return
	}
	// Bound the Hello/Ack frame read itself: AcceptStream only bounds how long
	// we wait for the stream to open, so a peer that opens the stream and then
	// sends a partial frame (or nothing) could otherwise hold the carrier slot
	// indefinitely. Mirrors handleCarrierConn's TCP read-deadline posture.
	if s.carrierHandshakeT > 0 {
		_ = hsStream.SetReadDeadline(time.Now().Add(s.carrierHandshakeT))
	}
	verified, ok := s.carrierHandshake(ctx, hsStream, conn.RemoteAddr())
	if !ok {
		return
	}
	// Handshake frame read; clear the deadline so the long-lived stream is not
	// subject to the handshake timeout.
	_ = hsStream.SetReadDeadline(time.Time{})
	session := protocol.NewQUICSession(conn)
	s.serveCarrierSession(ctx, hsStream, session, verified)
}

// carrierHandshake reads and validates the Hello frame and verifies its
// token, writing an Error frame and returning ok=false on any failure. It is
// shared by the TCP/yamux and QUIC carrier paths, which differ only in how
// the handshake's byte stream (rw) and the eventual session are constructed.
func (s *Server) carrierHandshake(ctx context.Context, rw protocol.FrameReadWriter, remote net.Addr) (VerifiedCarrier, bool) {
	// Metadata-only span on the mint→relay hop (ADR-0146 §7, ADR-0018 §11): the
	// only attribute is a bounded error class; the outcome is recorded via
	// setHandshakeOutcome on every return path. No Stream Tokens, carrier/account
	// identifiers, hostnames, payload, or client IPs ever touch this span
	// (Invariant #7, ADR-0146 §9 denylist). Span timing supplies the duration.
	start := time.Now()
	ctx, span := s.tracer.Start(ctx, "relay.carrier_handshake")
	defer span.End()

	frame, err := protocol.ReadFrame(rw)
	if err != nil {
		setHandshakeOutcome(span, dialOutcomeError)
		s.metrics.recordDial(dialOutcomeError)
		s.metrics.handshakeFailures.Add(1)
		if s.redactConnLogs {
			s.logger.Warn("carrier handshake failed", "err", err)
		} else {
			s.logger.Warn("carrier handshake failed", "remote", remote, "err", err)
		}
		return VerifiedCarrier{}, false
	}
	if frame.Type != protocol.FrameHello || frame.Hello == nil || frame.Hello.Version != protocol.Version {
		setHandshakeOutcome(span, dialOutcomeInvalid)
		s.metrics.recordDial(dialOutcomeInvalid)
		s.metrics.handshakeFailures.Add(1)
		_ = protocol.WriteFrame(rw, protocol.Frame{Type: protocol.FrameError, Error: "invalid hello"})
		return VerifiedCarrier{}, false
	}
	surface, err := protocol.HelloSurface(frame.Hello)
	if err != nil {
		setHandshakeOutcome(span, dialOutcomeInvalid)
		s.metrics.recordDial(dialOutcomeInvalid)
		s.metrics.handshakeFailures.Add(1)
		_ = protocol.WriteFrame(rw, protocol.Frame{Type: protocol.FrameError, Error: "invalid hello"})
		return VerifiedCarrier{}, false
	}
	if surface == protocol.SurfaceCache {
		if err := cache.ValidateTokenKey(frame.Hello.CacheVerificationKey); err != nil {
			setHandshakeOutcome(span, dialOutcomeInvalid)
			s.metrics.recordDial(dialOutcomeInvalid)
			s.metrics.handshakeFailures.Add(1)
			_ = protocol.WriteFrame(rw, protocol.Frame{Type: protocol.FrameError, Error: "invalid hello"})
			return VerifiedCarrier{}, false
		}
	}
	// The per-source backoff for repeated failed handshakes runs BEFORE the
	// carrier slot is reserved (in acceptCarriers/acceptQUICCarriers), so the
	// backoff-sleep never occupies a slot (SECREV-RELAY-8). Here we only record
	// the outcome of this attempt to feed that pre-slot throttle.
	verified, err := s.verifyCarrierToken(ctx, frame.Hello.Token, frame.Hello.Hostnames, surface, frame.Hello.CacheVerificationKey)
	if err != nil {
		outcome := carrierDialOutcome(err)
		setHandshakeOutcome(span, outcome)
		s.metrics.recordDial(outcome)
		if errors.Is(err, ErrUnauthorized) {
			s.handshakeThrottle.recordFailure(remote)
		}
		s.metrics.handshakeFailures.Add(1)
		_ = protocol.WriteFrame(rw, protocol.Frame{Type: protocol.FrameError, Error: "unauthorized"})
		code := carrierAuthorizationFailureCode(err)
		if s.redactConnLogs {
			s.logger.Warn("carrier unauthorized", "code", code)
		} else {
			s.logger.Warn("carrier unauthorized", "remote", remote, "code", code)
		}
		return VerifiedCarrier{}, false
	}
	if verified.TraceCorrelationID != "" {
		span.SetAttributes(attribute.String("relay.mint.correlation_id", verified.TraceCorrelationID))
	}
	setHandshakeOutcome(span, dialOutcomeSuccess)
	s.metrics.recordDial(dialOutcomeSuccess)
	s.metrics.observeSetupLatency(time.Since(start))
	s.handshakeThrottle.recordSuccess(remote)
	verified.Surface = surface
	if surface == protocol.SurfaceCache {
		verified.CacheVerificationKey = append([]byte(nil), frame.Hello.CacheVerificationKey...)
	}
	return verified, true
}

func (s *Server) verifyCarrierToken(ctx context.Context, token []byte, hostnames []string, surface string, cacheVerificationKey []byte) (VerifiedCarrier, error) {
	if surface == protocol.SurfaceCache {
		if v, ok := s.verifier.(CacheCarrierTokenVerifier); ok {
			return v.VerifyCacheCarrierToken(ctx, token, hostnames, cacheVerificationKey)
		}
	}
	if v, ok := s.verifier.(SurfaceTokenVerifier); ok {
		return v.VerifyCarrierToken(ctx, token, hostnames, surface)
	}
	if surface != protocol.SurfacePassthrough {
		return VerifiedCarrier{}, ErrUnauthorized
	}
	return s.verifier.VerifyTunnelToken(ctx, token, hostnames)
}

// carrierAuthorizationFailureCode converts verifier errors into a bounded
// operator signal. Verifier error text is never safe to log: even errors that
// wrap ErrUnauthorized may include attacker-controlled requested hostnames or
// provider claim details.
func carrierAuthorizationFailureCode(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrNonceStoreFull):
		return dialOutcomeNonceStoreFull
	case errors.Is(err, context.Canceled):
		return "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	default:
		return "verifier_error"
	}
}

func (s *Server) VerifyCacheAccessToken(ctx context.Context, carrierID, token string) (cache.VerifiedAccess, error) {
	keys := s.cacheKeys.keys(carrierID)
	if keys == nil {
		return cache.VerifiedAccess{}, cache.ErrUnauthorized
	}
	access, err := cache.HMACTokenVerifier{Keys: keys}.VerifyCacheAccessToken(ctx, token)
	if err != nil {
		return cache.VerifiedAccess{}, err
	}
	access.CarrierID = carrierID
	return access, nil
}

func (s *Server) PullCacheSegment(ctx context.Context, req cache.PullRequest) (cache.Entry, bool, error) {
	session := s.cacheCarriers.get(req.CarrierID)
	if session == nil {
		return cache.Entry{}, false, nil
	}
	return (cache.CarrierClient{Session: session}).Pull(ctx, req)
}

// setHandshakeOutcome records the bounded error-class outcome on the mint→relay
// span and marks the span's status. outcome is one of the dialOutcome*
// constants — never an identifier, token, hostname, or IP (ADR-0146 §9).
func setHandshakeOutcome(span trace.Span, outcome string) {
	span.SetAttributes(attribute.String("relay.handshake.outcome", outcome))
	if outcome == dialOutcomeSuccess {
		span.SetStatus(codes.Ok, "")
		return
	}
	span.SetStatus(codes.Error, outcome)
}

// serveCarrierSession registers session as a live carrier, sends the Ack
// frame over the handshake stream rw, and blocks until the session ends. It is
// shared by the TCP/yamux and QUIC carrier paths once each has produced a
// protocol.Session.
func (s *Server) serveCarrierSession(ctx context.Context, rw protocol.FrameReadWriter, session protocol.Session, verified VerifiedCarrier) {
	if verified.Surface == protocol.SurfaceCache {
		s.serveCacheCarrierSession(ctx, rw, session, verified)
		return
	}
	carrier := &carrier{
		id:            verified.ID,
		session:       session,
		streamCap:     s.streamCap,
		limiter:       newByteLimiter(s.rateBytes, s.rateBurst),
		fairUse:       s.fairUse,
		tunnelsActive: &s.metrics.tunnelsActive,
		drained:       make(chan struct{}),
		expiresAt:     verified.ExpiresAt,
	}
	if s.fairUse != nil {
		// Resolve the per-carrier usage entry once at connect time. The byte hot path
		// (recordBytes, per 32 KiB) then accounts directly against this cached pointer
		// instead of taking the limiter's global lock and scanning every tunnel on each
		// chunk. The carrier id is fixed for the connection's lifetime, and an actively
		// relaying carrier is never idle long enough to be evicted from the limiter map.
		carrier.usage = s.fairUse.tunnel(verified.ID)
	}
	accepted, refused := s.registry.register(carrier, verified.Hostnames)
	if len(refused) > 0 {
		if s.redactConnLogs {
			s.logger.Warn("carrier host conflict", "reason", "already_claimed_by_live_carrier")
		} else {
			s.logger.Warn("carrier host conflict", "id", verified.ID, "refused_hosts", refused, "reason", "already_claimed_by_live_carrier")
		}
	}
	if err := protocol.WriteFrame(rw, protocol.Frame{Type: protocol.FrameAck, Ack: &protocol.Ack{
		Version:   protocol.Version,
		CarrierID: verified.ID,
		Hostnames: accepted,
	}}); err != nil {
		s.registry.unregister(carrier)
		_ = session.Close()
		return
	}
	// The carrier is public-route ready only after registration produced at
	// least one route and the Ack completed. A connected carrier whose every
	// requested hostname conflicted cannot satisfy readiness.
	routeReady := len(accepted) > 0
	if routeReady {
		s.metrics.carriersConnected.Add(1)
	} else {
		s.metrics.nonServingCarriersConnected.Add(1)
	}
	defer func() {
		s.registry.unregister(carrier)
		if routeReady {
			s.metrics.carriersConnected.Add(-1)
		} else {
			s.metrics.nonServingCarriersConnected.Add(-1)
		}
		_ = session.Close()
	}()
	if s.redactConnLogs {
		s.logger.Info("carrier connected")
	} else {
		s.logger.Info("carrier connected", "id", verified.ID, "hosts", accepted)
	}
	s.awaitCarrierEnd(ctx, session, verified, carrier)
}

func (s *Server) serveCacheCarrierSession(ctx context.Context, rw protocol.FrameReadWriter, session protocol.Session, verified VerifiedCarrier) {
	if s.cacheCarriers != nil {
		s.cacheCarriers.register(verified.ID, session)
	}
	if err := protocol.WriteFrame(rw, protocol.Frame{Type: protocol.FrameAck, Ack: &protocol.Ack{
		Version:              protocol.Version,
		CarrierID:            verified.ID,
		Hostnames:            verified.Hostnames,
		Surface:              protocol.SurfaceCache,
		CacheProtocolVersion: protocol.CacheProtocolVersion,
	}}); err != nil {
		if s.cacheCarriers != nil {
			s.cacheCarriers.unregister(verified.ID, session)
		}
		_ = session.Close()
		return
	}
	s.metrics.nonServingCarriersConnected.Add(1)
	defer func() {
		s.metrics.nonServingCarriersConnected.Add(-1)
		if s.cacheCarriers != nil {
			s.cacheCarriers.unregister(verified.ID, session)
		}
		_ = session.Close()
	}()
	if s.cacheKeys != nil {
		s.cacheKeys.rotate(verified.ID, verified.CacheVerificationKey)
	}
	if s.redactConnLogs {
		s.logger.Info("cache carrier connected")
	} else {
		s.logger.Info("cache carrier connected", "id", verified.ID, "hosts", verified.Hostnames)
	}
	s.awaitCarrierEnd(ctx, session, verified, nil)
}

type cacheKeyRegistry struct {
	mu    sync.Mutex
	rings map[string]*cache.VerificationKeys
}

func newCacheKeyRegistry() *cacheKeyRegistry {
	return &cacheKeyRegistry{rings: make(map[string]*cache.VerificationKeys)}
}

func (r *cacheKeyRegistry) rotate(carrierID string, key []byte) {
	if r == nil || carrierID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if keys := r.rings[carrierID]; keys != nil {
		current := keys.Snapshot()[0]
		if !bytes.Equal(current, key) {
			_ = keys.Rotate(key)
		}
		return
	}
	keys, err := cache.NewVerificationKeys(key)
	if err != nil {
		return
	}
	r.rings[carrierID] = keys
}

func (r *cacheKeyRegistry) keys(carrierID string) *cache.VerificationKeys {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rings[carrierID]
}

type cacheCarrierRegistry struct {
	mu       sync.Mutex
	sessions map[string]protocol.Session
}

func newCacheCarrierRegistry() *cacheCarrierRegistry {
	return &cacheCarrierRegistry{sessions: make(map[string]protocol.Session)}
}

func (r *cacheCarrierRegistry) register(carrierID string, session protocol.Session) {
	if r == nil || carrierID == "" || session == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[carrierID] = session
}

func (r *cacheCarrierRegistry) unregister(carrierID string, session protocol.Session) {
	if r == nil || carrierID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[carrierID] == session {
		delete(r.sessions, carrierID)
	}
}

func (r *cacheCarrierRegistry) get(carrierID string) protocol.Session {
	if r == nil || carrierID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[carrierID]
}

// awaitCarrierEnd blocks until the carrier session ends, the server context is
// cancelled, or — when the verifying token carried an expires-at claim — that
// token expires. On expiry it closes the session so a still-open carrier is torn
// down at its token deadline, not merely refused on the next dial
// (RELAY-REVOKE-1). The verifier's deferred Close() then unregisters the carrier.
//
// verified.ExpiresAt is the token's own self-contained, already-verified expiry
// claim (ADR-0018 §5 short-TTL tunnel token), not a fetched revocation list or a
// playback-time phone-home; the teardown reads no external state. A zero
// ExpiresAt (e.g. the StaticTokenVerifier's shared-secret carriers) means no
// token-driven deadline, preserving the long-lived-session behavior.
func (s *Server) awaitCarrierEnd(ctx context.Context, session protocol.Session, verified VerifiedCarrier, carrier *carrier) {
	if verified.ExpiresAt.IsZero() {
		select {
		case <-session.CloseChan():
		case <-ctx.Done():
		}
		return
	}
	timer := time.NewTimer(time.Until(verified.ExpiresAt))
	defer timer.Stop()
	var drained <-chan struct{}
	if carrier != nil {
		drained = carrier.drained
	}
	select {
	case <-session.CloseChan():
	case <-ctx.Done():
	case <-drained:
		_ = session.Close()
		<-session.CloseChan()
	case <-timer.C:
		if carrier != nil && carrier.isDraining() && s.holdSupersededCarrier(ctx, session, carrier, verified.ExpiresAt) {
			return
		}
		if s.redactConnLogs {
			s.logger.Info("carrier token expired, tearing down session")
		} else {
			s.logger.Info("carrier token expired, tearing down session", "id", verified.ID)
		}
		_ = session.Close()
		<-session.CloseChan()
	}
}

// supersededSuccessorPoll is how often an expired superseded carrier rechecks
// whether a live same-identity carrier still holds its routes.
const supersededSuccessorPoll = time.Second

// holdSupersededCarrier keeps an expired, superseded carrier open for the
// streams already on it. While a live successor (hasLiveSuccessor) holds one of
// its hostnames it waits until expiresAt+supersededMaxAge. That successor holds
// an unexpired token, so the identity's authority stays bounded by a valid
// token. Once no live successor remains it waits at most expiredSessionDrain.
// When supersededMaxAge is set, it never waits past that deadline, even if
// the successor was already gone at expiry. It returns true when the session
// ended or the server context was cancelled, and false when the caller should
// close the session: its last stream finished or a bound elapsed.
func (s *Server) holdSupersededCarrier(ctx context.Context, session protocol.Session, carrier *carrier, expiresAt time.Time) bool {
	drainFor := s.expiredSessionDrain
	if s.supersededMaxAge > 0 {
		deadline := expiresAt.Add(s.supersededMaxAge)
		if s.registry.hasLiveSuccessor(carrier) && !s.awaitSuccessorLoss(ctx, session, carrier, deadline) {
			return session.IsClosed() || ctx.Err() != nil
		}
		drainFor = min(drainFor, time.Until(deadline))
	}
	if drainFor <= 0 {
		return false
	}
	drain := time.NewTimer(drainFor)
	defer drain.Stop()
	select {
	case <-session.CloseChan():
		return true
	case <-ctx.Done():
		return true
	case <-carrier.drained:
		return false
	case <-drain.C:
		return false
	}
}

// awaitSuccessorLoss waits while a live successor holds one of carrier's
// hostnames. It returns true once no live successor remains, and false when
// the session ended, ctx was cancelled, the last stream finished or the
// deadline passed.
func (s *Server) awaitSuccessorLoss(ctx context.Context, session protocol.Session, carrier *carrier, deadline time.Time) bool {
	maxAge := time.NewTimer(time.Until(deadline))
	defer maxAge.Stop()
	interval := s.supersededPoll
	if interval <= 0 {
		interval = supersededSuccessorPoll
	}
	poll := time.NewTicker(interval)
	defer poll.Stop()
	for s.registry.hasLiveSuccessor(carrier) {
		select {
		case <-session.CloseChan():
			return false
		case <-ctx.Done():
			return false
		case <-carrier.drained:
			return false
		case <-maxAge.C:
			return false
		case <-poll.C:
		}
	}
	return true
}

func (s *Server) handlePublicConn(ctx context.Context, conn net.Conn) {
	defer conn.Close() //nolint:errcheck // public connection cleanup.
	result, err := sni.PeekClientHello(conn, 64*1024, s.publicPeekT)
	if err != nil {
		if s.publicRejectLog.shouldLog("peek_failed") {
			if s.redactConnLogs {
				s.logger.Warn("public rejected", "err", err)
			} else {
				s.logger.Warn("public rejected", "remote", conn.RemoteAddr(), "err", err)
			}
		}
		return
	}
	carrier := s.registry.lookup(result.ServerName)
	if carrier == nil {
		if s.publicRejectLog.shouldLog("no_carrier") {
			if s.redactConnLogs {
				s.logger.Warn("public rejected", "reason", "no_carrier")
			} else {
				s.logger.Warn("public rejected", "remote", conn.RemoteAddr(), "host", result.ServerName, "reason", "no_carrier")
			}
		}
		return
	}
	source := sourcePrefix(conn.RemoteAddr())
	carrier, stream, release, err := s.openCarrierStream(result.ServerName, source, carrier)
	if errors.Is(err, errSourceCarrierCapReached) {
		if s.publicRejectLog.shouldLog("source_carrier_stream_cap_reached") {
			if s.redactConnLogs {
				s.logger.Warn("public rejected", "reason", "source_carrier_stream_cap_reached")
			} else {
				s.logger.Warn("public rejected", "remote", conn.RemoteAddr(), "host", result.ServerName, "carrier", carrier.id, "reason", "source_carrier_stream_cap_reached")
			}
		}
		return
	}
	if err != nil {
		if isFairUseThrottled(err) {
			s.metrics.fairUseRefusals.Add(1)
			if carrier.usage != nil && carrier.usage.shouldLogRefusal() {
				if s.redactConnLogs {
					s.logger.Warn("public rejected", "reason", "fair_use_throttled", "err", err)
				} else {
					s.logger.Warn("public rejected", "remote", conn.RemoteAddr(), "host", result.ServerName, "carrier", carrier.id, "reason", "fair_use_throttled", "err", err)
				}
			}
			return
		}
		if s.publicRejectLog.shouldLog("open_carrier_stream_failed") {
			if s.redactConnLogs {
				s.logger.Warn("public rejected", "reason", err)
			} else {
				s.logger.Warn("public rejected", "remote", conn.RemoteAddr(), "host", result.ServerName, "carrier", carrier.id, "reason", err)
			}
		}
		return
	}
	defer release()
	defer stream.Close() //nolint:errcheck // stream teardown during relay splice cleanup.
	// Track this as an in-flight relayed stream so graceful shutdown can drain
	// it within the grace window before force-closing carrier sessions.
	s.streamWG.Add(1)
	defer s.streamWG.Done()
	s.metrics.streamsActive.Add(1)
	defer s.metrics.streamsActive.Add(-1)
	if s.redactConnLogs {
		s.logger.Info("stream opened")
	} else {
		s.logger.Info("stream opened", "host", result.ServerName, "carrier", carrier.id, "remote", conn.RemoteAddr())
	}

	clientReader := io.MultiReader(bytesReader(result.Prefix), conn)
	s.splice(ctx, carrier, stream, conn, clientReader)
}

// openCarrierStream opens a stream for source on carrier, retrying once on a
// fresh carrier when the selected one entered drain between lookup and open.
// The per-source/per-carrier budget is acquired against the carrier the stream
// is actually opened on, and the returned release frees both the stream slot
// and that budget.
func (s *Server) openCarrierStream(host, source string, selected *carrier) (*carrier, net.Conn, func(), error) {
	openBudgeted := func(c *carrier) (*carrier, net.Conn, func(), error) {
		if !s.publicPerCarrier.acquire(source, c.id) {
			return c, nil, nil, errSourceCarrierCapReached
		}
		stream, release, err := c.open()
		if err != nil {
			s.publicPerCarrier.release(source, c.id)
			return c, stream, release, err
		}
		return c, stream, func() {
			if release != nil {
				release()
			}
			s.publicPerCarrier.release(source, c.id)
		}, nil
	}
	used, stream, release, err := openBudgeted(selected)
	if !errors.Is(err, errCarrierDraining) {
		return used, stream, release, err
	}
	fresh := s.registry.lookup(host)
	if fresh == nil || fresh == selected {
		return used, stream, release, err
	}
	return openBudgeted(fresh)
}

func connectionLogMode(redact bool) string {
	if redact {
		return "redacted"
	}
	return "metadata"
}

// spliceResult reports how one direction of a spliced copy ended: clean is true
// for a graceful EOF (the peer half-closed its write side) and false when the
// copy ended on an error (an abrupt disconnect of either end).
type spliceResult struct {
	clean bool
}

const abruptSpliceDeadline = 250 * time.Millisecond

// splice runs the byte-blind bidirectional pipe between the public client and the
// carrier upstream (yamux stream). It must satisfy two opposing requirements:
//
//   - A graceful half-close on one direction (clean EOF) must NOT tear down the
//     other: a client that half-closes its write side mid-request still expects
//     the in-flight download to finish, and vice versa. So we wait for BOTH
//     directions and only CloseWrite() the destination on a clean EOF.
//   - An abrupt disconnect of either peer (read/write error, not EOF) must tear
//     down BOTH halves. Otherwise the surviving copy can park forever reading
//     from a quiet-but-open peer that will never see the dead side, leaking the
//     goroutine, fd, stream-cap slot, and public-conn semaphore slot.
//
// We distinguish the two via copyWithLimit's error return: on the first direction
// to finish with an error we force-close both conns, which unblocks the parked
// read in the other direction so it returns promptly and the handler can clean up.
//
// Residual (accepted, 2026-06-13): a client that closes GRACEFULLY (FIN/clean EOF)
// while the upstream stays open-but-silent leaves the upstream->client copy parked
// until the upstream finally closes. At the byte level this is indistinguishable
// from a legitimate write-half-close + long download (the half-close-download case
// above), so we deliberately do NOT add an idle/inactivity deadline: a byte-blind
// timeout would also cut genuinely idle long-lived connections (websockets, SSE,
// long-poll). A well-behaved home backend closes on the propagated half-close, so
// this only bites a hung upstream -- MaxPublicConns + StreamCap bound the total
// exposure instead.
func (s *Server) splice(ctx context.Context, carrier *carrier, upstream net.Conn, client net.Conn, clientReader io.Reader) {
	done := make(chan spliceResult, 2)
	copyBytes := func(dst io.Writer, src io.Reader) {
		_, err := copyWithLimit(ctx, dst, src, carrier.limiter, func(n int64) {
			s.metrics.bytesRelayed.Add(n)
			if !carrier.recordBytes(n) {
				_ = upstream.Close()
				_ = client.Close()
			}
		})
		if err == nil {
			// Clean EOF: propagate the half-close so the peer sees it, but leave
			// the live opposite direction running.
			protocol.HalfCloseWrite(dst)
		}
		done <- spliceResult{clean: err == nil}
	}
	go copyBytes(upstream, clientReader)
	go copyBytes(client, upstream)

	if r := <-done; !r.clean {
		// One side died abruptly. Bound both blocked operations before aborting
		// both stream directions so a transport-specific half-close cannot park
		// the surviving copy indefinitely.
		deadline := time.Now().Add(abruptSpliceDeadline)
		_ = upstream.SetDeadline(deadline)
		_ = client.SetDeadline(deadline)
		protocol.AbortStream(upstream)
		protocol.AbortStream(client)
	}
	<-done
}

type byteSliceReader []byte

func bytesReader(b []byte) *byteSliceReader {
	r := byteSliceReader(b)
	return &r
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if len(*r) == 0 {
		return 0, io.EOF
	}
	n := copy(p, *r)
	*r = (*r)[n:]
	return n, nil
}

func copyWithLimit(ctx context.Context, dst io.Writer, src io.Reader, limiter *byteLimiter, record func(int64)) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			limiter.Wait(ctx, nr)
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				if record != nil {
					record(int64(nw))
				}
			}
			if ew != nil {
				return written, ew
			}
			if nw != nr {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}

type carrier struct {
	id            string
	session       protocol.Session
	streamCap     int
	active        int
	mu            sync.Mutex
	limiter       *byteLimiter
	fairUse       *fairUseLimiter
	usage         *tunnelUsage // cached fair-use accounting for c.id; nil if fairUse disabled
	tunnelsActive *atomic.Int64
	bytesRelayed  atomic.Int64
	draining      bool
	drained       chan struct{}
	drainOnce     sync.Once
	// expiresAt is the verified token expiry; zero means no token deadline.
	expiresAt time.Time
}

var errCarrierDraining = errors.New("carrier draining")

func (c *carrier) beginDrain() {
	c.mu.Lock()
	c.draining = true
	if c.drained == nil {
		c.drained = make(chan struct{})
	}
	if c.active == 0 {
		c.drainOnce.Do(func() { close(c.drained) })
	}
	c.mu.Unlock()
}

func (c *carrier) isDraining() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.draining
}

func (c *carrier) activate() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.draining {
		return errCarrierDraining
	}
	c.active++
	if c.active == 1 && c.tunnelsActive != nil {
		c.tunnelsActive.Add(1)
	}
	return nil
}

func (c *carrier) release() {
	c.mu.Lock()
	c.active--
	if c.active == 0 && c.tunnelsActive != nil {
		c.tunnelsActive.Add(-1)
	}
	if c.active == 0 && c.draining {
		c.drainOnce.Do(func() { close(c.drained) })
	}
	c.mu.Unlock()
}

func (c *carrier) open() (net.Conn, func(), error) {
	if c.usage != nil && c.fairUse.store != nil {
		reservation, err := c.usage.reserve(c.streamCap)
		if err != nil {
			return nil, func() {}, err
		}
		if err := c.activate(); err != nil {
			reservation.release()
			return nil, func() {}, err
		}
		stream, err := c.session.Open()
		if err != nil {
			c.release()
			reservation.release()
			return nil, func() {}, err
		}
		reservation.start(func() { _ = stream.Close() })
		return stream, func() {
			reservation.release()
			c.release()
		}, nil
	}
	limit := c.streamCap
	throttled := false
	if c.usage != nil && c.usage.hardLimited() {
		throttled = true
		limit = min(limit, c.usage.parent.throttledMaxConns)
	}
	c.mu.Lock()
	if c.draining {
		c.mu.Unlock()
		return nil, func() {}, errCarrierDraining
	}
	if c.active >= limit {
		c.mu.Unlock()
		if throttled {
			return nil, func() {}, errFairUseThrottled(limit)
		}
		return nil, func() {}, errors.New("stream cap reached")
	}
	c.active++
	// A carrier becomes an "active tunnel" the moment it starts relaying its first
	// in-flight stream (0->1), and stops being one when its last stream releases
	// (1->0). This is a distinct signal from carriers_connected, which counts every
	// handshaked carrier including idle ones.
	if c.active == 1 && c.tunnelsActive != nil {
		c.tunnelsActive.Add(1)
	}
	c.mu.Unlock()
	release := func() {
		c.release()
	}
	stream, err := c.session.Open()
	if err != nil {
		release()
		return nil, func() {}, err
	}
	return stream, release, nil
}

func (c *carrier) recordBytes(n int64) bool {
	if n <= 0 {
		return true
	}
	c.bytesRelayed.Add(n)
	if c.usage != nil {
		// Direct per-tunnel accounting via the cached pointer: no global limiter lock,
		// no full-map scan per chunk. usage.add does its own per-tunnel locking.
		return c.usage.add(n)
	}
	return true
}

type registry struct {
	mu       sync.RWMutex
	byHost   map[string]*carrier
	hostsFor map[*carrier][]string
}

func newRegistry() *registry {
	return &registry{byHost: make(map[string]*carrier), hostsFor: make(map[*carrier][]string)}
}

// register claims hostnames for carrier c on a first-writer-wins basis. A host
// already mapped to a still-live carrier of a DIFFERENT identity is NOT overwritten:
// silently stealing a live host would let a second carrier presenting the same allowed
// host hijack another's traffic (a takeover vector). Such hosts are returned in refused
// so the caller can log them. Two cases are still allowed to take over a host:
//   - a same-identity reconnect (existing.id == c.id): the carrier re-registering its
//     own host, e.g. after a network blip, before yamux has detected the stale session
//     as closed. Refusing this would break legitimate reconnection.
//   - a host owned by a closed carrier (e.g. one whose unregister has not yet run after
//     a crash), regardless of identity.
func (r *registry) register(c *carrier, hostnames []string) (accepted, refused []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	accepted = make([]string, 0, len(hostnames))
	for _, host := range hostnames {
		host = normalizeHost(host)
		existing := r.byHost[host]
		if existing != nil && existing.id != c.id && !existing.session.IsClosed() {
			refused = append(refused, host)
			continue
		}
		if existing != nil && existing != c && existing.id == c.id {
			existing.beginDrain()
		}
		r.byHost[host] = c
		accepted = append(accepted, host)
	}
	r.hostsFor[c] = accepted
	return accepted, refused
}

func (r *registry) unregister(c *carrier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, host := range r.hostsFor[c] {
		if r.byHost[host] == c {
			// r.mu orders register/unregister. Pointer equality is the TOCTOU
			// guard: a stale carrier cannot delete a newer reconnect's host claim.
			delete(r.byHost, host)
		}
	}
	delete(r.hostsFor, c)
}

// hasLiveSuccessor reports whether a different carrier of c's identity that
// still has authority holds any hostname c registered: open, not itself
// superseded, and with an unexpired token. A superseded carrier can stay in
// byHost for hostnames its replacement did not claim, so it must not count, or
// expired carriers could extend each other along a partial-hostname chain.
func (r *registry) hasLiveSuccessor(c *carrier) bool {
	now := time.Now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, host := range r.hostsFor[c] {
		cur := r.byHost[host]
		if cur == nil || cur == c || cur.id != c.id || cur.session.IsClosed() || cur.isDraining() {
			continue
		}
		if cur.expiresAt.IsZero() || now.Before(cur.expiresAt) {
			return true
		}
	}
	return false
}

func (r *registry) lookup(host string) *carrier {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byHost[normalizeHost(host)]
}

func (r *registry) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for c := range r.hostsFor {
		_ = c.session.Close()
	}
}
