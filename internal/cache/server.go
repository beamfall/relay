package cache

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/beamfall/relay/internal/config"
)

type Config struct {
	Addr              string
	AdminAddr         string
	AdminAllowPublic  bool
	AdminMetricsToken string
	TLSConfig         *tls.Config
	TokenVerifier     TokenVerifier
	Store             *Store
	PrewarmSignal     PrewarmSignal
	PullThrough       PullFetcher
	PullWaitTimeout   time.Duration
	PrefetchHeadroom  PrefetchHeadroom
	Logger            *slog.Logger
}

type Miss struct {
	CarrierID    string
	SegmentSetID string
	Segment      string
}

type PrewarmSignal func(context.Context, Miss)

type PrefetchHeadroom func(context.Context, Miss) int

type Server struct {
	listener      net.Listener
	adminListener net.Listener
	httpServer    *http.Server
	adminServer   *http.Server
	verifier      TokenVerifier
	store         *Store
	prewarmSignal PrewarmSignal
	pullThrough   PullFetcher
	pullTimeout   time.Duration
	headroom      PrefetchHeadroom
	logger        *slog.Logger
	metrics       metrics
	missCoalescer missCoalescer
	pulls         pullFlights
	wg            sync.WaitGroup
	closeOnce     sync.Once
	lifecycleMu   sync.Mutex
	closing       bool
}

func Start(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:9444"
	}
	if cfg.TLSConfig == nil {
		return nil, errors.New("cache TLS config is required")
	}
	if cfg.TokenVerifier == nil {
		return nil, errors.New("cache token verifier is required")
	}
	if v, ok := cfg.TokenVerifier.(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return nil, fmt.Errorf("cache token verifier: %w", err)
		}
	}
	if cfg.Store == nil {
		return nil, errors.New("cache store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.PullWaitTimeout <= 0 {
		cfg.PullWaitTimeout = 5 * time.Second
	}

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen cache: %w", err)
	}
	s := &Server{
		listener:      tls.NewListener(ln, cfg.TLSConfig),
		verifier:      cfg.TokenVerifier,
		store:         cfg.Store,
		prewarmSignal: cfg.PrewarmSignal,
		pullThrough:   cfg.PullThrough,
		pullTimeout:   cfg.PullWaitTimeout,
		headroom:      cfg.PrefetchHeadroom,
		logger:        cfg.Logger,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/cache/v1/segments/", s.handleSegment)
	s.httpServer = &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if cfg.AdminAddr != "" {
		warning, err := config.AdminExposureCheck(cfg.AdminAddr, cfg.AdminAllowPublic)
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("cache admin listener: %w", err)
		}
		if warning != "" {
			s.logger.Warn("cache admin listener exposure", "warning", warning)
		}
		loopbackOnly := config.AdminAddrIsLoopback(cfg.AdminAddr)
		if !loopbackOnly && cfg.AdminMetricsToken == "" {
			_ = s.Close()
			return nil, fmt.Errorf("cache admin listener %q is not loopback-only; /metrics requires an operator credential", cfg.AdminAddr)
		}
		adminMux := http.NewServeMux()
		adminMux.HandleFunc("/healthz", s.healthz)
		metricsHandler := http.HandlerFunc(s.handleMetrics)
		if !loopbackOnly {
			adminMux.Handle("/metrics", requireBearerToken(cfg.AdminMetricsToken, metricsHandler))
		} else {
			adminMux.Handle("/metrics", metricsHandler)
		}
		adminListener, err := net.Listen("tcp", cfg.AdminAddr)
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("listen cache admin: %w", err)
		}
		s.adminListener = adminListener
		s.adminServer = &http.Server{
			Addr:              cfg.AdminAddr,
			Handler:           adminMux,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.adminServer.Serve(adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error("cache admin server stopped", "err", err)
			}
		}()
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.httpServer.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("cache server stopped", "err", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return s, nil
}

func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

func (s *Server) AdminAddr() string {
	if s.adminListener == nil {
		return ""
	}
	return s.adminListener.Addr().String()
}

func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.lifecycleMu.Lock()
		s.closing = true
		s.lifecycleMu.Unlock()
		if s.httpServer != nil {
			err = errors.Join(err, s.httpServer.Close())
		}
		if s.adminServer != nil {
			err = errors.Join(err, s.adminServer.Close())
		}
		s.pulls.close()
		s.wg.Wait()
	})
	return err
}

func (s *Server) handleSegment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		s.metrics.unauthorized.Add(1)
		w.Header().Set("WWW-Authenticate", `Bearer realm="relay-cache"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	access, err := s.verifier.VerifyCacheAccessToken(r.Context(), token)
	if err != nil {
		s.metrics.unauthorized.Add(1)
		w.Header().Set("WWW-Authenticate", `Bearer realm="relay-cache"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	segment := strings.TrimPrefix(r.URL.Path, "/cache/v1/segments/")
	entry, ok, err := s.store.Get(access.SegmentSetID, segment)
	if err != nil {
		s.metrics.errors.Add(1)
		http.Error(w, "cache error", http.StatusInternalServerError)
		return
	}
	if !ok {
		s.metrics.misses.Add(1)
		if pulled, pulledOK := s.pullSegment(r.Context(), Miss{CarrierID: access.CarrierID, SegmentSetID: access.SegmentSetID, Segment: segment}, true); pulledOK {
			s.serveEntry(w, pulled)
			return
		}
		s.signalMiss(r.Context(), Miss{CarrierID: access.CarrierID, SegmentSetID: access.SegmentSetID, Segment: segment})
		http.NotFound(w, r)
		return
	}
	s.metrics.hits.Add(1)
	s.serveEntry(w, entry)
}

func (s *Server) serveEntry(w http.ResponseWriter, entry Entry) {
	s.metrics.bytesServed.Add(int64(len(entry.Bytes)))
	w.Header().Set("Content-Type", entry.ContentType)
	w.Header().Set("Cache-Control", "private, max-age=60")
	_, _ = w.Write(entry.Bytes)
}

func (s *Server) pullSegment(ctx context.Context, miss Miss, prefetch bool) (Entry, bool) {
	if s.pullThrough == nil {
		return Entry{}, false
	}
	waitCtx, cancel := context.WithTimeout(ctx, s.pullTimeout)
	defer cancel()
	res, ok := s.pulls.do(waitCtx, miss, func() pullResult {
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.pullTimeout)
		defer cancel()
		entry, found, err := s.pullThrough(fetchCtx, PullRequest(miss))
		if err != nil || !found {
			return pullResult{err: err}
		}
		if err := s.storePulled(miss, entry); err != nil {
			return pullResult{err: err}
		}
		if prefetch {
			s.startPrefetch(context.WithoutCancel(ctx), miss)
		}
		return pullResult{entry: entry, ok: true}
	})
	if !ok || res.err != nil {
		return Entry{}, false
	}
	return res.entry, res.ok
}

func (s *Server) startPrefetch(ctx context.Context, miss Miss) {
	s.lifecycleMu.Lock()
	if s.closing {
		s.lifecycleMu.Unlock()
		return
	}
	s.wg.Add(1)
	s.lifecycleMu.Unlock()
	go func() {
		defer s.wg.Done()
		s.prefetchAfter(ctx, miss)
	}()
}

func (s *Server) storePulled(miss Miss, entry Entry) error {
	err := s.store.Put(miss.SegmentSetID, miss.Segment, entry)
	if errors.Is(err, ErrQuotaExceeded) {
		s.metrics.quotaExceeded.Add(1)
		return nil
	}
	return err
}

func (s *Server) prefetchAfter(ctx context.Context, miss Miss) {
	limit := s.prefetchLimit(ctx, miss)
	next := miss.Segment
	for range limit {
		var ok bool
		next, ok = nextSegment(next)
		if !ok {
			return
		}
		prefetchCtx, cancel := context.WithTimeout(ctx, s.pullTimeout)
		_, pulled := s.pullSegment(prefetchCtx, Miss{CarrierID: miss.CarrierID, SegmentSetID: miss.SegmentSetID, Segment: next}, false)
		cancel()
		if !pulled {
			return
		}
	}
}

func (s *Server) prefetchLimit(ctx context.Context, miss Miss) int {
	if s.headroom == nil {
		return 0
	}
	n := s.headroom(ctx, miss)
	if n > 3 {
		return 3
	}
	if n < 0 {
		return 0
	}
	return n
}

func nextSegment(segment string) (string, bool) {
	ext := path.Ext(segment)
	stem := strings.TrimSuffix(segment, ext)
	i := len(stem)
	for i > 0 && stem[i-1] >= '0' && stem[i-1] <= '9' {
		i--
	}
	if i == len(stem) {
		return "", false
	}
	n, err := strconv.Atoi(stem[i:])
	if err != nil {
		return "", false
	}
	return stem[:i] + fmt.Sprintf("%0*d", len(stem[i:]), n+1) + ext, true
}

func (s *Server) signalMiss(ctx context.Context, miss Miss) {
	if s.prewarmSignal == nil || !s.missCoalescer.start(miss.SegmentSetID) {
		return
	}
	go func() {
		defer s.missCoalescer.done(miss.SegmentSetID)
		s.prewarmSignal(context.WithoutCancel(ctx), miss)
	}()
}

type missCoalescer struct {
	mu       sync.Mutex
	inflight map[string]struct{}
}

func (c *missCoalescer) start(segmentSetID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight == nil {
		c.inflight = make(map[string]struct{})
	}
	if _, ok := c.inflight[segmentSetID]; ok {
		return false
	}
	c.inflight[segmentSetID] = struct{}{}
	return true
}

func (c *missCoalescer) done(segmentSetID string) {
	c.mu.Lock()
	delete(c.inflight, segmentSetID)
	c.mu.Unlock()
}

type pullResult struct {
	entry Entry
	ok    bool
	err   error
}

type pullFlight struct {
	done chan struct{}
	res  pullResult
}

type pullFlights struct {
	mu             sync.Mutex
	inflight       map[string]*pullFlight
	wg             sync.WaitGroup
	closing        bool
	waiterCanceled chan struct{} // test-only timeout signal
}

func (f *pullFlights) do(ctx context.Context, miss Miss, fn func() pullResult) (pullResult, bool) {
	key := miss.CarrierID + "\x00" + miss.SegmentSetID + "\x00" + miss.Segment
	f.mu.Lock()
	if f.closing {
		f.mu.Unlock()
		return pullResult{err: context.Canceled}, false
	}
	if f.inflight == nil {
		f.inflight = make(map[string]*pullFlight)
	}
	flight := f.inflight[key]
	if flight == nil {
		flight = &pullFlight{done: make(chan struct{})}
		f.inflight[key] = flight
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			flight.res = fn()
			close(flight.done)
			f.mu.Lock()
			delete(f.inflight, key)
			f.mu.Unlock()
		}()
	}
	f.mu.Unlock()
	select {
	case <-flight.done:
		return flight.res, true
	case <-ctx.Done():
		if f.waiterCanceled != nil {
			select {
			case f.waiterCanceled <- struct{}{}:
			default:
			}
		}
		return pullResult{err: ctx.Err()}, false
	}
}

func (f *pullFlights) close() {
	f.mu.Lock()
	f.closing = true
	f.mu.Unlock()
	f.wg.Wait()
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(w, "beamfall_cache_hits_total %d\n", s.metrics.hits.Load())
	_, _ = fmt.Fprintf(w, "beamfall_cache_misses_total %d\n", s.metrics.misses.Load())
	_, _ = fmt.Fprintf(w, "beamfall_cache_unauthorized_total %d\n", s.metrics.unauthorized.Load())
	_, _ = fmt.Fprintf(w, "beamfall_cache_errors_total %d\n", s.metrics.errors.Load())
	_, _ = fmt.Fprintf(w, "beamfall_cache_bytes_served_total %d\n", s.metrics.bytesServed.Load())
	_, _ = fmt.Fprintf(w, "beamfall_cache_quota_exceeded_total %d\n", s.metrics.quotaExceeded.Load())
}

type metrics struct {
	hits          atomic.Int64
	misses        atomic.Int64
	unauthorized  atomic.Int64
	errors        atomic.Int64
	bytesServed   atomic.Int64
	quotaExceeded atomic.Int64
}

func requireBearerToken(token string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		gotSum := sha256.Sum256([]byte(got))
		if !ok || subtle.ConstantTimeCompare(gotSum[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="relay-cache-metrics"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
