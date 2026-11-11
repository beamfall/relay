package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/beamfall/relay/internal/cache"
	"github.com/beamfall/relay/internal/protocol"
)

const (
	defaultBackoffMin  = time.Second
	defaultBackoffMax  = 60 * time.Second
	defaultMaxStreams  = 64
	streamDrainTimeout = 5 * time.Second
	// defaultBackendDialTimeout bounds the dial to cfg.BackendAddr so a
	// blackholed backend can't wedge a handleStream goroutine (and its slots
	// semaphore entry) for the OS connect timeout, unresponsive to shutdown.
	defaultBackendDialTimeout = 10 * time.Second

	// TransportTCP is the v1 carrier: TLS/TCP with yamux multiplexing.
	TransportTCP = "tcp"
	// TransportQUIC is the ADR-0018 §1 v2 carrier: QUIC streams, giving each
	// relayed stream its own flow-control window so one stalled or
	// high-bitrate stream no longer head-of-line-blocks its siblings.
	TransportQUIC = "quic"
)

type Config struct {
	RelayAddr     string
	BackendAddr   string
	Token         []byte
	TokenProvider func(context.Context) ([]byte, error)
	Hostnames     []string
	TLSConfig     *tls.Config
	Logger        *slog.Logger
	// BackoffMin and BackoffMax bound the reconnect backoff. Zero values fall
	// back to defaults (1s..60s).
	BackoffMin time.Duration
	BackoffMax time.Duration
	// TokenRotationInterval proactively establishes a replacement passthrough
	// carrier at this cadence while the prior carrier remains alive to drain.
	// Zero disables proactive rotation.
	TokenRotationInterval time.Duration
	// MaxStreams bounds concurrently served inbound relay streams. <=0 uses a default.
	MaxStreams int
	// Transport selects the carrier wire transport: TransportTCP (default) or
	// TransportQUIC. RelayAddr must point at the matching relay listener.
	Transport string
	// YamuxStreamWindowBytes overrides the v1 (TransportTCP) carrier's
	// per-stream flow-control window. <=0 uses
	// protocol.DefaultYamuxStreamWindowBytes (1 MiB). Ignored for TransportQUIC.
	// MUST match the relay's relay.Config.YamuxStreamWindowBytes, since yamux
	// requires both ends of a session to agree on window size.
	YamuxStreamWindowBytes int
	// CarrierDialTimeout, CarrierTLSHandshakeTimeout, CarrierHelloTimeout, and
	// CarrierAckTimeout bound the four carrier-establishment phases. Zero uses
	// production defaults (10s, 10s, 5s, and 5s respectively). Each phase is
	// capped at 30s and their sum is capped at 60s.
	CarrierDialTimeout         time.Duration
	CarrierTLSHandshakeTimeout time.Duration
	CarrierHelloTimeout        time.Duration
	CarrierAckTimeout          time.Duration
	// CacheCarrier enables a second dedicated carrier connection for the Media
	// Cache surface. It uses the same relay address, transport, TLS config, and
	// reconnect/backoff policy as the passthrough carrier.
	CacheCarrier bool
	CacheToken   []byte
	// CacheTokenProvider overrides CacheToken the same way TokenProvider
	// overrides Token, allowing the cache surface to use separate credentials.
	CacheTokenProvider func(context.Context) ([]byte, error)
	// CacheVerificationKeyProvider overrides CacheVerificationKey the same way
	// TokenProvider overrides Token, allowing a fresh cache HMAC key on each
	// cache-carrier reconnect.
	CacheVerificationKeyProvider func(context.Context) ([]byte, error)
	CacheVerificationKey         []byte
	CachePullThrough             cache.PullFetcher
}

type Client struct {
	cfg        Config
	logger     *slog.Logger
	backoffMin time.Duration
	backoffMax time.Duration
	maxStreams int

	done chan struct{}

	closeOnce sync.Once
	closed    chan struct{} // closed by Close() to permanently stop reconnect

	mu      sync.Mutex
	cond    *sync.Cond
	conn    io.Closer // the raw carrier connection (TLS/TCP conn or QUIC conn)
	session protocol.Session
	attempt *carrierAttempt

	cacheConn    io.Closer
	cacheSession protocol.Session
	cacheAttempt *carrierAttempt
	wg           sync.WaitGroup

	dialCarrier          carrierDialFunc
	handshakeTLSCarrier  carrierTLSHandshakeFunc
	dialQUICCarrier      carrierQUICDialFunc
	handshakeQUICCarrier carrierQUICHandshakeFunc
	writeHelloCarrier    carrierHelloFunc
	readAckCarrier       carrierAckFunc
}

type sessionStreams struct {
	mu             sync.Mutex
	backends       map[net.Conn]struct{}
	active         int
	sessionClosed  bool
	acceptFinished bool
	drained        chan struct{}
}

func newSessionStreams() *sessionStreams {
	return &sessionStreams{
		backends: make(map[net.Conn]struct{}),
		drained:  make(chan struct{}),
	}
}

func (s *sessionStreams) begin() {
	s.mu.Lock()
	s.active++
	s.mu.Unlock()
}

func (s *sessionStreams) attachBackend(backend net.Conn) bool {
	s.mu.Lock()
	if s.sessionClosed {
		s.mu.Unlock()
		_ = backend.Close()
		return false
	}
	s.backends[backend] = struct{}{}
	s.mu.Unlock()
	return true
}

func (s *sessionStreams) finish(backend net.Conn) {
	s.mu.Lock()
	delete(s.backends, backend)
	s.active--
	s.closeDrainedLocked()
	s.mu.Unlock()
}

func (s *sessionStreams) closeBackends() {
	s.mu.Lock()
	s.sessionClosed = true
	backends := make([]net.Conn, 0, len(s.backends))
	for backend := range s.backends {
		backends = append(backends, backend)
	}
	s.mu.Unlock()
	for _, backend := range backends {
		_ = backend.Close()
	}
}

func (s *sessionStreams) finishAccepting() {
	s.mu.Lock()
	s.acceptFinished = true
	s.closeDrainedLocked()
	s.mu.Unlock()
}

func (s *sessionStreams) closeDrainedLocked() {
	if s.acceptFinished && s.active == 0 {
		close(s.drained)
		s.acceptFinished = false
	}
}

func (s *sessionStreams) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Start launches the tunnel client. It returns immediately once configuration
// is validated; the carrier dial happens asynchronously inside a reconnect loop
// so a relay restart or transient blip is recovered automatically with backoff.
func Start(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.RelayAddr == "" {
		return nil, errors.New("relay addr is required")
	}
	if cfg.BackendAddr == "" {
		return nil, errors.New("backend addr is required")
	}
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	if err := normalizeCarrierTimeouts(&cfg); err != nil {
		return nil, err
	}
	switch cfg.Transport {
	case "":
		cfg.Transport = TransportTCP
	case TransportTCP, TransportQUIC:
	default:
		return nil, fmt.Errorf("unknown carrier transport %q (want %q or %q)", cfg.Transport, TransportTCP, TransportQUIC)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	backoffMin := cfg.BackoffMin
	if backoffMin <= 0 {
		backoffMin = defaultBackoffMin
	}
	backoffMax := cfg.BackoffMax
	if backoffMax < backoffMin {
		backoffMax = defaultBackoffMax
	}
	if backoffMax < backoffMin {
		backoffMax = backoffMin
	}
	maxStreams := cfg.MaxStreams
	if maxStreams <= 0 {
		maxStreams = defaultMaxStreams
	}

	c := &Client{
		cfg:        cfg,
		logger:     logger,
		backoffMin: backoffMin,
		backoffMax: backoffMax,
		maxStreams: maxStreams,
		done:       make(chan struct{}),
		closed:     make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	c.wg.Add(1)
	go c.runPassthrough(ctx)
	if cfg.CacheCarrier {
		c.wg.Add(1)
		go c.run(ctx, c.serveCacheOnce)
	}
	go func() {
		c.wg.Wait()
		close(c.done)
	}()
	return c, nil
}

// WaitReady blocks until the client has a live carrier session or ctx is done.
// It returns nil once a session is established, or ctx.Err() if cancelled first.
// Across reconnects it reflects the current state: if the session is live it
// returns immediately.
func (c *Client) WaitReady(ctx context.Context) error {
	// Wake the cond waiter when ctx is cancelled so we don't block forever.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			c.broadcastLocked()
			c.mu.Unlock()
		case <-stop:
		}
	}()

	c.mu.Lock()
	defer c.mu.Unlock()
	for c.session == nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c.isClosed() {
			return errors.New("tunnel client closed")
		}
		c.cond.Wait()
	}
	return nil
}

// Close permanently stops the client: it ends the reconnect loop and tears down
// the active carrier session, if any. Idempotent and safe to call concurrently.
// After Close the client does not reconnect even if the context is still live.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	c.mu.Lock()
	session := c.session
	conn := c.conn
	attempt := c.attempt
	cacheSession := c.cacheSession
	cacheConn := c.cacheConn
	cacheAttempt := c.cacheAttempt
	c.broadcastLocked()
	c.mu.Unlock()
	if attempt != nil {
		attempt.cancel()
	}
	if session != nil {
		_ = session.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
	if cacheSession != nil {
		_ = cacheSession.Close()
	}
	if cacheAttempt != nil {
		cacheAttempt.cancel()
	}
	if cacheConn != nil {
		_ = cacheConn.Close()
	}
}

// Wait blocks until the reconnect loop has exited (context cancelled).
func (c *Client) Wait() {
	<-c.done
}

// run owns the reconnect loop: dial+serve a single carrier session, and on loss
// re-dial with exponential backoff + jitter until the context is cancelled or
// Close is called.
func (c *Client) run(ctx context.Context, serve func(context.Context) (bool, error)) {
	defer c.wg.Done()
	backoff := c.backoffMin
	for {
		if ctx.Err() != nil || c.isClosed() {
			return
		}
		wentLive, err := serve(ctx)
		if ctx.Err() != nil || c.isClosed() {
			return
		}
		// Reset backoff after a session that actually came up, so a single
		// transient blip reconnects fast instead of escalating the delay.
		if wentLive {
			backoff = c.backoffMin
		}
		if err != nil {
			c.logger.Info("tunnel carrier session ended, reconnecting", "err", err)
		} else {
			c.logger.Info("tunnel carrier session ended, reconnecting")
		}

		// Sleep for backoff with jitter, fully cancellable on shutdown.
		delay := jitter(backoff)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-c.closed:
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = nextBackoff(backoff, c.backoffMax)
	}
}

type carrierResult struct {
	generation int
	wentLive   bool
	err        error
}

func (c *Client) runPassthrough(ctx context.Context) {
	if c.cfg.TokenRotationInterval <= 0 {
		c.run(ctx, c.serveOnce)
		return
	}
	c.runRotating(ctx)
}

// runRotating overlaps carrier generations: the replacement is fully
// handshaked before the relay routes new streams to it, while the displaced
// generation keeps serving streams it already accepted until the relay closes
// it after the expiry drain window.
func (c *Client) runRotating(ctx context.Context) {
	defer c.wg.Done()
	results := make(chan carrierResult)
	live := make(chan int)
	generation := 0
	active := 0
	latest := 0
	backoff := c.backoffMin

	launch := func() {
		generation++
		latest = generation
		active++
		go func(current int) {
			wentLive, err := c.serveOnceReady(ctx, func() {
				select {
				case live <- current:
				case <-ctx.Done():
				case <-c.closed:
				}
			})
			results <- carrierResult{generation: current, wentLive: wentLive, err: err}
		}(generation)
	}
	launch()

	rotation := time.NewTimer(c.cfg.TokenRotationInterval)
	if !rotation.Stop() {
		<-rotation.C
	}
	defer rotation.Stop()
	var rotationC <-chan time.Time
	var retry *time.Timer
	var retryC <-chan time.Time
	ctxDone := ctx.Done()
	closed := c.closed
	shuttingDown := false

	for active > 0 || !shuttingDown {
		select {
		case <-ctxDone:
			shuttingDown = true
			ctxDone = nil
			closed = nil
			stopTimer(rotation)
			rotationC = nil
			if retry != nil {
				retry.Stop()
			}
			retryC = nil
		case <-closed:
			shuttingDown = true
			ctxDone = nil
			closed = nil
			stopTimer(rotation)
			rotationC = nil
			if retry != nil {
				retry.Stop()
			}
			retryC = nil
		case current := <-live:
			if shuttingDown || current != latest {
				continue
			}
			backoff = c.backoffMin
			resetTimer(rotation, c.cfg.TokenRotationInterval)
			rotationC = rotation.C
		case result := <-results:
			active--
			if shuttingDown || result.generation != latest {
				continue
			}
			if result.wentLive {
				backoff = c.backoffMin
			}
			if result.err != nil {
				c.logger.Info("tunnel carrier session ended, reconnecting", "err", result.err)
			} else {
				c.logger.Info("tunnel carrier session ended, reconnecting")
			}
			stopTimer(rotation)
			rotationC = nil
			delay := jitter(backoff)
			retry = time.NewTimer(delay)
			retryC = retry.C
			backoff = nextBackoff(backoff, c.backoffMax)
		case <-retryC:
			retryC = nil
			launch()
		case <-rotationC:
			rotationC = nil
			launch()
		}
	}
}

func stopTimer(timer *time.Timer) {
	if timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func resetTimer(timer *time.Timer, delay time.Duration) {
	stopTimer(timer)
	timer.Reset(delay)
}

func (c *Client) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *Client) broadcastLocked() {
	if c.cond != nil {
		c.cond.Broadcast()
	}
}

// serveOnce dials the carrier, performs the handshake, and serves streams until
// the session ends or the context is cancelled. The bool reports whether a live
// session was established (used by the caller to reset backoff); the error is
// the cause of the session ending (nil for a clean context-driven exit).
func (c *Client) serveOnce(ctx context.Context) (wentLive bool, err error) {
	return c.serveOnceReady(ctx, nil)
}

func (c *Client) serveOnceReady(ctx context.Context, ready func()) (wentLive bool, err error) {
	token := c.cfg.Token
	if c.cfg.TokenProvider != nil {
		token, err = c.cfg.TokenProvider(ctx)
		if err != nil {
			return false, fmt.Errorf("load tunnel token: %w", err)
		}
	}

	attempt, attemptCtx, err := c.beginCarrierAttempt(ctx, false)
	if err != nil {
		return false, err
	}
	defer c.abortCarrierAttempt(attempt, false)

	conn, session, err := c.establishCarrier(attemptCtx, attempt, token, passthroughHello(), false)
	if err != nil {
		return false, err
	}
	if err := c.activateCarrier(attemptCtx, attempt, conn, session, false); err != nil {
		_ = session.Close()
		_ = conn.Close()
		return false, err
	}
	c.logger.Info("tunnel connected", "relay", c.cfg.RelayAddr, "backend", c.cfg.BackendAddr, "hosts", c.cfg.Hostnames)
	if ready != nil {
		ready()
	}

	// Tear the session down on context cancel or Close so the blocking
	// Accept loop unblocks promptly. ended fires when serveOnce returns.
	ended := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-c.closed:
			_ = session.Close()
		case <-ended:
		}
	}()

	defer func() {
		close(ended)
		_ = session.Close()
		_ = conn.Close()
		c.mu.Lock()
		if c.session == session {
			c.session = nil
			c.conn = nil
		}
		c.broadcastLocked()
		c.mu.Unlock()
	}()

	return true, c.accept(ctx, session)
}

func (c *Client) serveCacheOnce(ctx context.Context) (wentLive bool, err error) {
	token := c.cfg.CacheToken
	if c.cfg.CacheTokenProvider != nil {
		token, err = c.cfg.CacheTokenProvider(ctx)
		if err != nil {
			return false, fmt.Errorf("load cache carrier token: %w", err)
		}
	}
	key := c.cfg.CacheVerificationKey
	if c.cfg.CacheVerificationKeyProvider != nil {
		key, err = c.cfg.CacheVerificationKeyProvider(ctx)
		if err != nil {
			return false, fmt.Errorf("load cache verification key: %w", err)
		}
	}
	if err := cache.ValidateTokenKey(key); err != nil {
		return false, err
	}

	attempt, attemptCtx, err := c.beginCarrierAttempt(ctx, true)
	if err != nil {
		return false, err
	}
	defer c.abortCarrierAttempt(attempt, true)

	conn, session, err := c.establishCarrier(attemptCtx, attempt, token, c.cacheHello(key), true)
	if err != nil {
		return false, err
	}
	if err := c.activateCarrier(attemptCtx, attempt, conn, session, true); err != nil {
		_ = session.Close()
		_ = conn.Close()
		return false, err
	}
	c.logger.Info("cache carrier connected", "relay", c.cfg.RelayAddr, "hosts", c.cfg.Hostnames)

	ended := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-c.closed:
			_ = session.Close()
		case <-ended:
		}
	}()

	defer func() {
		close(ended)
		_ = session.Close()
		_ = conn.Close()
		c.mu.Lock()
		if c.cacheSession == session {
			c.cacheSession = nil
			c.cacheConn = nil
		}
		c.mu.Unlock()
	}()

	errCh := make(chan error, 1)
	if c.cfg.CachePullThrough != nil {
		go func() {
			errCh <- (cache.CarrierHandler{Pull: c.cfg.CachePullThrough}).Serve(ctx, session)
		}()
	}
	select {
	case err := <-errCh:
		return true, err
	case <-session.CloseChan():
		return true, errors.New("cache carrier session closed")
	case <-ctx.Done():
		return true, nil
	case <-c.closed:
		return true, nil
	}
}

// accept serves inbound streams for a single live session until Accept fails
// (session closed by relay loss or shutdown) or the context is cancelled.
func (c *Client) accept(ctx context.Context, session protocol.Session) error {
	streams := newSessionStreams()
	slots := make(chan struct{}, c.maxStreams)
	watcherDone := make(chan struct{})
	go func() {
		select {
		case <-session.CloseChan():
			streams.closeBackends()
		case <-watcherDone:
		}
	}()
	defer close(watcherDone)
	for {
		stream, err := session.Accept()
		if err != nil {
			streams.closeBackends()
			streams.finishAccepting()
			if ctx.Err() != nil || c.isClosed() {
				<-streams.drained
				return nil
			}
			c.watchStreamDrain(streams)
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			c.logger.Warn("tunnel stream cap reached")
			_ = stream.Close()
			continue
		}
		streams.begin()
		go func() {
			defer func() { <-slots }()
			c.handleStream(ctx, stream, streams)
		}()
	}
}

func (c *Client) watchStreamDrain(streams *sessionStreams) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		timer := time.NewTimer(streamDrainTimeout)
		defer timer.Stop()
		select {
		case <-streams.drained:
		case <-timer.C:
			c.logger.Debug("tunnel stream drain timed out", "streams", streams.count())
		}
	}()
}

func (c *Client) handleStream(ctx context.Context, stream net.Conn, streams *sessionStreams) {
	defer stream.Close() //nolint:errcheck // stream cleanup after bidirectional copy.
	dialer := net.Dialer{Timeout: defaultBackendDialTimeout}
	backend, err := dialer.DialContext(ctx, "tcp", c.cfg.BackendAddr)
	if err != nil {
		c.logger.Warn("tunnel backend dial failed", "err", err)
		streams.finish(nil)
		return
	}
	defer backend.Close() //nolint:errcheck // backend cleanup after bidirectional copy.
	defer streams.finish(backend)
	if !streams.attachBackend(backend) {
		return
	}
	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(backend, stream)
		protocol.HalfCloseWrite(backend)
		done <- err
	}()
	go func() {
		_, err := io.Copy(stream, backend)
		protocol.HalfCloseWrite(stream)
		done <- err
	}()
	// Wait for BOTH directions to finish on normal completion. A backend (or
	// public client) that half-closes its write side makes one copy hit EOF
	// first; returning then would let the deferred close tear down the still-
	// active direction and truncate it. Each copy half-closes its destination via
	// protocol.HalfCloseWrite, so the half-close propagates without us cutting the
	// live direction. ctx.Done() still wins immediately so cancellation/shutdown
	// tears the stream down promptly.
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return
		case err := <-done:
			if err != nil {
				c.logger.Debug("tunnel stream copy ended abruptly", "err", err, "streams", streams.count())
			}
		}
	}
}

// nextBackoff doubles the current backoff, capped at max.
func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max || next <= 0 {
		return max
	}
	return next
}

// jitter returns d with up to ±20% full jitter applied, never negative.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	span := d / 5 // 20%
	if span <= 0 {
		return d
	}
	// rand in [-span, +span)
	delta := time.Duration(rand.Int63n(int64(2*span))) - span
	out := d + delta
	if out < 0 {
		return 0
	}
	return out
}
