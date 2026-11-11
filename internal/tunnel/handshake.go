package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"

	"github.com/beamfall/relay/internal/protocol"
)

const (
	defaultCarrierDialTimeout         = 10 * time.Second
	defaultCarrierTLSHandshakeTimeout = 10 * time.Second
	defaultCarrierHelloTimeout        = 5 * time.Second
	defaultCarrierAckTimeout          = 5 * time.Second
	maxCarrierPhaseTimeout            = 30 * time.Second
	maxCarrierTotalTimeout            = 60 * time.Second
)

var errTunnelClientClosed = errors.New("tunnel client closed")

type carrierDialFunc func(context.Context, string, string) (net.Conn, error)
type carrierTLSHandshakeFunc func(context.Context, net.Conn, *tls.Config) (net.Conn, error)
type carrierQUICDialFunc func(context.Context, string) (quicCarrier, error)
type carrierQUICHandshakeFunc func(context.Context, quicCarrier, *tls.Config) error
type carrierHelloFunc func(context.Context, protocol.FrameReadWriter, []byte, helloOptions) error
type carrierAckFunc func(context.Context, protocol.FrameReadWriter) error

type quicCarrier interface {
	io.Closer
	Handshake(context.Context, *tls.Config) error
	OpenHandshakeStream(context.Context) (protocol.FrameReadWriter, error)
	Session() protocol.Session
}

type carrierAttempt struct {
	cancel    context.CancelFunc
	conn      io.Closer
	stopClose func() bool
}

type onceConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *onceConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close() })
	return c.err
}

func normalizeCarrierTimeouts(cfg *Config) error {
	values := []struct {
		name         string
		value        *time.Duration
		defaultValue time.Duration
	}{
		{"carrier dial timeout", &cfg.CarrierDialTimeout, defaultCarrierDialTimeout},
		{"carrier TLS handshake timeout", &cfg.CarrierTLSHandshakeTimeout, defaultCarrierTLSHandshakeTimeout},
		{"carrier Hello timeout", &cfg.CarrierHelloTimeout, defaultCarrierHelloTimeout},
		{"carrier Ack timeout", &cfg.CarrierAckTimeout, defaultCarrierAckTimeout},
	}
	total := time.Duration(0)
	for _, item := range values {
		if *item.value < 0 {
			return fmt.Errorf("%s must not be negative", item.name)
		}
		if *item.value == 0 {
			*item.value = item.defaultValue
		}
		if *item.value > maxCarrierPhaseTimeout {
			return fmt.Errorf("%s %s exceeds hard maximum %s", item.name, *item.value, maxCarrierPhaseTimeout)
		}
		if total > maxCarrierTotalTimeout-*item.value {
			return fmt.Errorf("carrier establishment timeout total exceeds hard maximum %s", maxCarrierTotalTimeout)
		}
		total += *item.value
	}
	return nil
}

func (c *Client) carrierTotalTimeout() time.Duration {
	return c.cfg.CarrierDialTimeout +
		c.cfg.CarrierTLSHandshakeTimeout +
		c.cfg.CarrierHelloTimeout +
		c.cfg.CarrierAckTimeout
}

func (c *Client) beginCarrierAttempt(parent context.Context, cacheCarrier bool) (*carrierAttempt, context.Context, error) {
	if err := normalizeCarrierTimeouts(&c.cfg); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(parent, c.carrierTotalTimeout())
	attempt := &carrierAttempt{cancel: cancel}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed() {
		cancel()
		return nil, nil, errTunnelClientClosed
	}
	slot := &c.attempt
	if cacheCarrier {
		slot = &c.cacheAttempt
	}
	if *slot != nil {
		cancel()
		return nil, nil, errors.New("carrier establishment already in progress")
	}
	*slot = attempt
	return attempt, ctx, nil
}

func (c *Client) ownCarrierConn(ctx context.Context, attempt *carrierAttempt, conn io.Closer, cacheCarrier bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	slot, connSlot := &c.attempt, &c.conn
	if cacheCarrier {
		slot, connSlot = &c.cacheAttempt, &c.cacheConn
	}
	if *slot != attempt || c.isClosed() || ctx.Err() != nil {
		return contextError(ctx)
	}
	attempt.conn = conn
	attempt.stopClose = context.AfterFunc(ctx, func() { _ = conn.Close() })
	*connSlot = conn
	return nil
}

func (c *Client) activateCarrier(ctx context.Context, attempt *carrierAttempt, conn io.Closer, session protocol.Session, cacheCarrier bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if attempt.stopClose != nil && !attempt.stopClose() {
		return contextError(ctx)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	slot, connSlot, sessionSlot := &c.attempt, &c.conn, &c.session
	if cacheCarrier {
		slot, connSlot, sessionSlot = &c.cacheAttempt, &c.cacheConn, &c.cacheSession
	}
	if *slot != attempt || c.isClosed() || ctx.Err() != nil {
		return contextError(ctx)
	}
	*slot = nil
	*connSlot = conn
	*sessionSlot = session
	attempt.cancel()
	if !cacheCarrier {
		c.broadcastLocked()
	}
	return nil
}

func (c *Client) abortCarrierAttempt(attempt *carrierAttempt, cacheCarrier bool) {
	attempt.cancel()
	if attempt.stopClose != nil {
		attempt.stopClose()
	}
	c.mu.Lock()
	slot, connSlot := &c.attempt, &c.conn
	if cacheCarrier {
		slot, connSlot = &c.cacheAttempt, &c.cacheConn
	}
	if *slot == attempt {
		*slot = nil
		if *connSlot == attempt.conn {
			*connSlot = nil
		}
	}
	c.broadcastLocked()
	c.mu.Unlock()
	if attempt.conn != nil {
		_ = attempt.conn.Close()
	}
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errTunnelClientClosed
}

func (c *Client) establishCarrier(ctx context.Context, attempt *carrierAttempt, token []byte, hello helloOptions, cacheCarrier bool) (io.Closer, protocol.Session, error) {
	if c.cfg.Transport == TransportQUIC {
		return c.dialQUIC(ctx, attempt, token, hello, cacheCarrier)
	}
	return c.dialTCP(ctx, attempt, token, hello, cacheCarrier)
}

func (c *Client) dialTCP(ctx context.Context, attempt *carrierAttempt, token []byte, hello helloOptions, cacheCarrier bool) (io.Closer, protocol.Session, error) {
	dialCtx, cancel := context.WithTimeout(ctx, c.cfg.CarrierDialTimeout)
	dial := c.dialCarrier
	if dial == nil {
		dialer := net.Dialer{}
		dial = dialer.DialContext
	}
	raw, err := dial(dialCtx, "tcp", c.cfg.RelayAddr)
	dialContextErr := dialCtx.Err()
	cancel()
	if err != nil {
		return nil, nil, fmt.Errorf("connect relay carrier: %w", err)
	}
	conn := &onceConn{Conn: raw}
	if dialContextErr != nil || ctx.Err() != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("connect relay carrier: %w", firstContextError(dialContextErr, ctx.Err()))
	}
	if err := c.ownCarrierConn(ctx, attempt, conn, cacheCarrier); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	tlsConf, err := relayTLSConfig(c.cfg.TLSConfig, c.cfg.RelayAddr)
	if err != nil {
		return nil, nil, err
	}

	tlsCtx, cancel := context.WithTimeout(ctx, c.cfg.CarrierTLSHandshakeTimeout)
	tlsHandshake := c.handshakeTLSCarrier
	if tlsHandshake == nil {
		tlsHandshake = handshakeTLS
	}
	secure, err := tlsHandshake(tlsCtx, conn, tlsConf)
	tlsContextErr := tlsCtx.Err()
	cancel()
	if err != nil {
		return nil, nil, fmt.Errorf("TLS handshake with relay carrier: %w", err)
	}
	if tlsContextErr != nil || ctx.Err() != nil {
		return nil, nil, fmt.Errorf("TLS handshake with relay carrier: %w", firstContextError(tlsContextErr, ctx.Err()))
	}
	if err := c.handshake(ctx, secure, token, hello); err != nil {
		return nil, nil, err
	}
	session, err := yamux.Client(secure, protocol.YamuxConfig(c.cfg.YamuxStreamWindowBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("start yamux client: %w", err)
	}
	return conn, session, nil
}

func handshakeTLS(ctx context.Context, conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	secure := tls.Client(conn, cfg)
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return secure, nil
}

func relayTLSConfig(cfg *tls.Config, relayAddr string) (*tls.Config, error) {
	tlsConf := cfg.Clone()
	if tlsConf.ServerName == "" {
		host, _, err := net.SplitHostPort(relayAddr)
		if err != nil {
			return nil, fmt.Errorf("derive relay TLS server name: %w", err)
		}
		tlsConf.ServerName = host
	}
	return tlsConf, nil
}

func (c *Client) dialQUIC(ctx context.Context, attempt *carrierAttempt, token []byte, hello helloOptions, cacheCarrier bool) (io.Closer, protocol.Session, error) {
	tlsConf, err := relayTLSConfig(c.cfg.TLSConfig, c.cfg.RelayAddr)
	if err != nil {
		return nil, nil, err
	}
	if len(tlsConf.NextProtos) == 0 {
		tlsConf.NextProtos = []string{"beamfall-relay-carrier/1"}
	}

	dialCtx, cancel := context.WithTimeout(ctx, c.cfg.CarrierDialTimeout)
	dial := c.dialQUICCarrier
	if dial == nil {
		dial = dialQUICSocket
	}
	conn, err := dial(dialCtx, c.cfg.RelayAddr)
	dialContextErr := dialCtx.Err()
	cancel()
	if err != nil {
		return nil, nil, fmt.Errorf("connect relay quic carrier: %w", err)
	}
	if dialContextErr != nil || ctx.Err() != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("connect relay quic carrier: %w", firstContextError(dialContextErr, ctx.Err()))
	}
	if err := c.ownCarrierConn(ctx, attempt, conn, cacheCarrier); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	tlsCtx, cancel := context.WithTimeout(ctx, c.cfg.CarrierTLSHandshakeTimeout)
	handshake := c.handshakeQUICCarrier
	if handshake == nil {
		handshake = func(ctx context.Context, conn quicCarrier, cfg *tls.Config) error {
			return conn.Handshake(ctx, cfg)
		}
	}
	err = handshake(tlsCtx, conn, tlsConf)
	tlsContextErr := tlsCtx.Err()
	cancel()
	if err != nil {
		return nil, nil, fmt.Errorf("TLS handshake with relay quic carrier: %w", err)
	}
	if tlsContextErr != nil || ctx.Err() != nil {
		return nil, nil, fmt.Errorf("TLS handshake with relay quic carrier: %w", firstContextError(tlsContextErr, ctx.Err()))
	}

	helloCtx, cancel := context.WithTimeout(ctx, c.cfg.CarrierHelloTimeout)
	hsStream, err := conn.OpenHandshakeStream(helloCtx)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("open quic carrier handshake stream: %w", err)
	}
	if helloCtx.Err() != nil || ctx.Err() != nil {
		contextErr := firstContextError(helloCtx.Err(), ctx.Err())
		cancel()
		return nil, nil, fmt.Errorf("open quic carrier handshake stream: %w", contextErr)
	}
	err = c.writeCarrierHello(helloCtx, hsStream, token, hello)
	helloContextErr := helloCtx.Err()
	cancel()
	if err != nil {
		return nil, nil, err
	}
	if helloContextErr != nil || ctx.Err() != nil {
		return nil, nil, fmt.Errorf("write carrier hello: %w", firstContextError(helloContextErr, ctx.Err()))
	}
	ackCtx, cancel := context.WithTimeout(ctx, c.cfg.CarrierAckTimeout)
	err = c.readCarrierAck(ackCtx, hsStream)
	ackContextErr := ackCtx.Err()
	cancel()
	if err != nil {
		return nil, nil, err
	}
	if ackContextErr != nil || ctx.Err() != nil {
		return nil, nil, fmt.Errorf("read carrier ack: %w", firstContextError(ackContextErr, ctx.Err()))
	}
	return conn, conn.Session(), nil
}

type realQUICCarrier struct {
	packet net.PacketConn
	remote net.Addr

	mu        sync.Mutex
	conn      *quic.Conn
	closeConn func() error
	closed    bool
	once      sync.Once
	err       error
}

func dialQUICSocket(ctx context.Context, address string) (quicCarrier, error) {
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := net.DefaultResolver.LookupPort(ctx, "udp", service)
	if err != nil {
		return nil, err
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("relay address resolved to no IPs")
	}
	network := "udp6"
	if addrs[0].IP.To4() != nil {
		network = "udp4"
	}
	packet, err := (&net.ListenConfig{}).ListenPacket(ctx, network, ":0")
	if err != nil {
		return nil, err
	}
	return &realQUICCarrier{
		packet: packet,
		remote: &net.UDPAddr{IP: addrs[0].IP, Port: port, Zone: addrs[0].Zone},
	}, nil
}

func (q *realQUICCarrier) Handshake(ctx context.Context, cfg *tls.Config) error {
	conn, err := quic.Dial(ctx, q.packet, q.remote, cfg, protocol.QUICConfig())
	if err != nil {
		return err
	}
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		_ = conn.CloseWithError(0, "")
		return contextError(ctx)
	}
	q.conn = conn
	q.closeConn = func() error { return conn.CloseWithError(0, "") }
	q.mu.Unlock()
	return nil
}

func (q *realQUICCarrier) OpenHandshakeStream(ctx context.Context) (protocol.FrameReadWriter, error) {
	q.mu.Lock()
	conn := q.conn
	q.mu.Unlock()
	if conn == nil {
		return nil, errors.New("QUIC handshake is incomplete")
	}
	return conn.OpenStreamSync(ctx)
}

func (q *realQUICCarrier) Session() protocol.Session {
	q.mu.Lock()
	defer q.mu.Unlock()
	return &ownedQUICSession{
		Session: protocol.NewQUICSession(q.conn),
		close:   q.Close,
	}
}

func (q *realQUICCarrier) Close() error {
	q.once.Do(func() {
		q.mu.Lock()
		q.closed = true
		closeQUIC := q.closeConn
		q.mu.Unlock()
		var closeQUICErr error
		if closeQUIC != nil {
			closeQUICErr = closeQUIC()
		}
		q.err = errors.Join(closeQUICErr, q.packet.Close())
	})
	return q.err
}

type ownedQUICSession struct {
	protocol.Session
	close func() error
}

func (s *ownedQUICSession) Close() error {
	return s.close()
}

type helloOptions struct {
	surface              string
	cacheProtocolVersion int
	cacheVerificationKey []byte
}

func (c *Client) handshake(ctx context.Context, rw protocol.FrameReadWriter, token []byte, opts helloOptions) error {
	helloCtx, cancel := context.WithTimeout(ctx, c.cfg.CarrierHelloTimeout)
	err := c.writeCarrierHello(helloCtx, rw, token, opts)
	helloContextErr := helloCtx.Err()
	cancel()
	if err != nil {
		return err
	}
	if helloContextErr != nil || ctx.Err() != nil {
		return fmt.Errorf("write carrier hello: %w", firstContextError(helloContextErr, ctx.Err()))
	}
	ackCtx, cancel := context.WithTimeout(ctx, c.cfg.CarrierAckTimeout)
	err = c.readCarrierAck(ackCtx, rw)
	ackContextErr := ackCtx.Err()
	cancel()
	if err != nil {
		return err
	}
	if ackContextErr != nil || ctx.Err() != nil {
		return fmt.Errorf("read carrier ack: %w", firstContextError(ackContextErr, ctx.Err()))
	}
	return nil
}

func (c *Client) writeCarrierHello(ctx context.Context, rw protocol.FrameReadWriter, token []byte, opts helloOptions) error {
	if c.writeHelloCarrier != nil {
		return c.writeHelloCarrier(ctx, rw, token, opts)
	}
	return c.writeHello(ctx, rw, token, opts)
}

func (c *Client) readCarrierAck(ctx context.Context, rw protocol.FrameReadWriter) error {
	if c.readAckCarrier != nil {
		return c.readAckCarrier(ctx, rw)
	}
	return c.readAck(ctx, rw)
}

func (c *Client) writeHello(ctx context.Context, rw protocol.FrameReadWriter, token []byte, opts helloOptions) error {
	hello := &protocol.Hello{Version: protocol.Version, Token: token, Hostnames: c.cfg.Hostnames}
	if opts.surface == protocol.SurfaceCache {
		hello.Surface = protocol.SurfaceCache
		hello.CacheProtocolVersion = opts.cacheProtocolVersion
		hello.CacheVerificationKey = opts.cacheVerificationKey
	}
	if err := writeFrameWithDeadline(ctx, rw, c.cfg.CarrierHelloTimeout, protocol.Frame{Type: protocol.FrameHello, Hello: hello}); err != nil {
		return fmt.Errorf("write carrier hello: %w", err)
	}
	return nil
}

func (c *Client) readAck(ctx context.Context, rw protocol.FrameReadWriter) error {
	frame, err := readFrameWithDeadline(ctx, rw, c.cfg.CarrierAckTimeout)
	if err != nil {
		return fmt.Errorf("read carrier ack: %w", err)
	}
	if frame.Type != protocol.FrameAck || frame.Ack == nil {
		if frame.Type == protocol.FrameError && frame.Error != "" {
			return fmt.Errorf("relay rejected carrier: %s", frame.Error)
		}
		return errors.New("relay rejected carrier: malformed Ack")
	}
	return nil
}

type deadlineReadWriter interface {
	protocol.FrameReadWriter
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func writeFrameWithDeadline(ctx context.Context, rw protocol.FrameReadWriter, timeout time.Duration, frame protocol.Frame) error {
	deadlined, ok := rw.(deadlineReadWriter)
	if !ok {
		return errors.New("carrier stream does not support deadlines")
	}
	deadline := phaseDeadline(ctx, timeout)
	if err := deadlined.SetWriteDeadline(deadline); err != nil {
		return err
	}
	err := protocol.WriteFrame(deadlined, frame)
	_ = deadlined.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return contextErrorIfDone(ctx)
}

func readFrameWithDeadline(ctx context.Context, rw protocol.FrameReadWriter, timeout time.Duration) (protocol.Frame, error) {
	deadlined, ok := rw.(deadlineReadWriter)
	if !ok {
		return protocol.Frame{}, errors.New("carrier stream does not support deadlines")
	}
	deadline := phaseDeadline(ctx, timeout)
	if err := deadlined.SetReadDeadline(deadline); err != nil {
		return protocol.Frame{}, err
	}
	frame, err := protocol.ReadFrame(deadlined)
	_ = deadlined.SetReadDeadline(time.Time{})
	if err != nil {
		return protocol.Frame{}, err
	}
	return frame, contextErrorIfDone(ctx)
}

func phaseDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func contextErrorIfDone(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func firstContextError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return errTunnelClientClosed
}

func passthroughHello() helloOptions {
	return helloOptions{surface: protocol.SurfacePassthrough}
}

func (c *Client) cacheHello(key []byte) helloOptions {
	return helloOptions{
		surface:              protocol.SurfaceCache,
		cacheProtocolVersion: protocol.CacheProtocolVersion,
		cacheVerificationKey: key,
	}
}
