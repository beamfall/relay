package relay

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/beamfall/relay/internal/protocol"
)

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

type retryTestListener struct {
	net.Listener
	once   sync.Once
	served chan struct{}
}

func (l *retryTestListener) Accept() (net.Conn, error) {
	failed := false
	l.once.Do(func() { failed = true })
	if failed {
		return nil, temporaryAcceptError{}
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &observedReadConn{Conn: conn, served: l.served}, nil
}

type observedReadConn struct {
	net.Conn
	once   sync.Once
	served chan struct{}
}

func (c *observedReadConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.served) })
	return c.Conn.Read(p)
}

type retryTestQUICListener struct {
	quicListener
	once sync.Once
}

func (l *retryTestQUICListener) Accept(ctx context.Context) (*quic.Conn, error) {
	failed := false
	l.once.Do(func() { failed = true })
	if failed {
		return nil, temporaryAcceptError{}
	}
	return l.quicListener.Accept(ctx)
}

func TestAcceptPublicRetriesTemporaryErrorAndServesConnection(t *testing.T) {
	listener := newRetryTestListener(t)
	s := newAcceptRetryTestServer()
	s.publicListener = listener
	s.publicSlots = make(chan struct{}, 1)
	s.publicPerIP = newPerIPLimiter(1)
	s.registry = newRegistry()

	ctx, cancel := context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.acceptPublic(ctx)
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		s.Wait()
	})

	writeInvalidHandshake(t, listener.Addr().String())
	waitForAcceptServed(t, listener.served)
	assertAcceptRetryMetric(t, s, 1)
}

func TestAcceptCarriersRetriesTemporaryErrorAndServesConnection(t *testing.T) {
	listener := newRetryTestListener(t)
	s := newAcceptRetryTestServer()
	s.carrierListener = listener
	s.carrierAdmissions = make(chan struct{}, 1)
	s.carrierPendingPerIP = newPerIPLimiter(1)
	s.carrierSlots = make(chan struct{}, 1)

	ctx, cancel := context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.acceptCarriers(ctx)
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		s.Wait()
	})

	writeInvalidHandshake(t, listener.Addr().String())
	waitForAcceptServed(t, listener.served)
	assertAcceptRetryMetric(t, s, 1)
}

func TestAcceptQUICCarriersRetriesTemporaryErrorAndServesConnection(t *testing.T) {
	cert := backoffTestCert(t)
	base, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"beamfall-relay-carrier/1"},
	}, protocol.QUICConfig())
	if err != nil {
		t.Fatalf("listen quic: %v", err)
	}
	listener := &retryTestQUICListener{quicListener: base}
	s := newAcceptRetryTestServer()
	s.quicListener = listener
	s.carrierAdmissions = make(chan struct{}, 1)
	s.carrierPendingPerIP = newPerIPLimiter(1)
	s.carrierSlots = make(chan struct{}, 1)

	ctx, cancel := context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.acceptQUICCarriers(ctx)
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		s.Wait()
	})

	conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"beamfall-relay-carrier/1"},
	}, protocol.QUICConfig())
	if err != nil {
		t.Fatalf("dial quic: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open quic stream: %v", err)
	}
	if _, err := stream.Write([]byte{0}); err != nil {
		t.Fatalf("write invalid quic handshake: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close invalid quic handshake stream: %v", err)
	}

	waitForAtomicValue(t, &s.metrics.handshakeFailures, 1)
	assertAcceptRetryMetric(t, s, 1)
}

func TestAcceptRetryDelayStartsAtFiveMillisecondsAndCapsAtOneSecond(t *testing.T) {
	want := []time.Duration{
		5 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
		80 * time.Millisecond,
		160 * time.Millisecond,
		320 * time.Millisecond,
		640 * time.Millisecond,
		time.Second,
		time.Second,
	}
	var delay time.Duration
	for i, expected := range want {
		delay = nextAcceptRetryDelay(delay)
		if delay != expected {
			t.Fatalf("retry delay %d = %v, want %v", i, delay, expected)
		}
	}
}

func newRetryTestListener(t *testing.T) *retryTestListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	return &retryTestListener{Listener: listener, served: make(chan struct{})}
}

func newAcceptRetryTestServer() *Server {
	s := &Server{
		handshakeThrottle: newHandshakeThrottle(),
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		redactConnLogs:    true,
		tracer:            noop.NewTracerProvider().Tracer("accept-retry-test"),
	}
	s.metrics.initSLIs()
	return s
}

func writeInvalidHandshake(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		_ = conn.Close()
		t.Fatalf("write invalid handshake: %v", err)
	}
	_ = conn.Close()
}

func waitForAcceptServed(t *testing.T, served <-chan struct{}) {
	t.Helper()
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("connection was not served after temporary accept error")
	}
}

func waitForAtomicValue(t *testing.T, value interface{ Load() int64 }, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for value.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("atomic value = %d, want %d", value.Load(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertAcceptRetryMetric(t *testing.T, s *Server, want int64) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	s.metricsHandler().ServeHTTP(rr, req)
	wantLine := "beamfall_relay_accept_retries_total " + strconv.FormatInt(want, 10)
	if got := metricLine(rr.Body.String(), "beamfall_relay_accept_retries_total"); got != wantLine {
		t.Fatalf("accept retry metric = %q, want %q", got, wantLine)
	}
}

var _ net.Error = temporaryAcceptError{}
var _ quicListener = (*retryTestQUICListener)(nil)
