package relay

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace/noop"

	"github.com/beamfall/relay/internal/cache"
	"github.com/beamfall/relay/internal/protocol"
)

func TestCarrierHandshakeRejectsCrossSurfaceCredentials(t *testing.T) {
	key := testCacheVerificationKey()
	server := surfaceHandshakeServer(StaticTokenVerifier{
		Token:     []byte("right"),
		Hostnames: []string{"home.relay.test"},
	})
	frame := rejectHandshake(t, server, &protocol.Hello{
		Version:              protocol.Version,
		Token:                []byte("right"),
		Hostnames:            []string{"home.relay.test"},
		Surface:              protocol.SurfaceCache,
		CacheProtocolVersion: protocol.CacheProtocolVersion,
		CacheVerificationKey: key,
	})
	if frame.Error != "unauthorized" {
		t.Fatalf("error = %q, want unauthorized", frame.Error)
	}

	server = surfaceHandshakeServer(StaticTokenVerifier{
		Token:     []byte("right"),
		Hostnames: []string{"home.relay.test"},
		Surface:   protocol.SurfaceCache,
	})
	frame = rejectHandshake(t, server, &protocol.Hello{
		Version:   protocol.Version,
		Token:     []byte("right"),
		Hostnames: []string{"home.relay.test"},
	})
	if frame.Error != "unauthorized" {
		t.Fatalf("error = %q, want unauthorized", frame.Error)
	}
}

func TestCarrierHandshakeRejectsCacheVersionSkew(t *testing.T) {
	key := testCacheVerificationKey()
	server := surfaceHandshakeServer(StaticTokenVerifier{
		Token:     []byte("right"),
		Hostnames: []string{"home.relay.test"},
		Surface:   protocol.SurfaceCache,
	})
	frame := rejectHandshake(t, server, &protocol.Hello{
		Version:              protocol.Version,
		Token:                []byte("right"),
		Hostnames:            []string{"home.relay.test"},
		Surface:              protocol.SurfaceCache,
		CacheProtocolVersion: protocol.CacheProtocolVersion + 1,
		CacheVerificationKey: key,
	})
	if frame.Error != "invalid hello" {
		t.Fatalf("error = %q, want invalid hello", frame.Error)
	}
}

func TestCarrierHandshakeAcceptsCacheSurface(t *testing.T) {
	key := testCacheVerificationKey()
	server := surfaceHandshakeServer(StaticTokenVerifier{
		Token:     []byte("right"),
		Hostnames: []string{"home.relay.test"},
		Surface:   protocol.SurfaceCache,
	})
	verified := acceptHandshake(t, server, &protocol.Hello{
		Version:              protocol.Version,
		Token:                []byte("right"),
		Hostnames:            []string{"home.relay.test"},
		Surface:              protocol.SurfaceCache,
		CacheProtocolVersion: protocol.CacheProtocolVersion,
		CacheVerificationKey: key,
	})
	if verified.Surface != protocol.SurfaceCache {
		t.Fatalf("surface = %q, want cache", verified.Surface)
	}
	if string(verified.CacheVerificationKey) != string(key) {
		t.Fatal("cache verification key was not carried into VerifiedCarrier")
	}
}

func TestCarrierHandshakePassesCacheVerificationKeyToVerifier(t *testing.T) {
	key := testCacheVerificationKey()
	verifier := &recordingCacheVerifier{}
	server := surfaceHandshakeServer(verifier)
	acceptHandshake(t, server, &protocol.Hello{
		Version:              protocol.Version,
		Token:                []byte("right"),
		Hostnames:            []string{"home.relay.test"},
		Surface:              protocol.SurfaceCache,
		CacheProtocolVersion: protocol.CacheProtocolVersion,
		CacheVerificationKey: key,
	})
	if string(verifier.key) != string(key) {
		t.Fatal("cache verification key was not passed to token verifier")
	}
}

type recordingCacheVerifier struct {
	key []byte
}

func (v *recordingCacheVerifier) VerifyTunnelToken(context.Context, []byte, []string) (VerifiedCarrier, error) {
	return VerifiedCarrier{}, ErrUnauthorized
}

func (v *recordingCacheVerifier) VerifyCacheCarrierToken(_ context.Context, token []byte, requestedHostnames []string, cacheVerificationKey []byte) (VerifiedCarrier, error) {
	if string(token) != "right" {
		return VerifiedCarrier{}, ErrUnauthorized
	}
	v.key = append([]byte(nil), cacheVerificationKey...)
	return VerifiedCarrier{ID: "carrier-1", Hostnames: requestedHostnames, Surface: protocol.SurfaceCache}, nil
}

func testCacheVerificationKey() []byte {
	return []byte("abcdefghijklmnopqrstuvwxyz0123456789")
}

func surfaceHandshakeServer(verifier TokenVerifier) *Server {
	return &Server{
		verifier:            verifier,
		handshakeThrottle:   newHandshakeThrottle(),
		cacheCarrierEnabled: true,
		logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		tracer:              noop.NewTracerProvider().Tracer("test"),
	}
}

func TestCarrierHandshakeRefusesCacheSurfaceWhenDisabled(t *testing.T) {
	key := testCacheVerificationKey()
	verifier := &recordingCacheVerifier{}
	server := &Server{
		verifier:          verifier,
		handshakeThrottle: newHandshakeThrottle(),
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		tracer:            noop.NewTracerProvider().Tracer("test"),
	}
	frame := rejectHandshake(t, server, &protocol.Hello{
		Version:              protocol.Version,
		Token:                []byte("right"),
		Hostnames:            []string{"home.relay.test"},
		Surface:              protocol.SurfaceCache,
		CacheProtocolVersion: protocol.CacheProtocolVersion,
		CacheVerificationKey: key,
	})
	if frame.Error != "invalid hello" {
		t.Fatalf("error = %q, want invalid hello", frame.Error)
	}
	if len(verifier.key) != 0 {
		t.Fatal("disabled cache surface reached token verifier")
	}
	if got := server.metrics.handshakeFailures.Load(); got != 1 {
		t.Fatalf("handshakeFailures = %d, want 1", got)
	}
}

type closeTrackingSession struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newCloseTrackingSession() *closeTrackingSession {
	return &closeTrackingSession{closed: make(chan struct{})}
}

func (s *closeTrackingSession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *closeTrackingSession) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *closeTrackingSession) CloseChan() <-chan struct{} { return s.closed }
func (s *closeTrackingSession) Open() (net.Conn, error)    { return nil, io.EOF }
func (s *closeTrackingSession) Accept() (net.Conn, error)  { return nil, io.EOF }

func TestServeCarrierSessionRefusesCacheSurfaceWhenDisabled(t *testing.T) {
	server := &Server{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	client, peer := net.Pipe()
	defer client.Close() //nolint:errcheck // test pipe cleanup.
	defer peer.Close()   //nolint:errcheck // test pipe cleanup.

	session := newCloseTrackingSession()
	done := make(chan struct{})
	go func() {
		server.serveCarrierSession(context.Background(), peer, session, VerifiedCarrier{
			ID:      "carrier-1",
			Surface: protocol.SurfaceCache,
		})
		close(done)
	}()

	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := protocol.ReadFrame(client)
	if err != nil {
		t.Fatalf("read error frame: %v", err)
	}
	if frame.Type != protocol.FrameError || frame.Error != "invalid hello" {
		t.Fatalf("frame = %#v, want invalid hello error", frame)
	}
	<-done
	if !session.IsClosed() {
		t.Fatal("disabled cache carrier session was not closed")
	}
}

func TestCacheCarrierSupersedesPreviousSession(t *testing.T) {
	reg := newCacheCarrierRegistry()
	first := newCloseTrackingSession()
	second := newCloseTrackingSession()

	reg.register("carrier-1", first)
	if first.IsClosed() {
		t.Fatal("first cache carrier session closed on initial register")
	}
	reg.register("carrier-1", second)
	if !first.IsClosed() {
		t.Fatal("superseded cache carrier session was not closed")
	}
	if second.IsClosed() {
		t.Fatal("replacement cache carrier session was closed")
	}
	if got := reg.get("carrier-1"); got != second {
		t.Fatalf("registered session = %v, want replacement", got)
	}
}

func TestCacheKeyRegistryPrunesExpiredEntries(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	reg := newCacheKeyRegistry()
	reg.now = func() time.Time { return now }

	key1 := testCacheVerificationKey()
	key2 := append([]byte(nil), key1...)
	key2[0] ^= 0xff

	reg.acquire("carrier-1", key1)
	if reg.keys("carrier-1") == nil {
		t.Fatal("active carrier keys missing")
	}
	reg.release("carrier-1")

	now = now.Add(cache.MaxTokenTTL / 2)
	if reg.keys("carrier-1") == nil {
		t.Fatal("cache keys pruned before retention TTL elapsed")
	}

	now = now.Add(cache.MaxTokenTTL)
	reg.acquire("carrier-2", key2)
	if reg.keys("carrier-1") != nil {
		t.Fatal("expired inactive cache keys were not pruned")
	}
	if reg.keys("carrier-2") == nil {
		t.Fatal("active carrier-2 keys missing")
	}
}

func rejectHandshake(t *testing.T, server *Server, hello *protocol.Hello) protocol.Frame {
	t.Helper()
	client, peer := net.Pipe()
	defer client.Close() //nolint:errcheck // test pipe cleanup.
	defer peer.Close()   //nolint:errcheck // test pipe cleanup.

	done := make(chan bool, 1)
	go func() {
		_, ok := server.carrierHandshake(context.Background(), peer, peer.RemoteAddr())
		done <- ok
	}()
	if err := protocol.WriteFrame(client, protocol.Frame{Type: protocol.FrameHello, Hello: hello}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := protocol.ReadFrame(client)
	if err != nil {
		t.Fatalf("read error frame: %v", err)
	}
	if ok := <-done; ok {
		t.Fatal("handshake accepted, want reject")
	}
	return frame
}

func acceptHandshake(t *testing.T, server *Server, hello *protocol.Hello) VerifiedCarrier {
	t.Helper()
	client, peer := net.Pipe()
	defer client.Close() //nolint:errcheck // test pipe cleanup.
	defer peer.Close()   //nolint:errcheck // test pipe cleanup.

	done := make(chan VerifiedCarrier, 1)
	go func() {
		verified, ok := server.carrierHandshake(context.Background(), peer, peer.RemoteAddr())
		if !ok {
			t.Error("handshake rejected")
		}
		done <- verified
	}()
	if err := protocol.WriteFrame(client, protocol.Frame{Type: protocol.FrameHello, Hello: hello}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	select {
	case verified := <-done:
		return verified
	case <-time.After(time.Second):
		t.Fatal("handshake timed out")
		return VerifiedCarrier{}
	}
}
