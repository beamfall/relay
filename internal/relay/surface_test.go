package relay

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace/noop"

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
		verifier:          verifier,
		handshakeThrottle: newHandshakeThrottle(),
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		tracer:            noop.NewTracerProvider().Tracer("test"),
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
