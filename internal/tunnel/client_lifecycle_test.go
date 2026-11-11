package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/protocol"
)

func TestClientDeliversFullUploadAfterBackendHalfClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	carrier := newFakeCarrier(t)
	defer carrier.close()
	response := []byte("HELLO-FROM-BACKEND")
	backend := newBackendHalfCloser(t, response, 200*time.Millisecond)
	defer backend.close()
	client := startTestClient(t, ctx, carrier.addr(), backend.addr())
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("client not ready: %v", err)
	}
	stream, err := carrier.latestSession(t).Open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(response))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read backend response: %v", err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("backend response = %q, want %q", got, response)
	}
	upload := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	if _, err := stream.Write(upload); err != nil {
		t.Fatalf("write upload: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	select {
	case received := <-backend.uploaded:
		if !bytes.Equal(received, upload) {
			t.Fatalf("upload truncated: got %d bytes, want %d", len(received), len(upload))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backend never received the full upload")
	}
}

func TestClientReconnectsAfterRelayDrops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	carrier := newFakeCarrier(t)
	backend := newBackendEcho(t)
	defer backend.close()
	client := startTestClient(t, ctx, carrier.addr(), backend.addr())
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("client not ready before drop: %v", err)
	}
	firstSession := carrier.latestSession(t)
	roundTrip(t, firstSession, "before-drop")
	_ = firstSession.Close()
	carrier.waitAcceptedCount(t, 2)
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("client not ready after reconnect: %v", err)
	}
	roundTrip(t, carrier.latestSession(t), "after-reconnect")
}

func TestClientReconnectsWhileBackendIgnoresHalfClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	carrier := newFakeCarrier(t)
	defer carrier.close()
	backend := newBackendBlocker(t)
	defer backend.close()
	var logs bytes.Buffer
	client, err := Start(ctx, Config{
		RelayAddr:   carrier.addr(),
		BackendAddr: backend.addr(),
		Token:       []byte("test-token"),
		Hostnames:   []string{"home.relay.test"},
		TLSConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		Logger:      slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		BackoffMin:  10 * time.Millisecond,
		BackoffMax:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start tunnel client: %v", err)
	}
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("client not ready before drop: %v", err)
	}
	firstSession := carrier.latestSession(t)
	stream, err := firstSession.Open()
	if err != nil {
		t.Fatalf("open parked stream: %v", err)
	}
	defer stream.Close() //nolint:errcheck // test stream cleanup.
	if _, err := stream.Write([]byte("park")); err != nil {
		t.Fatalf("write parked stream: %v", err)
	}
	waitSignal(t, backend.first, "backend did not accept parked stream")

	_ = firstSession.Close()
	carrier.waitAcceptedCountWithin(t, 2, 5*time.Second)
	client.Close()
	waitClient(t, client, "client did not drain streams after reconnect")
	if got := logs.String(); !strings.Contains(got, "tunnel stream copy ended abruptly") || !strings.Contains(got, "streams=1") {
		t.Fatalf("Debug logs = %q, want abrupt copy error with stream count", got)
	}
}

func TestClientShutdownDrainsStreamIgnoringHalfClose(t *testing.T) {
	for _, shutdown := range []string{"context", "Close"} {
		t.Run(shutdown, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			carrier := newFakeCarrier(t)
			defer carrier.close()
			backend := newBackendBlocker(t)
			defer backend.close()
			client := startTestClient(t, ctx, carrier.addr(), backend.addr())
			if err := client.WaitReady(ctx); err != nil {
				t.Fatalf("client not ready: %v", err)
			}
			stream, err := carrier.latestSession(t).Open()
			if err != nil {
				t.Fatalf("open parked stream: %v", err)
			}
			defer stream.Close() //nolint:errcheck // test stream cleanup.
			if _, err := stream.Write([]byte("park")); err != nil {
				t.Fatalf("write parked stream: %v", err)
			}
			waitSignal(t, backend.first, "backend did not accept parked stream")

			if shutdown == "context" {
				cancel()
			} else {
				client.Close()
			}
			waitClient(t, client, "client exit did not wait for stream drain")
		})
	}
}

func TestClientContextCancelEndsLoopPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	carrier := newFakeCarrier(t)
	defer carrier.close()
	backend := newBackendEcho(t)
	defer backend.close()
	client := startTestClient(t, ctx, carrier.addr(), backend.addr())
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("client not ready: %v", err)
	}
	cancel()
	waitClient(t, client, "reconnect loop did not exit after context cancel")
}

func TestClientCloseStopsReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	carrier := newFakeCarrier(t)
	defer carrier.close()
	backend := newBackendEcho(t)
	defer backend.close()
	client := startTestClient(t, ctx, carrier.addr(), backend.addr())
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("client not ready: %v", err)
	}
	carrier.waitAcceptedCount(t, 1)
	client.Close()
	waitClient(t, client, "loop did not exit after Close")
	countAfterClose := carrier.acceptedCount()
	time.Sleep(200 * time.Millisecond)
	if got := carrier.acceptedCount(); got != countAfterClose {
		t.Fatalf("client reconnected after Close: accepted went %d -> %d", countAfterClose, got)
	}
}

func TestClientHandlesBackendDialFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	carrier := newFakeCarrier(t)
	defer carrier.close()
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve backend port: %v", err)
	}
	deadBackend := tmp.Addr().String()
	_ = tmp.Close()
	client := startTestClient(t, ctx, carrier.addr(), deadBackend)
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("client not ready: %v", err)
	}
	stream, err := carrier.latestSession(t).Open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected stream to be closed after backend dial failure")
	}
	_ = stream.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("client session dropped after backend dial failure: %v", err)
	}
}

func TestNextBackoffCapsAtMax(t *testing.T) {
	max := 60 * time.Second
	b := time.Second
	for range 20 {
		b = nextBackoff(b, max)
	}
	if b != max {
		t.Fatalf("backoff = %v, want capped at %v", b, max)
	}
	if got := nextBackoff(time.Second, max); got != 2*time.Second {
		t.Fatalf("nextBackoff(1s) = %v, want 2s", got)
	}
	if got := nextBackoff(time.Duration(1<<62), max); got != max {
		t.Fatalf("nextBackoff(overflow) = %v, want %v", got, max)
	}
}

func TestCarrierTimeoutDefaultsAndLimits(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := Config{}
		if err := normalizeCarrierTimeouts(&cfg); err != nil {
			t.Fatalf("normalize defaults: %v", err)
		}
		if cfg.CarrierDialTimeout != 10*time.Second ||
			cfg.CarrierTLSHandshakeTimeout != 10*time.Second ||
			cfg.CarrierHelloTimeout != 5*time.Second ||
			cfg.CarrierAckTimeout != 5*time.Second {
			t.Fatalf("defaults = %v/%v/%v/%v, want 10s/10s/5s/5s",
				cfg.CarrierDialTimeout, cfg.CarrierTLSHandshakeTimeout,
				cfg.CarrierHelloTimeout, cfg.CarrierAckTimeout)
		}
	})

	t.Run("total hard maximum", func(t *testing.T) {
		cfg := Config{
			CarrierDialTimeout:         15 * time.Second,
			CarrierTLSHandshakeTimeout: 15 * time.Second,
			CarrierHelloTimeout:        15 * time.Second,
			CarrierAckTimeout:          15 * time.Second,
		}
		if err := normalizeCarrierTimeouts(&cfg); err != nil {
			t.Fatalf("accept exact 60s total: %v", err)
		}
	})

	for _, field := range []string{"dial", "tls", "hello", "ack"} {
		t.Run(field+" phase hard maximum", func(t *testing.T) {
			cfg := Config{
				CarrierDialTimeout:         time.Second,
				CarrierTLSHandshakeTimeout: time.Second,
				CarrierHelloTimeout:        time.Second,
				CarrierAckTimeout:          time.Second,
			}
			switch field {
			case "dial":
				cfg.CarrierDialTimeout = 30 * time.Second
			case "tls":
				cfg.CarrierTLSHandshakeTimeout = 30 * time.Second
			case "hello":
				cfg.CarrierHelloTimeout = 30 * time.Second
			case "ack":
				cfg.CarrierAckTimeout = 30 * time.Second
			}
			if err := normalizeCarrierTimeouts(&cfg); err != nil {
				t.Fatalf("accept exact 30s %s timeout: %v", field, err)
			}
		})
	}

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "phase above maximum",
			cfg:  Config{CarrierAckTimeout: 30*time.Second + time.Nanosecond},
		},
		{
			name: "total above maximum",
			cfg: Config{
				CarrierDialTimeout:         16 * time.Second,
				CarrierTLSHandshakeTimeout: 15 * time.Second,
				CarrierHelloTimeout:        15 * time.Second,
				CarrierAckTimeout:          15 * time.Second,
			},
		},
		{
			name: "negative",
			cfg:  Config{CarrierHelloTimeout: -time.Nanosecond},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := normalizeCarrierTimeouts(&tt.cfg); err == nil {
				t.Fatal("normalize succeeded, want validation error")
			}
		})
	}
}

func TestCarrierAggregateTimeoutCapsInflatedLaterPhase(t *testing.T) {
	const phaseTimeout = 25 * time.Millisecond
	const aggregateBudget = 4 * phaseTimeout
	client := newLifecycleClient(t, phaseTimeout)
	client.cfg.Transport = TransportQUIC
	carrier := &lifecycleQUICCarrier{}
	client.dialQUICCarrier = func(context.Context, string) (quicCarrier, error) {
		client.cfg.CarrierTLSHandshakeTimeout = time.Second
		return carrier, nil
	}
	carrier.handshake = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}

	start := time.Now()
	if _, err := client.serveOnce(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("serveOnce error = %v, want deadline exceeded", err)
	}
	elapsed := time.Since(start)
	if elapsed < aggregateBudget/2 || elapsed > 4*aggregateBudget {
		t.Fatalf("aggregate timeout elapsed = %v, want near %v", elapsed, aggregateBudget)
	}
	if got := carrier.closeCount.Load(); got != 1 {
		t.Fatalf("carrier closed %d times, want exactly once", got)
	}
	assertNoLiveCarrier(t, client)
}

func TestRealQUICCarrierCloseOwnsConnectionAndPacket(t *testing.T) {
	connectionCloseErr := errors.New("close QUIC connection")
	packetCloseErr := errors.New("close UDP socket")
	var connectionCloseCount atomic.Int32
	packet := &closeCountingPacketConn{closeErr: packetCloseErr}
	carrier := &realQUICCarrier{
		packet: packet,
		closeConn: func() error {
			connectionCloseCount.Add(1)
			return connectionCloseErr
		},
	}

	session := carrier.Session()
	for _, closeCarrier := range []func() error{session.Close, carrier.Close, session.Close} {
		err := closeCarrier()
		if !errors.Is(err, connectionCloseErr) {
			t.Fatalf("Close error = %v, want QUIC connection error", err)
		}
		if !errors.Is(err, packetCloseErr) {
			t.Fatalf("Close error = %v, want UDP socket error", err)
		}
	}
	if got := connectionCloseCount.Load(); got != 1 {
		t.Fatalf("QUIC connection closed %d times, want exactly once", got)
	}
	if got := packet.closeCount.Load(); got != 1 {
		t.Fatalf("UDP socket closed %d times, want exactly once", got)
	}
}

func TestCarrierPhaseDeadlinesReapOwnedConnection(t *testing.T) {
	for _, phase := range []string{"dial", "tls", "hello", "ack"} {
		t.Run(phase, func(t *testing.T) {
			client := newLifecycleClient(t, 25*time.Millisecond)
			harness := installHangingPhase(t, client, phase)
			defer harness.cleanup()

			started := time.Now()
			_, err := client.serveOnce(context.Background())
			if err == nil {
				t.Fatal("serveOnce succeeded for hung phase")
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("hung %s phase returned after %v, want bounded return", phase, elapsed)
			}
			harness.waitExited(t)
			harness.assertCloseCount(t)
			assertNoLiveCarrier(t, client)
		})
	}
}

func TestCloseCancelsEveryCarrierPhaseAndWaitsForExit(t *testing.T) {
	for _, phase := range []string{"dial", "tls", "hello", "ack"} {
		t.Run(phase, func(t *testing.T) {
			client := newLifecycleClient(t, 5*time.Second)
			harness := installHangingPhase(t, client, phase)
			defer harness.cleanup()
			startLifecycleLoop(client, context.Background())

			waitSignal(t, harness.entered, "phase did not begin")
			client.Close()
			waitClient(t, client, "Close did not terminate reconnect loop")

			harness.waitExited(t)
			harness.assertCloseCount(t)
			assertNoLiveCarrier(t, client)
		})
	}
}

func TestContextCancellationReapsAckWaitAndLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := newLifecycleClient(t, 5*time.Second)
	harness := installHangingPhase(t, client, "ack")
	defer harness.cleanup()
	startLifecycleLoop(client, ctx)

	waitSignal(t, harness.entered, "Ack wait did not begin")
	cancel()
	waitClient(t, client, "context cancellation did not terminate reconnect loop")

	harness.waitExited(t)
	harness.assertCloseCount(t)
	assertNoLiveCarrier(t, client)
}

func TestCarrierRejectsMalformedAckAndReapsConnection(t *testing.T) {
	client := newLifecycleClient(t, time.Second)
	clientConn, peer := net.Pipe()
	counted := &countingConn{Conn: clientConn}
	client.dialCarrier = func(context.Context, string, string) (net.Conn, error) {
		return counted, nil
	}
	client.handshakeTLSCarrier = passThroughTLS

	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		defer peer.Close() //nolint:errcheck // test peer cleanup.
		if _, err := protocol.ReadFrame(peer); err != nil {
			return
		}
		_ = protocol.WriteFrame(peer, protocol.Frame{Type: protocol.FrameAck})
	}()

	_, err := client.serveOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "malformed Ack") {
		t.Fatalf("serveOnce error = %v, want malformed Ack rejection", err)
	}
	waitSignal(t, peerDone, "malformed-Ack peer goroutine leaked")
	if got := counted.closeCount.Load(); got != 1 {
		t.Fatalf("underlying connection closed %d times, want exactly once", got)
	}
	assertNoLiveCarrier(t, client)
}

func TestCarrierRejectsLateDialSuccessAfterDeadline(t *testing.T) {
	client := newLifecycleClient(t, 20*time.Millisecond)
	clientConn, peer := net.Pipe()
	defer peer.Close() //nolint:errcheck // test peer cleanup.
	counted := &countingConn{Conn: clientConn}
	client.dialCarrier = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return counted, nil
	}
	client.handshakeTLSCarrier = func(context.Context, net.Conn, *tls.Config) (net.Conn, error) {
		t.Fatal("TLS phase reached after late dial success")
		return nil, errors.New("unreachable")
	}

	_, err := client.serveOnce(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("serveOnce error = %v, want deadline exceeded", err)
	}
	if got := counted.closeCount.Load(); got != 1 {
		t.Fatalf("late connection closed %d times, want exactly once", got)
	}
	assertNoLiveCarrier(t, client)
}

func TestCarrierRejectsLateTLSSuccessAfterDeadline(t *testing.T) {
	client := newLifecycleClient(t, 20*time.Millisecond)
	clientConn, peer := net.Pipe()
	defer peer.Close() //nolint:errcheck // test peer cleanup.
	counted := &countingConn{Conn: clientConn}
	client.dialCarrier = func(context.Context, string, string) (net.Conn, error) {
		return counted, nil
	}
	client.handshakeTLSCarrier = func(ctx context.Context, conn net.Conn, _ *tls.Config) (net.Conn, error) {
		<-ctx.Done()
		return conn, nil
	}

	_, err := client.serveOnce(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("serveOnce error = %v, want deadline exceeded", err)
	}
	if got := counted.closeCount.Load(); got != 1 {
		t.Fatalf("late TLS connection closed %d times, want exactly once", got)
	}
	assertNoLiveCarrier(t, client)
}

func TestTCPCarrierTLSHostnameVerification(t *testing.T) {
	cert := selfSignedCert(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	tests := []struct {
		name       string
		relayAddr  string
		serverName string
		wantSNI    string
		wantValid  bool
	}{
		{"derived hostname", "carrier.local:443", "", "carrier.local", true},
		{"explicit override", "wrong.local:443", "carrier.local", "carrier.local", true},
		{"wrong derived hostname", "wrong.local:443", "", "wrong.local", false},
		{"derived IPv6", "[::1]:443", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newLifecycleClient(t, time.Second)
			client.cfg.RelayAddr = tt.relayAddr
			client.cfg.TLSConfig = &tls.Config{
				RootCAs:    roots,
				ServerName: tt.serverName,
				MinVersion: tls.VersionTLS13,
			}
			client.writeHelloCarrier = func(context.Context, protocol.FrameReadWriter, []byte, helloOptions) error {
				return nil
			}
			client.readAckCarrier = func(context.Context, protocol.FrameReadWriter) error { return nil }
			local, peer := net.Pipe()
			counted := &countingConn{Conn: local}
			client.dialCarrier = func(context.Context, string, string) (net.Conn, error) {
				return counted, nil
			}
			sni := make(chan string, 1)
			releaseServer := make(chan struct{})
			serverDone := make(chan error, 1)
			go func() {
				defer peer.Close() //nolint:errcheck
				server := tls.Server(peer, &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS13,
					GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
						sni <- hello.ServerName
						return nil, nil
					},
				})
				serverErr := server.Handshake()
				if serverErr == nil {
					<-releaseServer
				}
				serverDone <- serverErr
			}()

			attempt, attemptCtx, err := client.beginCarrierAttempt(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				close(releaseServer)
				client.abortCarrierAttempt(attempt, false)
				select {
				case <-serverDone: //nolint:errcheck // only the goroutine exit matters here.
				case <-time.After(time.Second):
					t.Error("TLS server goroutine did not exit")
				}
			}()
			conn, session, err := client.dialTCP(attemptCtx, attempt, client.cfg.Token, passthroughHello(), false)
			if tt.wantValid {
				if err != nil {
					t.Fatalf("verified TLS carrier failed: %v", err)
				}
				_ = session.Close()
				_ = conn.Close()
			} else {
				var hostnameErr x509.HostnameError
				if !errors.As(err, &hostnameErr) {
					t.Fatalf("TLS carrier error = %v, want hostname validation failure", err)
				}
			}
			if got := <-sni; got != tt.wantSNI {
				t.Fatalf("ClientHello SNI = %q, want %q", got, tt.wantSNI)
			}
			if client.cfg.TLSConfig.ServerName != tt.serverName {
				t.Fatalf("caller TLS ServerName mutated to %q", client.cfg.TLSConfig.ServerName)
			}
			client.abortCarrierAttempt(attempt, false)
			if got := counted.closeCount.Load(); got != 1 {
				t.Fatalf("TCP connection closed %d times, want exactly once", got)
			}
		})
	}
}

func TestCarrierRejectsLateHelloAndAckSuccess(t *testing.T) {
	tests := []struct {
		name      string
		transport string
		phase     string
	}{
		{"TCP Hello", TransportTCP, "hello"},
		{"TCP Ack", TransportTCP, "ack"},
		{"QUIC Ack", TransportQUIC, "ack"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newLifecycleClient(t, 20*time.Millisecond)
			client.cfg.Transport = tt.transport
			var closeCount *atomic.Int32
			if tt.transport == TransportTCP {
				local, peer := net.Pipe()
				defer peer.Close() //nolint:errcheck
				counted := &countingConn{Conn: local}
				closeCount = &counted.closeCount
				client.dialCarrier = func(context.Context, string, string) (net.Conn, error) {
					return counted, nil
				}
				client.handshakeTLSCarrier = passThroughTLS
			} else {
				carrier := &lifecycleQUICCarrier{}
				closeCount = &carrier.closeCount
				client.dialQUICCarrier = func(context.Context, string) (quicCarrier, error) {
					return carrier, nil
				}
			}
			client.writeHelloCarrier = func(ctx context.Context, _ protocol.FrameReadWriter, _ []byte, _ helloOptions) error {
				if tt.phase == "hello" {
					<-ctx.Done()
				}
				return nil
			}
			client.readAckCarrier = func(ctx context.Context, _ protocol.FrameReadWriter) error {
				if tt.phase == "ack" {
					<-ctx.Done()
				}
				return nil
			}

			if _, err := client.serveOnce(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("serveOnce error = %v, want deadline exceeded", err)
			}
			if got := closeCount.Load(); got != 1 {
				t.Fatalf("carrier closed %d times, want exactly once", got)
			}
			assertNoLiveCarrier(t, client)
		})
	}
}

func TestQUICCarrierPhaseLifecycle(t *testing.T) {
	for _, phase := range []string{"dial", "tls", "hello", "ack"} {
		t.Run("deadline/"+phase, func(t *testing.T) {
			client := newLifecycleClient(t, 25*time.Millisecond)
			client.cfg.Transport = TransportQUIC
			h := installHangingQUICPhase(t, client, phase)
			defer h.cleanup()
			start := time.Now()
			if _, err := client.serveOnce(context.Background()); err == nil {
				t.Fatal("serveOnce succeeded for hung phase")
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("hung phase returned after %v", elapsed)
			}
			h.waitExited(t)
			h.assertCloseCount(t)
			assertNoLiveCarrier(t, client)
		})
		t.Run("close/"+phase, func(t *testing.T) {
			client := newLifecycleClient(t, 5*time.Second)
			client.cfg.Transport = TransportQUIC
			h := installHangingQUICPhase(t, client, phase)
			defer h.cleanup()
			startLifecycleLoop(client, context.Background())
			waitSignal(t, h.entered, "phase did not begin")
			client.Close()
			waitClient(t, client, "Close did not terminate QUIC phase")
			h.waitExited(t)
			h.assertCloseCount(t)
			assertNoLiveCarrier(t, client)
		})
	}
}

func TestQUICCarrierHonorsIndependentTimeouts(t *testing.T) {
	tests := []struct {
		name string
		dial time.Duration
		tls  time.Duration
		hang string
	}{
		{"dial", 20 * time.Millisecond, 500 * time.Millisecond, "dial"},
		{"tls", 500 * time.Millisecond, 20 * time.Millisecond, "tls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newLifecycleClient(t, time.Second)
			client.cfg.Transport = TransportQUIC
			client.cfg.CarrierDialTimeout = tt.dial
			client.cfg.CarrierTLSHandshakeTimeout = tt.tls
			h := installHangingQUICPhase(t, client, tt.hang)
			defer h.cleanup()
			start := time.Now()
			if _, err := client.serveOnce(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("serveOnce error = %v, want deadline exceeded", err)
			}
			if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
				t.Fatalf("%s timeout used another phase's bound: %v", tt.name, elapsed)
			}
		})
	}
}

type phaseHarness struct {
	entered    <-chan struct{}
	phaseDone  <-chan struct{}
	closeCount *atomic.Int32
	cleanupFn  func()
}

func installHangingQUICPhase(t *testing.T, client *Client, phase string) phaseHarness {
	t.Helper()
	entered, done := make(chan struct{}), make(chan struct{})
	var markOnce sync.Once
	mark := func() { markOnce.Do(func() { close(entered) }) }
	if phase == "dial" {
		client.dialQUICCarrier = func(ctx context.Context, _ string) (quicCarrier, error) {
			defer close(done)
			mark()
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return phaseHarness{entered: entered, phaseDone: done, cleanupFn: func() {}}
	}
	clientSide, peer := net.Pipe()
	carrier := &lifecycleQUICCarrier{stream: clientSide}
	client.dialQUICCarrier = func(context.Context, string) (quicCarrier, error) { return carrier, nil }
	peerDone := make(chan struct{})
	switch phase {
	case "tls":
		carrier.handshake = func(ctx context.Context) error {
			defer close(done)
			mark()
			<-ctx.Done()
			return ctx.Err()
		}
	case "hello":
		carrier.stream = &countingConn{Conn: clientSide, writeStarted: func() { mark(); close(done) }}
	case "ack":
		go func() {
			defer close(peerDone)
			defer close(done)
			if _, err := protocol.ReadFrame(peer); err != nil {
				return
			}
			mark()
			_, _ = peer.Read(make([]byte, 1))
		}()
	default:
		t.Fatalf("unknown QUIC phase %q", phase)
	}
	return phaseHarness{
		entered: entered, phaseDone: done, closeCount: &carrier.closeCount,
		cleanupFn: func() {
			_ = peer.Close()
			if phase == "ack" {
				waitSignal(t, peerDone, "QUIC Ack peer leaked")
			}
		},
	}
}

func installHangingPhase(t *testing.T, client *Client, phase string) phaseHarness {
	t.Helper()
	entered := make(chan struct{})
	phaseDone := make(chan struct{})
	var enteredOnce sync.Once
	markEntered := func() { enteredOnce.Do(func() { close(entered) }) }

	if phase == "dial" {
		client.dialCarrier = func(ctx context.Context, _, _ string) (net.Conn, error) {
			defer close(phaseDone)
			markEntered()
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return phaseHarness{
			entered:   entered,
			phaseDone: phaseDone,
			cleanupFn: func() {},
		}
	}

	clientConn, peer := net.Pipe()
	counted := &countingConn{Conn: clientConn}
	client.dialCarrier = func(context.Context, string, string) (net.Conn, error) {
		return counted, nil
	}
	client.handshakeTLSCarrier = passThroughTLS
	cleanupPeer := make(chan struct{})
	peerDone := make(chan struct{})

	switch phase {
	case "tls":
		client.handshakeTLSCarrier = func(ctx context.Context, _ net.Conn, _ *tls.Config) (net.Conn, error) {
			defer close(phaseDone)
			markEntered()
			<-ctx.Done()
			return nil, ctx.Err()
		}
	case "hello":
		counted.writeStarted = markEntered
		close(phaseDone)
	case "ack":
		go func() {
			defer close(peerDone)
			if _, err := protocol.ReadFrame(peer); err != nil {
				return
			}
			markEntered()
			close(phaseDone)
			<-cleanupPeer
		}()
	default:
		t.Fatalf("unknown phase %q", phase)
	}

	return phaseHarness{
		entered:    entered,
		phaseDone:  phaseDone,
		closeCount: &counted.closeCount,
		cleanupFn: func() {
			if phase == "ack" {
				close(cleanupPeer)
				_ = peer.Close()
				waitSignal(t, peerDone, "Ack peer goroutine leaked")
				return
			}
			_ = peer.Close()
		},
	}
}

func (h phaseHarness) cleanup() {
	h.cleanupFn()
}

func (h phaseHarness) waitExited(t *testing.T) {
	t.Helper()
	waitSignal(t, h.phaseDone, "phase goroutine did not exit")
}

func (h phaseHarness) assertCloseCount(t *testing.T) {
	t.Helper()
	if h.closeCount == nil {
		return
	}
	if got := h.closeCount.Load(); got != 1 {
		t.Fatalf("underlying connection closed %d times, want exactly once", got)
	}
}

type countingConn struct {
	net.Conn
	closeCount   atomic.Int32
	writeStarted func()
}

func (c *countingConn) Write(p []byte) (int, error) {
	if c.writeStarted != nil {
		c.writeStarted()
	}
	return c.Conn.Write(p)
}

func (c *countingConn) Close() error {
	c.closeCount.Add(1)
	return c.Conn.Close()
}

type closeCountingPacketConn struct {
	net.PacketConn
	closeCount atomic.Int32
	closeErr   error
}

func (c *closeCountingPacketConn) Close() error {
	c.closeCount.Add(1)
	return c.closeErr
}

func newLifecycleClient(t *testing.T, phaseTimeout time.Duration) *Client {
	t.Helper()
	cfg := Config{
		RelayAddr:                  "relay.invalid:443",
		BackendAddr:                "127.0.0.1:1",
		Token:                      []byte("test-token"),
		TLSConfig:                  &tls.Config{MinVersion: tls.VersionTLS13},
		Transport:                  TransportTCP,
		CarrierDialTimeout:         phaseTimeout,
		CarrierTLSHandshakeTimeout: phaseTimeout,
		CarrierHelloTimeout:        phaseTimeout,
		CarrierAckTimeout:          phaseTimeout,
	}
	if err := normalizeCarrierTimeouts(&cfg); err != nil {
		t.Fatalf("normalize lifecycle test config: %v", err)
	}
	client := &Client{
		cfg:        cfg,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		backoffMin: time.Millisecond,
		backoffMax: time.Millisecond,
		maxStreams: 1,
		done:       make(chan struct{}),
		closed:     make(chan struct{}),
	}
	client.cond = sync.NewCond(&client.mu)
	return client
}

func startLifecycleLoop(client *Client, ctx context.Context) {
	client.wg.Add(1)
	go client.run(ctx, client.serveOnce)
	go func() {
		client.wg.Wait()
		close(client.done)
	}()
}

func waitClient(t *testing.T, client *Client, message string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		client.Wait()
		close(done)
	}()
	waitSignal(t, done, message)
}

func waitSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func assertNoLiveCarrier(t *testing.T, client *Client) {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.attempt != nil || client.conn != nil || client.session != nil {
		t.Fatalf("carrier ownership leaked: attempt=%v conn=%v session=%v",
			client.attempt != nil, client.conn != nil, client.session != nil)
	}
}
