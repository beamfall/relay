package relay_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/cache"
	"github.com/beamfall/relay/internal/protocol"
	"github.com/beamfall/relay/internal/relay"
	"github.com/beamfall/relay/internal/tunnel"
	"github.com/beamfall/relay/relaytoken"
)

const testHost = "home.relay.test"

type mapTokenVerifier map[string]relay.VerifiedCarrier

func (v mapTokenVerifier) VerifyTunnelToken(_ context.Context, token []byte, requested []string) (relay.VerifiedCarrier, error) {
	carrier, ok := v[string(token)]
	if !ok {
		return relay.VerifiedCarrier{}, relay.ErrUnauthorized
	}
	carrier.Hostnames = requested
	return carrier, nil
}

type oneSecondExpiryVerifier struct{}

func (oneSecondExpiryVerifier) VerifyTunnelToken(_ context.Context, _ []byte, requested []string) (relay.VerifiedCarrier, error) {
	return relay.VerifiedCarrier{
		ID:        "carrier-1",
		Hostnames: requested,
		ExpiresAt: time.Now().Add(time.Second),
	}, nil
}

type expiringSurfaceVerifier struct{}

func (expiringSurfaceVerifier) VerifyTunnelToken(ctx context.Context, token []byte, requested []string) (relay.VerifiedCarrier, error) {
	return expiringSurfaceVerifier{}.VerifyCarrierToken(ctx, token, requested, protocol.SurfacePassthrough)
}

func (expiringSurfaceVerifier) VerifyCarrierToken(_ context.Context, token []byte, requested []string, surface string) (relay.VerifiedCarrier, error) {
	switch {
	case surface == protocol.SurfacePassthrough && string(token) == "passthrough-token":
		return relay.VerifiedCarrier{ID: "carrier-1", Hostnames: requested, Surface: surface}, nil
	case surface == protocol.SurfaceCache && string(token) == "cache-token":
		return relay.VerifiedCarrier{ID: "carrier-1", Hostnames: requested, Surface: surface, ExpiresAt: time.Now().Add(40 * time.Millisecond)}, nil
	default:
		return relay.VerifiedCarrier{}, relay.ErrUnauthorized
	}
}

type stableSurfaceVerifier struct{}

func (stableSurfaceVerifier) VerifyTunnelToken(ctx context.Context, token []byte, requested []string) (relay.VerifiedCarrier, error) {
	return stableSurfaceVerifier{}.VerifyCarrierToken(ctx, token, requested, protocol.SurfacePassthrough)
}

func (stableSurfaceVerifier) VerifyCarrierToken(_ context.Context, token []byte, requested []string, surface string) (relay.VerifiedCarrier, error) {
	switch {
	case surface == protocol.SurfacePassthrough && string(token) == "passthrough-token":
		return relay.VerifiedCarrier{ID: "carrier-1", Hostnames: requested, Surface: surface}, nil
	case surface == protocol.SurfaceCache && string(token) == "cache-token":
		return relay.VerifiedCarrier{ID: "carrier-1", Hostnames: requested, Surface: surface}, nil
	default:
		return relay.VerifiedCarrier{}, relay.ErrUnauthorized
	}
}

type dualCacheSurfaceVerifier struct{}

func (dualCacheSurfaceVerifier) VerifyTunnelToken(ctx context.Context, token []byte, requested []string) (relay.VerifiedCarrier, error) {
	return dualCacheSurfaceVerifier{}.VerifyCarrierToken(ctx, token, requested, protocol.SurfacePassthrough)
}

func (dualCacheSurfaceVerifier) VerifyCarrierToken(_ context.Context, token []byte, requested []string, surface string) (relay.VerifiedCarrier, error) {
	switch {
	case surface == protocol.SurfacePassthrough && string(token) == "passthrough-token-1":
		return relay.VerifiedCarrier{ID: "carrier-1", Hostnames: requested, Surface: surface}, nil
	case surface == protocol.SurfaceCache && string(token) == "cache-token-1":
		return relay.VerifiedCarrier{ID: "carrier-1", Hostnames: requested, Surface: surface}, nil
	case surface == protocol.SurfacePassthrough && string(token) == "passthrough-token-2":
		return relay.VerifiedCarrier{ID: "carrier-2", Hostnames: requested, Surface: surface}, nil
	case surface == protocol.SurfaceCache && string(token) == "cache-token-2":
		return relay.VerifiedCarrier{ID: "carrier-2", Hostnames: requested, Surface: surface}, nil
	default:
		return relay.VerifiedCarrier{}, relay.ErrUnauthorized
	}
}

type wrappedHostedVerifier struct {
	*relay.HostedTokenVerifier
}

func TestRelayPassesTLSBytesEndToEndAndDoesNotLogPayload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	var logs syncBuffer
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 8,
		Logger:    slog.New(slog.NewTextHandler(&logs, nil)),
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()

	conn := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer conn.Close() //nolint:errcheck // test connection cleanup.

	sentinel := "SENTINEL-PAYLOAD"
	if _, err := conn.Write([]byte(sentinel + "\n")); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if line != "echo:"+sentinel+"\n" {
		t.Fatalf("echo = %q", line)
	}
	if strings.Contains(logs.String(), sentinel) {
		t.Fatalf("relay logs contain payload sentinel: %s", logs.String())
	}
}

func TestTokenExpiryTakeoverDrainAllowsInflightStreamToComplete(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSGappedStreamer(t, testHost, []byte("before-expiry"), []byte("after-expiry"), 1100*time.Millisecond)
	defer home.Close()
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier:       oneSecondExpiryVerifier{},
		StreamCap:           8,
		ExpiredSessionDrain: 500 * time.Millisecond,
	})
	defer node.Close()

	var tokenNonce atomic.Uint32
	client, err := tunnel.Start(ctx, tunnel.Config{
		RelayAddr:   node.CarrierAddr(),
		BackendAddr: home.Addr(),
		TokenProvider: func(context.Context) ([]byte, error) {
			return []byte{byte(tokenNonce.Add(1))}, nil
		},
		TokenRotationInterval: 500 * time.Millisecond,
		Hostnames:             []string{testHost},
		TLSConfig:             &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		BackoffMin:            5 * time.Millisecond,
		BackoffMax:            10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start tunnel client: %v", err)
	}
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("tunnel client not ready: %v", err)
	}

	conn := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer conn.Close() //nolint:errcheck
	if _, err := conn.Write([]byte("start\n")); err != nil {
		t.Fatalf("start stream: %v", err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read stream across token expiry: %v", err)
	}
	if want := "before-expiryafter-expiry"; string(got) != want {
		t.Fatalf("stream body = %q, want %q", got, want)
	}
}

// TestRelayPassesQUICBytesEndToEnd pins the ADR-0018 §1 v2 QUIC carrier: the
// same public-TLS-passthrough round-trip as the v1 yamux carrier, but the
// tunnel client dials the relay's QUIC carrier listener instead of the
// TLS/TCP one. Proves the QUIC carrier is wired end-to-end (handshake over a
// QUIC stream, registry/fair-use/splice code paths all unchanged) rather than
// merely compiling.
func TestRelayPassesQUICBytesEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 8,
	})
	defer node.Close()
	if node.QUICAddr() == "" {
		t.Fatal("relay QUIC carrier listener did not start")
	}

	client := startTunnelClientTransport(t, ctx, tunnel.TransportQUIC, node.QUICAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()

	conn := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer conn.Close() //nolint:errcheck // test connection cleanup.

	sentinel := "QUIC-SENTINEL-PAYLOAD"
	if _, err := conn.Write([]byte(sentinel + "\n")); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if line != "echo:"+sentinel+"\n" {
		t.Fatalf("echo = %q", line)
	}
}

func TestRelayCacheVerificationKeysOverlapThroughTunnelReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: expiringSurfaceVerifier{},
		StreamCap:     8,
	})
	defer node.Close()

	keys := [][]byte{cacheVerificationKey(1), cacheVerificationKey(2)}
	var keyCalls int
	client, err := tunnel.Start(ctx, tunnel.Config{
		RelayAddr:   node.CarrierAddr(),
		BackendAddr: home.Addr(),
		Token:       []byte("passthrough-token"),
		Hostnames:   []string{testHost},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		BackoffMin:   5 * time.Millisecond,
		BackoffMax:   10 * time.Millisecond,
		CacheCarrier: true,
		CacheToken:   []byte("cache-token"),
		CacheVerificationKeyProvider: func(context.Context) ([]byte, error) {
			if keyCalls >= len(keys) {
				return keys[len(keys)-1], nil
			}
			key := keys[keyCalls]
			keyCalls++
			return key, nil
		},
	})
	if err != nil {
		t.Fatalf("start tunnel client: %v", err)
	}
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("tunnel client not ready: %v", err)
	}

	oldToken := mintCacheToken(t, keys[0])
	waitCacheTokenAccepted(t, ctx, node, oldToken)
	newToken := mintCacheToken(t, keys[1])
	waitCacheTokenAccepted(t, ctx, node, newToken)
	if _, err := node.VerifyCacheAccessToken(ctx, "carrier-1", oldToken); err != nil {
		t.Fatalf("previous cache key rejected during overlap: %v", err)
	}
	forged := mintCacheToken(t, cacheVerificationKey(9))
	if _, err := node.VerifyCacheAccessToken(ctx, "carrier-1", forged); err != cache.ErrUnauthorized {
		t.Fatalf("forged cache token err = %v, want unauthorized", err)
	}
	if _, err := node.VerifyCacheAccessToken(ctx, "missing-carrier", newToken); err != cache.ErrUnauthorized {
		t.Fatalf("cross-carrier cache token err = %v, want unauthorized", err)
	}
}

func TestRelayPullsCacheMissThroughAuthenticatedCacheCarrier(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: stableSurfaceVerifier{},
		StreamCap:     8,
	})
	defer node.Close()

	client, err := tunnel.Start(ctx, tunnel.Config{
		RelayAddr:   node.CarrierAddr(),
		BackendAddr: home.Addr(),
		Token:       []byte("passthrough-token"),
		Hostnames:   []string{testHost},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
		BackoffMin:           5 * time.Millisecond,
		BackoffMax:           10 * time.Millisecond,
		CacheCarrier:         true,
		CacheToken:           []byte("cache-token"),
		CacheVerificationKey: cacheVerificationKey(1),
		CachePullThrough: func(ctx context.Context, req cache.PullRequest) (cache.Entry, bool, error) {
			if req.SegmentSetID != "segset" || req.Segment != "0001.m4s" {
				return cache.Entry{}, false, fmt.Errorf("unexpected pull request: %#v", req)
			}
			return cache.Entry{Bytes: []byte("ciphertext"), ContentType: "video/mp4", ExpiresAt: time.Now().Add(time.Hour)}, true, nil
		},
	})
	if err != nil {
		t.Fatalf("start tunnel client: %v", err)
	}
	defer client.Close()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatalf("tunnel client not ready: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entry, ok, err := node.PullCacheSegment(ctx, cache.PullRequest{CarrierID: "carrier-1", SegmentSetID: "segset", Segment: "0001.m4s"})
		if err != nil {
			t.Fatalf("pull cache segment: %v", err)
		}
		if ok {
			if string(entry.Bytes) != "ciphertext" || entry.ContentType != "video/mp4" {
				t.Fatalf("entry = %#v", entry)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cache carrier pull-through was not wired before deadline")
}

func TestRelayPullsCacheMissThroughRequestedAuthenticatedCarrier(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: dualCacheSurfaceVerifier{},
		StreamCap:     8,
	})
	defer node.Close()

	client1, err := tunnel.Start(ctx, tunnel.Config{
		RelayAddr:            node.CarrierAddr(),
		BackendAddr:          home.Addr(),
		Token:                []byte("passthrough-token-1"),
		Hostnames:            []string{testHost},
		TLSConfig:            &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		BackoffMin:           5 * time.Millisecond,
		BackoffMax:           10 * time.Millisecond,
		CacheCarrier:         true,
		CacheToken:           []byte("cache-token-1"),
		CacheVerificationKey: cacheVerificationKey(1),
		CachePullThrough:     fixedCachePuller("carrier-1-ciphertext"),
	})
	if err != nil {
		t.Fatalf("start first tunnel client: %v", err)
	}
	defer client1.Close()
	if err := client1.WaitReady(ctx); err != nil {
		t.Fatalf("first tunnel client not ready: %v", err)
	}

	client2, err := tunnel.Start(ctx, tunnel.Config{
		RelayAddr:            node.CarrierAddr(),
		BackendAddr:          home.Addr(),
		Token:                []byte("passthrough-token-2"),
		Hostnames:            []string{testHost},
		TLSConfig:            &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		BackoffMin:           5 * time.Millisecond,
		BackoffMax:           10 * time.Millisecond,
		CacheCarrier:         true,
		CacheToken:           []byte("cache-token-2"),
		CacheVerificationKey: cacheVerificationKey(2),
		CachePullThrough:     fixedCachePuller("carrier-2-ciphertext"),
	})
	if err != nil {
		t.Fatalf("start second tunnel client: %v", err)
	}
	defer client2.Close()
	if err := client2.WaitReady(ctx); err != nil {
		t.Fatalf("second tunnel client not ready: %v", err)
	}

	assertRelayPull := func(carrierID, want string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			entry, ok, err := node.PullCacheSegment(ctx, cache.PullRequest{CarrierID: carrierID, SegmentSetID: "segset", Segment: "0001.m4s"})
			if err != nil {
				t.Fatalf("pull cache segment for %s: %v", carrierID, err)
			}
			if ok {
				if string(entry.Bytes) != want {
					t.Fatalf("carrier %s pulled %q, want %q", carrierID, entry.Bytes, want)
				}
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("cache carrier %s pull-through was not wired before deadline", carrierID)
	}

	assertRelayPull("carrier-2", "carrier-2-ciphertext")
	assertRelayPull("carrier-1", "carrier-1-ciphertext")
	if _, ok, err := node.PullCacheSegment(ctx, cache.PullRequest{CarrierID: "missing-carrier", SegmentSetID: "segset", Segment: "0001.m4s"}); err != nil || ok {
		t.Fatalf("missing carrier pull = ok %v err %v, want miss without error", ok, err)
	}
}

func fixedCachePuller(body string) cache.PullFetcher {
	return func(ctx context.Context, req cache.PullRequest) (cache.Entry, bool, error) {
		if req.SegmentSetID != "segset" || req.Segment != "0001.m4s" {
			return cache.Entry{}, false, fmt.Errorf("unexpected pull request: %#v", req)
		}
		return cache.Entry{Bytes: []byte(body), ContentType: "video/mp4", ExpiresAt: time.Now().Add(time.Hour)}, true, nil
	}
}

// TestRelayNeverLogsTokenBytes pins the byte-blindness guarantee that the relay
// must never write token bytes to its logs (PROTOCOL.md: "The relay never logs
// the token"). A distinctive sentinel token is carried through a real carrier
// handshake and a full public round-trip; the sentinel must be absent from the
// relay's log buffer. The carrier-connected log line (a positive control) proves
// the relay is logging at all, so the sentinel's absence is meaningful rather
// than vacuous.
func TestRelayNeverLogsTokenBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const tokenSentinel = "TOKEN-SENTINEL-DO-NOT-LOG"

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	var logs syncBuffer
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte(tokenSentinel),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 8,
		Logger:    slog.New(slog.NewTextHandler(&logs, nil)),
	})
	defer node.Close()

	// A successful carrier handshake (token accepted) plus a public round-trip
	// exercises the full path where the token transits the relay.
	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte(tokenSentinel), []string{testHost})
	defer client.Close()

	conn := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer conn.Close() //nolint:errcheck // test connection cleanup.
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// Positive control: the relay logs the carrier connection, so logging is live.
	if !strings.Contains(logs.String(), "carrier connected") {
		t.Fatalf("expected a carrier-connected log line (positive control), logs:\n%s", logs.String())
	}
	// Load-bearing assertion: the token bytes must never appear in any log line.
	if strings.Contains(logs.String(), tokenSentinel) {
		t.Fatalf("relay logged token bytes (byte-blindness violation):\n%s", logs.String())
	}
}

// TestRelayRejectsUnauthorizedCarrierAndDoesNotLogToken asserts the carrier
// handshake's token-auth rejection path also keeps the (wrong) token out of the
// logs, and that an unauthorized carrier never gets registered (a later public
// dial for its host is refused).
func TestRelayRejectsUnauthorizedCarrierAndDoesNotLogToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const wrongToken = "WRONG-TOKEN-SENTINEL"

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	var logs syncBuffer
	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("the-real-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 4,
		Logger:    slog.New(slog.NewTextHandler(&logs, nil)),
	})
	defer node.Close()

	conn := dialCarrier(t, node.CarrierAddr())
	defer conn.Close() //nolint:errcheck // test connection cleanup.
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.FrameHello, Hello: &protocol.Hello{
		Version:   protocol.Version,
		Token:     []byte(wrongToken),
		Hostnames: []string{testHost},
	}}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read reject: %v", err)
	}
	if frame.Type != protocol.FrameError || frame.Error != "unauthorized" {
		t.Fatalf("reject frame = %+v, want unauthorized", frame)
	}

	// The rejected token must not appear in the unauthorized log line.
	if strings.Contains(logs.String(), wrongToken) {
		t.Fatalf("relay logged rejected token bytes:\n%s", logs.String())
	}
	// Unauthorized carrier never registers: a public dial for its host is refused.
	pub, err := tls.Dial("tcp", node.PublicAddr(), &tls.Config{
		ServerName: testHost,
		RootCAs:    home.Roots,
		MinVersion: tls.VersionTLS13,
	})
	if err == nil {
		pub.Close() //nolint:errcheck // test listener cleanup.
		t.Fatal("expected public dial to fail with no authorized carrier registered")
	}
}

func TestRedactConnectionLogsDefaultRedactsWrappedHostedVerifier(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		host      = "hosted-redact.relay.test"
		missing   = "missing-hosted-redact.relay.test"
		carrierID = "hosted-carrier-redact"
	)

	home := startHomeTLSEcho(t, host)
	defer home.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate hosted signing key: %v", err)
	}
	now := time.Now().UTC()
	token := signHostedRelayTestToken(t, priv, relaytoken.Claims{
		Type:      relaytoken.TokenType,
		Issuer:    "beamfall-cloud",
		Audience:  "beamfall-relay",
		KeyID:     "relay-test-key",
		ServerID:  carrierID,
		Hostnames: []string{host},
		Purpose:   "tunnel-connect",
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
		Nonce:     "nonce-redact",
	})

	var logs syncBuffer
	nonceStore, err := relay.NewFileHMACNonceStore(filepath.Join(t.TempDir(), "hosted-nonces.json"))
	if err != nil {
		t.Fatalf("new hosted nonce store: %v", err)
	}
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: wrappedHostedVerifier{
			HostedTokenVerifier: &relay.HostedTokenVerifier{
				Issuer:   "beamfall-cloud",
				Audience: "beamfall-relay",
				PublicKeys: map[string]ed25519.PublicKey{
					"relay-test-key": pub,
				},
				Now:        func() time.Time { return now },
				NonceStore: nonceStore,
			},
		},
		StreamCap: 4,
		Logger:    slog.New(slog.NewTextHandler(&logs, nil)),
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte(token), []string{host})
	defer client.Close()

	conn := dialPublicTLS(t, node.PublicAddr(), host, home.Roots)
	defer conn.Close() //nolint:errcheck // test connection cleanup.
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	bad, err := tls.Dial("tcp", node.PublicAddr(), &tls.Config{
		ServerName: missing,
		RootCAs:    home.Roots,
		MinVersion: tls.VersionTLS13,
	})
	if err == nil {
		bad.Close() //nolint:errcheck // test listener cleanup.
		t.Fatal("expected missing hosted SNI to fail")
	}

	if !strings.Contains(logs.String(), "connection log redaction") || !strings.Contains(logs.String(), "mode=redacted") {
		t.Fatalf("startup log did not state redacted connection-log mode:\n%s", logs.String())
	}
	var sawOpened, sawRejected, sawConnected bool
	for _, line := range strings.Split(logs.String(), "\n") {
		switch {
		case strings.Contains(line, "stream opened"):
			sawOpened = true
			assertNoPublicMetadata(t, line, host, carrierID)
		case strings.Contains(line, "public rejected"):
			sawRejected = true
			assertNoPublicMetadata(t, line, missing, carrierID)
		case strings.Contains(line, "carrier connected"):
			// Carrier-identity fields (id, hosts) route through the redaction
			// switch too (SECREV-RELAY-15): with redaction on, the connect line
			// must not carry the carrier id or its hostnames.
			sawConnected = true
			assertNoPublicMetadata(t, line, host, carrierID)
		}
	}
	if !sawOpened || !sawRejected || !sawConnected {
		t.Fatalf("missing hosted log lines opened=%v rejected=%v connected=%v:\n%s", sawOpened, sawRejected, sawConnected, logs.String())
	}
}

func TestCarrierAckHostnamesExcludeRefusedConflicts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		sharedHost = "shared.relay.test"
		secondHost = "second.relay.test"
	)
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: mapTokenVerifier{
			"first-token":  {ID: "carrier-1"},
			"second-token": {ID: "carrier-2"},
		},
	})
	defer node.Close()

	first := dialCarrier(t, node.CarrierAddr())
	defer first.Close() //nolint:errcheck // test connection cleanup.
	if err := protocol.WriteFrame(first, protocol.Frame{Type: protocol.FrameHello, Hello: &protocol.Hello{
		Version:   protocol.Version,
		Token:     []byte("first-token"),
		Hostnames: []string{sharedHost},
	}}); err != nil {
		t.Fatalf("write first hello: %v", err)
	}
	if frame, err := protocol.ReadFrame(first); err != nil {
		t.Fatalf("read first ack: %v", err)
	} else if frame.Type != protocol.FrameAck {
		t.Fatalf("first frame = %+v, want ack", frame)
	}

	second := dialCarrier(t, node.CarrierAddr())
	defer second.Close() //nolint:errcheck // test connection cleanup.
	if err := protocol.WriteFrame(second, protocol.Frame{Type: protocol.FrameHello, Hello: &protocol.Hello{
		Version:   protocol.Version,
		Token:     []byte("second-token"),
		Hostnames: []string{sharedHost, secondHost},
	}}); err != nil {
		t.Fatalf("write second hello: %v", err)
	}
	frame, err := protocol.ReadFrame(second)
	if err != nil {
		t.Fatalf("read second ack: %v", err)
	}
	if frame.Type != protocol.FrameAck || frame.Ack == nil {
		t.Fatalf("second frame = %+v, want ack", frame)
	}
	if got := frame.Ack.Hostnames; len(got) != 1 || got[0] != secondHost {
		t.Fatalf("ack hostnames = %#v, want only accepted host %q", got, secondHost)
	}
}

// TestRelayHardFailsOnNonLoopbackAdminAddr pins the SECREV-RELAY-5 hard-fail
// guardrail: binding the admin listener (/healthz, /metrics) to a
// non-loopback/non-private address refuses to start unless AdminAllowPublic
// is set, while a loopback bind (the common/default case) still starts
// cleanly with no warning.
func TestRelayHardFailsOnNonLoopbackAdminAddr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var loopbackLogs syncBuffer
	loopback := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		Logger: slog.New(slog.NewTextHandler(&loopbackLogs, nil)),
	})
	defer loopback.Close()
	if strings.Contains(loopbackLogs.String(), "admin listener") {
		t.Fatalf("loopback admin addr should not warn, got logs:\n%s", loopbackLogs.String())
	}

	cert := mustSelfSignedCert(t, "relay-carrier.local")
	exposedCfg := relay.Config{
		PublicAddr:  "127.0.0.1:0",
		CarrierAddr: "127.0.0.1:0",
		QUICAddr:    "127.0.0.1:0",
		AdminAddr:   "0.0.0.0:0",
		CarrierTLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert.TLSCert},
			MinVersion:   tls.VersionTLS13,
		},
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if node, err := relay.Start(ctx, exposedCfg); err == nil {
		node.Close()
		t.Fatal("non-loopback admin addr without AdminAllowPublic should refuse to start, got no error")
	}

	// ADR-0146 §5: even with AdminAllowPublic, a non-loopback /metrics bind must
	// carry an operator credential — Start fails closed without one.
	exposedCfg.AdminAllowPublic = true
	if node, err := relay.Start(ctx, exposedCfg); err == nil {
		node.Close()
		t.Fatal("non-loopback admin addr without AdminMetricsToken should refuse to start (ADR-0146 §5), got no error")
	}

	exposedCfg.AdminMetricsToken = "operator-metrics-secret"
	allowed, err := relay.Start(ctx, exposedCfg)
	if err != nil {
		t.Fatalf("non-loopback admin addr with AdminAllowPublic + AdminMetricsToken should start, got: %v", err)
	}
	allowed.Close()
}

// TestRelayThrottlesRepeatedUnauthorizedHandshakes proves the failed-handshake
// throttle is wired into the carrier auth path end-to-end: a burst of wrong-token
// handshakes is rejected and counted, and a legitimate carrier still connects
// afterward (the throttle penalizes bad sources without bricking the listener).
func TestRelayThrottlesRepeatedUnauthorizedHandshakes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("the-real-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 4,
	})
	defer node.Close()

	// A burst of unauthorized handshakes. Kept just over the free-failure
	// threshold so the (bounded, growing) backoff doesn't slow the test much.
	const attempts = 8
	for i := 0; i < attempts; i++ {
		conn := dialCarrier(t, node.CarrierAddr())
		if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.FrameHello, Hello: &protocol.Hello{
			Version:   protocol.Version,
			Token:     []byte("WRONG"),
			Hostnames: []string{testHost},
		}}); err != nil {
			conn.Close() //nolint:errcheck // test connection cleanup.
			t.Fatalf("write hello %d: %v", i, err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		frame, err := protocol.ReadFrame(conn)
		if err != nil {
			conn.Close() //nolint:errcheck // test connection cleanup.
			t.Fatalf("read reject %d: %v", i, err)
		}
		if frame.Type != protocol.FrameError || frame.Error != "unauthorized" {
			conn.Close() //nolint:errcheck // test connection cleanup.
			t.Fatalf("attempt %d frame = %+v, want unauthorized", i, frame)
		}
		conn.Close() //nolint:errcheck // test connection cleanup.
	}

	// Every rejected handshake must be counted.
	body := getMetrics(t, node.AdminAddr())
	if !strings.Contains(body, "beamfall_relay_handshake_failures_total") {
		t.Fatalf("metrics missing handshake_failures counter:\n%s", body)
	}
	for _, want := range []string{
		"beamfall_relay_handshake_failures_total 0",
		"beamfall_relay_handshake_failures_total 1",
		"beamfall_relay_handshake_failures_total 2",
	} {
		if strings.Contains(body, want+"\n") {
			t.Fatalf("handshake_failures too low after %d bad handshakes: line %q\n%s", attempts, want, body)
		}
	}

	// A legitimate carrier still connects despite the prior bad-handshake burst.
	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("the-real-token"), []string{testHost})
	defer client.Close()
}

func TestRelayDeliversFullDownloadAfterClientHalfClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Two-part download with a gap between the parts. The client half-closes its
	// write side after receiving part 1, while part 2 is still pending upstream.
	// A splice that returns as soon as the client->upstream copy hits EOF would
	// let the deferred close tear down the still-active download direction and
	// truncate part 2; waiting for both directions delivers the full payload.
	part1 := bytes.Repeat([]byte("0123456789abcdef"), 64) // 1 KiB
	part2 := bytes.Repeat([]byte("fedcba9876543210"), 64) // 1 KiB
	home := startHomeTLSGappedStreamer(t, testHost, part1, part2, 200*time.Millisecond)
	defer home.Close()

	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 8,
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()

	// Dial raw TCP and wrap TLS ourselves so we keep a handle on the TCP socket.
	// The relay is byte-blind (it splices raw TCP, never terminates client TLS),
	// so a real client half-close is a FIN on the TCP write half; a TLS
	// close-notify alone would not make the relay's raw read return EOF.
	tcp, err := net.Dial("tcp", node.PublicAddr())
	if err != nil {
		t.Fatalf("dial public tcp: %v", err)
	}
	defer tcp.Close() //nolint:errcheck // test listener cleanup.
	conn := tls.Client(tcp, &tls.Config{
		ServerName: testHost,
		RootCAs:    home.Roots,
		MinVersion: tls.VersionTLS13,
	})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("client tls handshake: %v", err)
	}

	if _, err := conn.Write([]byte("GET\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read part 1 so the download is provably in flight, then half-close the
	// client's TCP write side (request-then-long-download). The client->upstream
	// copy hits EOF now, while part 2 is still pending upstream.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	first := make([]byte, len(part1))
	if _, err := io.ReadFull(conn, first); err != nil {
		t.Fatalf("read download part 1: %v", err)
	}
	if !bytes.Equal(first, part1) {
		t.Fatalf("download part 1 corrupted")
	}
	if err := tcp.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("half-close client tcp write: %v", err)
	}

	rest, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read download remainder: %v", err)
	}
	if !bytes.Equal(rest, part2) {
		t.Fatalf("download truncated after half-close: got %d bytes, want %d", len(rest), len(part2))
	}
}

func TestRelayRejectsUnknownSNI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 4,
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()

	conn, err := tls.Dial("tcp", node.PublicAddr(), &tls.Config{
		ServerName: "missing.relay.test",
		RootCAs:    home.Roots,
		MinVersion: tls.VersionTLS13,
	})
	if err == nil {
		conn.Close() //nolint:errcheck // test connection cleanup.
		t.Fatal("expected TLS handshake through unknown SNI to fail")
	}
}

func TestRelayEnforcesStreamCap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 1,
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()

	first := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer first.Close() //nolint:errcheck // test connection cleanup.

	second, err := tls.Dial("tcp", node.PublicAddr(), &tls.Config{
		ServerName: testHost,
		RootCAs:    home.Roots,
		MinVersion: tls.VersionTLS13,
	})
	if err == nil {
		second.Close() //nolint:errcheck // test connection cleanup.
		t.Fatal("expected second stream to fail while stream cap is exhausted")
	}
}

// TestPerCarrierCapLeavesCapacityForSecondIPv4 proves 64 connection attempts
// from one IPv4 /32 cannot consume a carrier's full 64-stream budget: only the
// configured per-source share remains open, and a second /32 can still connect.
func TestPerCarrierCapLeavesCapacityForSecondIPv4(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()
	node := startRelay(t, ctx, relay.Config{
		PublicAddr: "0.0.0.0:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap:           64,
		MaxPublicConnsPerIP: 64,
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()
	_, publicPort, err := net.SplitHostPort(node.PublicAddr())
	if err != nil {
		t.Fatalf("split public address: %v", err)
	}
	firstAddr := net.JoinHostPort("127.0.0.1", publicPort)
	secondIP := assignedNonLoopbackIPv4(t)
	secondAddr := net.JoinHostPort(secondIP, publicPort)

	held := make([]*tls.Conn, 0, 16)
	defer func() {
		for _, conn := range held {
			_ = conn.Close()
		}
	}()
	for i := 0; i < 16; i++ {
		conn, err := dialPublicTLSFrom(firstAddr, testHost, home.Roots, "127.0.0.1")
		if err != nil {
			t.Fatalf("source one connection %d within cap: %v", i+1, err)
		}
		held = append(held, conn)
	}
	for i := 16; i < 64; i++ {
		conn, err := dialPublicTLSFrom(firstAddr, testHost, home.Roots, "127.0.0.1")
		if err == nil {
			_ = conn.Close()
			t.Fatalf("source one connection %d exceeded per-carrier cap", i+1)
		}
	}

	second, err := dialPublicTLSFrom(secondAddr, testHost, home.Roots, secondIP)
	if err != nil {
		t.Fatalf("second IPv4 /32 could not use remaining carrier capacity: %v", err)
	}
	_ = second.Close()
}

func TestRelayFairUseThrottleRefusesOnlyNewConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()
	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 8,
		FairUse: relay.FairUseConfig{
			Enabled:           true,
			WindowDays:        30,
			HardLimitBytes:    1,
			ThrottledMaxConns: 1,
		},
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()

	first := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer first.Close() //nolint:errcheck // test connection cleanup.
	if _, err := first.Write([]byte("first\n")); err != nil {
		t.Fatalf("write first payload: %v", err)
	}
	if _, err := bufio.NewReader(first).ReadString('\n'); err != nil {
		t.Fatalf("read first echo: %v", err)
	}

	second, err := tls.Dial("tcp", node.PublicAddr(), &tls.Config{
		ServerName: testHost,
		RootCAs:    home.Roots,
		MinVersion: tls.VersionTLS13,
	})
	if err == nil {
		second.Close() //nolint:errcheck // test connection cleanup.
		t.Fatal("expected second stream to fail while tunnel is fair-use throttled")
	}
	if _, err := first.Write([]byte("still-open\n")); err != nil {
		t.Fatalf("established stream was killed by fair-use throttle: %v", err)
	}

	body := getMetrics(t, node.AdminAddr())
	if !strings.Contains(body, "beamfall_relay_fairuse_refused_connections_total 1") {
		t.Fatalf("metrics missing fair-use refusal: %s", body)
	}
	if !strings.Contains(body, "beamfall_relay_fairuse_throttled_tunnels 1") {
		t.Fatalf("metrics missing throttled tunnel gauge: %s", body)
	}
}

func TestRelayFairUseDisabledDoesNotThrottle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap:                 2,
		MaxStreamsPerIPPerCarrier: 2, // keep this test scoped to fair-use disablement
		FairUse: relay.FairUseConfig{
			Enabled:           false,
			WindowDays:        30,
			HardLimitBytes:    1,
			ThrottledMaxConns: 1,
		},
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	defer client.Close()

	first := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer first.Close() //nolint:errcheck // test connection cleanup.
	if _, err := first.Write([]byte("first\n")); err != nil {
		t.Fatalf("write first payload: %v", err)
	}
	if _, err := bufio.NewReader(first).ReadString('\n'); err != nil {
		t.Fatalf("read first echo: %v", err)
	}

	second := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer second.Close() //nolint:errcheck // test connection cleanup.
}

func TestRelayRejectsAfterCarrierIsTornDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 4,
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("test-token"), []string{testHost})
	client.Close()

	// Poll instead of a fixed sleep: the carrier teardown is asynchronous, so a
	// single dial shortly after Close() can race the relay's carrier-session
	// cleanup and see a stale success. Retry the TLS dial until it fails (or the
	// deadline elapses), closing any successful conn so it doesn't linger.
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := tls.Dial("tcp", node.PublicAddr(), &tls.Config{
			ServerName: testHost,
			RootCAs:    home.Roots,
			MinVersion: tls.VersionTLS13,
		})
		if err != nil {
			break
		}
		conn.Close() //nolint:errcheck // test connection cleanup.
		if time.Now().After(deadline) {
			t.Fatal("expected TLS handshake to fail after carrier closes")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRelayAdminHealthAndMetrics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("test-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
	})
	defer node.Close()

	health, err := http.Get("http://" + node.AdminAddr() + "/healthz")
	if err != nil {
		t.Fatalf("get healthz: %v", err)
	}
	defer health.Body.Close() //nolint:errcheck // test response cleanup.
	if health.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", health.StatusCode)
	}

	metrics, err := http.Get("http://" + node.AdminAddr() + "/metrics")
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	defer metrics.Body.Close() //nolint:errcheck // test response cleanup.
	body, err := io.ReadAll(metrics.Body)
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	if !strings.Contains(string(body), "beamfall_relay_carriers_connected") {
		t.Fatalf("metrics missing carrier gauge: %s", string(body))
	}
}

func TestRelayMetricsOmitConnectionMetadataAndSecrets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		tokenSentinel   = "METRICS-TOKEN-SENTINEL"
		payloadSentinel = "METRICS-PAYLOAD-SENTINEL"
		carrierID       = "metrics-carrier-id"
	)

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte(tokenSentinel),
			CarrierID: carrierID,
			Hostnames: []string{testHost},
		},
		StreamCap: 4,
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte(tokenSentinel), []string{testHost})
	defer client.Close()

	conn := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer conn.Close() //nolint:errcheck // test connection cleanup.
	if _, err := conn.Write([]byte(payloadSentinel + "\n")); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	body := getMetrics(t, node.AdminAddr())
	// ADR-0146 §9: connection metadata and secrets — hostnames, carrier id,
	// tunnel token, payload — must never surface in /metrics (labels included).
	// The bounded SLI labels (outcome/le, ADR-0146 §8) are permitted and are
	// asserted separately in TestMetricsLabelsAreBoundedOnly.
	for _, forbidden := range []string{testHost, carrierID, tokenSentinel, payloadSentinel} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metrics exported forbidden metadata %q:\n%s", forbidden, body)
		}
	}
}

func TestMetadataRetentionConformance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		tokenSentinel   = "METADATA-RETENTION-TOKEN-SENTINEL"
		payloadSentinel = "METADATA-RETENTION-PAYLOAD-SENTINEL"
		carrierID       = "metadata-retention-carrier"
	)

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	var logs syncBuffer
	redactLogs := false
	node := startRelay(t, ctx, relay.Config{
		AdminAddr: "127.0.0.1:0",
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte(tokenSentinel),
			CarrierID: carrierID,
			Hostnames: []string{testHost},
		},
		StreamCap:            4,
		Logger:               slog.New(slog.NewTextHandler(&logs, nil)),
		RedactConnectionLogs: &redactLogs,
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte(tokenSentinel), []string{testHost})
	defer client.Close()

	conn := dialPublicTLS(t, node.PublicAddr(), testHost, home.Roots)
	defer conn.Close() //nolint:errcheck // test connection cleanup.
	if _, err := conn.Write([]byte(payloadSentinel + "\n")); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	gotLogs := logs.String()
	for _, want := range []string{
		"mode=metadata",
		"carrier connected",
		"id=" + carrierID,
		"hosts=[" + testHost + "]",
		"stream opened",
		"host=" + testHost,
		"carrier=" + carrierID,
		"remote=",
	} {
		if !strings.Contains(gotLogs, want) {
			t.Fatalf("metadata-retention log conformance missing %q:\n%s", want, gotLogs)
		}
	}
	for _, forbidden := range []string{tokenSentinel, payloadSentinel} {
		if strings.Contains(gotLogs, forbidden) {
			t.Fatalf("metadata-retention logs leaked forbidden value %q:\n%s", forbidden, gotLogs)
		}
	}

	if err := relay.ValidateRetentionWindow(relay.OperationalLogRetentionWindow); err != nil {
		t.Fatalf("published retention window violates policy: %v", err)
	}
	wantRetention := strconv.FormatInt(int64(relay.OperationalLogRetentionWindow/time.Second), 10)
	body := getMetrics(t, node.AdminAddr())
	if !strings.Contains(body, "beamfall_relay_log_retention_seconds "+wantRetention+"\n") {
		t.Fatalf("metrics did not publish retention window %s seconds:\n%s", wantRetention, body)
	}
}

func getMetrics(t *testing.T, adminAddr string) string {
	t.Helper()
	resp, err := http.Get("http://" + adminAddr + "/metrics")
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test response cleanup.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	return string(body)
}

func signHostedRelayTestToken(t *testing.T, key ed25519.PrivateKey, claims relaytoken.Claims) string {
	t.Helper()
	tok, err := relaytoken.SignWith(claims, claims.KeyID, func(b []byte) ([]byte, error) {
		return ed25519.Sign(key, b), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func assertNoPublicMetadata(t *testing.T, line string, forbidden ...string) {
	t.Helper()
	for _, field := range []string{"remote=", "host=", "carrier="} {
		if strings.Contains(line, field) {
			t.Fatalf("hosted public log kept joinable field %q: %s", field, line)
		}
	}
	for _, value := range forbidden {
		if strings.Contains(line, value) {
			t.Fatalf("hosted public log leaked %q: %s", value, line)
		}
	}
}

func startRelay(t *testing.T, ctx context.Context, cfg relay.Config) *relay.Server {
	t.Helper()
	cert := mustSelfSignedCert(t, "relay-carrier.local")
	if cfg.PublicAddr == "" {
		cfg.PublicAddr = "127.0.0.1:0"
	}
	cfg.CarrierAddr = "127.0.0.1:0"
	// Also stand up the ADR-0018 §1 v2 QUIC carrier listener on every test relay
	// so QUIC-carrier tests can reuse this helper instead of a parallel one.
	cfg.QUICAddr = "127.0.0.1:0"
	cfg.CarrierTLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert.TLSCert},
		MinVersion:   tls.VersionTLS13,
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	node, err := relay.Start(ctx, cfg)
	if err != nil {
		t.Fatalf("start relay: %v", err)
	}
	// Server.Close is documented idempotent (closeOnce), so this self-cleanup is
	// safe alongside the ~27 existing `defer node.Close()` call sites: whichever
	// runs first wins, the other is a no-op.
	t.Cleanup(node.Close)
	return node
}

func cacheVerificationKey(offset byte) []byte {
	key := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	for i := range key {
		key[i] += offset
	}
	return key
}

func mintCacheToken(t *testing.T, key []byte) string {
	t.Helper()
	token, err := cache.MintToken(key, "segset", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("mint cache token: %v", err)
	}
	return token
}

func waitCacheTokenAccepted(t *testing.T, ctx context.Context, node *relay.Server, token string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := node.VerifyCacheAccessToken(ctx, "carrier-1", token); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cache token was not accepted before deadline")
}

func startTunnelClient(t *testing.T, ctx context.Context, relayAddr, backendAddr string, token []byte, hostnames []string) *tunnel.Client {
	t.Helper()
	return startTunnelClientTransport(t, ctx, "", relayAddr, backendAddr, token, hostnames)
}

// startTunnelClientTransport is startTunnelClient with an explicit carrier
// transport (tunnel.TransportTCP/tunnel.TransportQUIC; "" defaults to TCP), so
// the same relay carrier tests can be driven over either wire transport.
func startTunnelClientTransport(t *testing.T, ctx context.Context, transport, relayAddr, backendAddr string, token []byte, hostnames []string) *tunnel.Client {
	t.Helper()
	client, err := tunnel.Start(ctx, tunnel.Config{
		RelayAddr:   relayAddr,
		BackendAddr: backendAddr,
		Token:       token,
		Hostnames:   hostnames,
		Transport:   transport,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
	})
	if err != nil {
		t.Fatalf("start tunnel client: %v", err)
	}
	// Start now connects asynchronously inside a reconnect loop; wait for the
	// carrier session to come up so tests dialing the public listener don't race
	// ahead of carrier registration.
	readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.WaitReady(readyCtx); err != nil {
		t.Fatalf("tunnel client not ready: %v", err)
	}
	return client
}

func dialPublicTLS(t *testing.T, addr, serverName string, roots *x509.CertPool) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: serverName,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial public TLS: %v", err)
	}
	return conn
}

func dialPublicTLSFrom(addr, serverName string, roots *x509.CertPool, localIP string) (*tls.Conn, error) {
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)}}
	raw, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		_ = raw.Close()
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName: serverName,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
	})
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func assignedNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("list local addresses: %v", err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		return ip.String()
	}
	t.Fatal("no assigned non-loopback IPv4 address available for second-source acceptance test")
	return ""
}

type homeServer struct {
	listener net.Listener
	Roots    *x509.CertPool
}

func (h *homeServer) Addr() string { return h.listener.Addr().String() }
func (h *homeServer) Close()       { _ = h.listener.Close() }

func startHomeTLSEcho(t *testing.T, host string) *homeServer {
	t.Helper()
	cert := mustSelfSignedCert(t, host)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert.TLSCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("start home tls server: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close() //nolint:errcheck // test home server cleanup.
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return
				}
				_, _ = conn.Write([]byte("echo:" + line))
				_, _ = io.Copy(io.Discard, conn)
			}(conn)
		}
	}()
	return &homeServer{listener: ln, Roots: cert.Roots}
}

// startHomeTLSGappedStreamer serves a home backend that, after reading the
// request line, writes part1, waits gap, then writes part2 and closes. The gap
// keeps the download direction provably in flight while the public client
// half-closes its write side, exercising the request-then-long-download path.
func startHomeTLSGappedStreamer(t *testing.T, host string, part1, part2 []byte, gap time.Duration) *homeServer {
	t.Helper()
	cert := mustSelfSignedCert(t, host)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert.TLSCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("start home tls streamer: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close() //nolint:errcheck // test home server cleanup.
				if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
					return
				}
				if _, err := conn.Write(part1); err != nil {
					return
				}
				time.Sleep(gap)
				_, _ = conn.Write(part2)
			}(conn)
		}
	}()
	return &homeServer{listener: ln, Roots: cert.Roots}
}

type testCert struct {
	TLSCert tls.Certificate
	Roots   *x509.CertPool
}

func mustSelfSignedCert(t *testing.T, dnsName string) testCert {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(certPEM); !ok {
		t.Fatal("append root cert")
	}
	return testCert{TLSCert: tlsCert, Roots: roots}
}

// syncBuffer is a mutex-guarded io.Writer + reader for capturing relay logs in
// tests. The relay writes log lines from background goroutines (the carrier and
// public accept handlers) while the test goroutine reads the captured output to
// assert byte-blindness. A bare bytes.Buffer is not safe for that concurrent
// Write/String pattern, so reads under -race trip the detector even though the
// production logger (a real slog.Logger over stderr) is internally synchronized.
// syncBuffer makes the test harness honest under -race without changing what is
// asserted.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
