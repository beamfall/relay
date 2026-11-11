package relay_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/relay"
)

// TestSNIBlindRoutingE2E is the GCR-021-A relay-path E2E: it proves the relay
// routes a public connection purely from the peeked ClientHello SNI while
// remaining byte-blind to the client<->home content.
//
// Unlike the log-leak assertions (TestRelayPassesTLSBytesEndToEndAndDoesNotLogPayload,
// TestRelayNeverLogsTokenBytes), which check that content never reaches the
// relay's *logs*, this test taps the raw bytes that cross the relay's public
// socket and asserts the plaintext content sentinel never appears in the wire
// bytes the relay carries at all. The public TLS session is terminated by the
// *home* server (verified against the home CA), so the relay never holds a
// public cert or terminates TLS; it can only see the ClientHello SNI it routes
// on. That makes byte-blindness cryptographic (ADR-0046 / ADR-0018), not
// merely a redaction policy.
//
// The proof rests on three assertions:
//   - the encrypted round-trip succeeds, and because the relay's only routing
//     input is the peeked SNI (relay.Server routes via sni.PeekClientHello ->
//     registry.lookup(ServerName)), a successful delivery to the SNI-registered
//     carrier *is* SNI-blind routing;
//   - the plaintext content sentinel is absent from every raw byte the relay
//     carried in either direction (byte-blindness);
//   - the SNI hostname *is* present in the tapped client->relay bytes (positive
//     control): the relay does see the routing hostname in cleartext, so the
//     sentinel's absence is meaningful, not vacuous (a TLS session that carried
//     nothing would trivially "not leak").
func TestSNIBlindRoutingE2E(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	home := startHomeTLSEcho(t, testHost)
	defer home.Close()

	var logs syncBuffer
	node := startRelay(t, ctx, relay.Config{
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("sni-blind-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{testHost},
		},
		StreamCap: 8,
		Logger:    slog.New(slog.NewTextHandler(&logs, nil)),
	})
	defer node.Close()

	client := startTunnelClient(t, ctx, node.CarrierAddr(), home.Addr(), []byte("sni-blind-token"), []string{testHost})
	defer client.Close()

	// Tap the raw TCP bytes crossing the relay's public socket. TLS is layered
	// on top of the tap, so the tap records exactly what the relay splices:
	// ClientHello (SNI in cleartext) followed by TLS records (ciphertext).
	tap := dialTappedPublic(t, node.PublicAddr())
	defer tap.Close() //nolint:errcheck // test connection cleanup.
	conn := tls.Client(tap, &tls.Config{
		ServerName: testHost,
		RootCAs:    home.Roots,
		MinVersion: tls.VersionTLS13,
	})
	defer conn.Close() //nolint:errcheck // test connection cleanup.
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatalf("public TLS handshake (terminated by home, relay byte-blind): %v", err)
	}
	// The peer cert chains to the *home* CA, not the relay: the relay did not
	// terminate TLS, so it never saw plaintext.
	if err := conn.VerifyHostname(testHost); err != nil {
		t.Fatalf("home-terminated TLS did not verify %s: %v", testHost, err)
	}

	const contentSentinel = "SNI-BLIND-PLAINTEXT-CONTENT-DO-NOT-LEAK"
	if _, err := conn.Write([]byte(contentSentinel + "\n")); err != nil {
		t.Fatalf("write content sentinel: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read echo through relay: %v", err)
	}
	if line != "echo:"+contentSentinel+"\n" {
		t.Fatalf("echo = %q, want home echo of content sentinel", line)
	}

	// Assertion 1 (positive control): the relay saw the SNI hostname in
	// cleartext on the client->relay wire. This is the one thing the relay is
	// allowed to read, and routing depends on it.
	sent := tap.sentBytes()
	if !bytes.Contains(sent, []byte(testHost)) {
		t.Fatalf("SNI hostname %q absent from tapped client->relay bytes; routing input not observed (control failed)", testHost)
	}

	// Assertion 2 (byte-blindness): the plaintext content sentinel must never
	// appear in the raw bytes the relay carried in either direction. It is only
	// ever present inside the client<->home TLS session, which the relay cannot
	// decrypt.
	recv := tap.recvBytes()
	if bytes.Contains(sent, []byte(contentSentinel)) {
		t.Fatal("plaintext content sentinel leaked in client->relay wire bytes (byte-blindness violation)")
	}
	if bytes.Contains(recv, []byte(contentSentinel)) {
		t.Fatal("plaintext content sentinel leaked in relay->client wire bytes (byte-blindness violation)")
	}
	if strings.Contains(logs.String(), contentSentinel) {
		t.Fatalf("relay logs leaked content sentinel (byte-blindness violation):\n%s", logs.String())
	}
}

// dialTappedPublic opens a raw TCP connection to the relay public listener,
// wrapped so every byte read/written can be inspected after the round-trip.
func dialTappedPublic(t *testing.T, addr string) *tappedConn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial relay public listener: %v", err)
	}
	return &tappedConn{Conn: raw}
}

// tappedConn records the raw bytes written to and read from the wrapped
// connection so a test can assert on the ciphertext the relay actually carried.
type tappedConn struct {
	net.Conn
	mu   sync.Mutex
	sent bytes.Buffer
	recv bytes.Buffer
}

func (c *tappedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.sent.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c *tappedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.recv.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c *tappedConn) sentBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.sent.Bytes()...)
}

func (c *tappedConn) recvBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.recv.Bytes()...)
}
