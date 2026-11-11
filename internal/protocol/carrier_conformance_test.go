// carrier_conformance_test.go proves the ADR-0018 §1 v2 requirement that the
// Hello/Ack/Error wire contract is carrier-agnostic: the golden vectors in
// contracts/protocol/v1/vectors.json (whose `carriers` field, populated by
// cmd/gen-vectors, lists every transport this guarantee covers) must
// round-trip identically over a real yamux-over-TLS/TCP stream (v1) and a
// real QUIC stream (v2), not just through in-memory ReadFrame/WriteFrame
// calls (already covered by conformance_test.go). This is a pure transport-
// carriage property, so it is exercised directly against YamuxConfig/
// QUICConfig here rather than through a live relay.Server, which would add
// unrelated handshake/auth logic to what should be an isolated carriage
// check.
package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
)

// TestCarrierConformanceVectorsRoundTripOverEveryTransport replays each golden
// vector's raw wire bytes over a real stream of every carrier transport listed
// in vectors.json's `carriers` field, asserting ReadFrame decodes the same
// frame regardless of which transport carried it.
func TestCarrierConformanceVectorsRoundTripOverEveryTransport(t *testing.T) {
	vf := loadVectors(t)
	if len(vf.Vectors) == 0 {
		t.Fatal("no golden vectors loaded")
	}
	wantCarriers := map[string]bool{"tcp": true, "quic": true}
	for _, c := range vf.Carriers {
		delete(wantCarriers, c)
	}
	if len(wantCarriers) != 0 {
		t.Fatalf("vectors.json carriers list missing: %v", wantCarriers)
	}

	t.Run("tcp", func(t *testing.T) {
		client, server := yamuxPipe(t)
		defer client.Close() //nolint:errcheck // test session cleanup.
		defer server.Close() //nolint:errcheck // test session cleanup.
		clientStream, err := client.Open()
		if err != nil {
			t.Fatalf("open yamux client stream: %v", err)
		}
		defer clientStream.Close() //nolint:errcheck // test stream cleanup.
		serverStream, err := server.Accept()
		if err != nil {
			t.Fatalf("accept yamux server stream: %v", err)
		}
		defer serverStream.Close() //nolint:errcheck // test stream cleanup.
		replayVectorsOverStream(t, vf, clientStream, serverStream)
	})

	t.Run("quic", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		clientConn, serverConn := quicPipe(t, ctx)
		defer clientConn.CloseWithError(0, "") //nolint:errcheck // test connection cleanup.
		defer serverConn.CloseWithError(0, "") //nolint:errcheck // test connection cleanup.
		clientStream, serverStream := quicStreamPair(t, ctx, clientConn, serverConn)
		defer clientStream.Close() //nolint:errcheck // test stream cleanup.
		defer serverStream.Close() //nolint:errcheck // test stream cleanup.
		replayVectorsOverStream(t, vf, clientStream, serverStream)
	})
}

func TestAbruptYamuxCloseTimeoutIsBounded(t *testing.T) {
	const want = 30 * time.Second
	if got := YamuxConfig(0).StreamCloseTimeout; got != want {
		t.Fatalf("yamux StreamCloseTimeout = %s, want %s", got, want)
	}
}

// replayVectorsOverStream writes each golden vector's raw wire bytes to
// writer and asserts reader (the other end of the same real transport
// stream) decodes back to the identical frame, proving the transport carries
// the frame verbatim (no reframing, truncation, or reordering).
func replayVectorsOverStream(t *testing.T, vf vectorFile, writer io.Writer, reader io.Reader) {
	t.Helper()
	type deadliner interface{ SetReadDeadline(time.Time) error }
	if d, ok := reader.(deadliner); ok {
		if err := d.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
	}
	for _, v := range vf.Vectors {
		wire, err := hex.DecodeString(v.WireBytesHex)
		if err != nil {
			t.Fatalf("%s: decode hex: %v", v.Name, err)
		}
		if _, err := writer.Write(wire); err != nil {
			t.Fatalf("%s: write vector over stream: %v", v.Name, err)
		}
		got, err := ReadFrame(reader)
		if err != nil {
			t.Fatalf("%s: read frame back from stream: %v", v.Name, err)
		}
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(v.Struct)
		if !bytes.Equal(gotJSON, wantJSON) {
			t.Errorf("%s: frame carried over stream mismatch:\n  got  %s\n  want %s", v.Name, gotJSON, wantJSON)
		}
	}
}

// yamuxPipe returns a connected client/server yamux.Session pair over a real
// TLS/TCP loopback listener, using the shared YamuxConfig on both ends (as
// the relay and tunnel client do).
func yamuxPipe(t *testing.T) (client, server *yamux.Session) {
	t.Helper()
	cert := selfSignedTestCert(t, "carrier-conformance.local")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test listener cleanup.

	type dialResult struct {
		conn net.Conn
		err  error
	}
	roots := x509.NewCertPool()
	roots.AddCert(mustParseCert(t, cert))
	// tls.Dial completes the client handshake, which cannot finish until the
	// server drives its own handshake — but the server *tls.Conn only starts
	// its handshake once yamux.Server (below) reads from it. Run the dial in a
	// goroutine so the client and server handshakes proceed concurrently;
	// blocking on it here would deadlock against ln.Accept()/yamux.Server.
	dialCh := make(chan dialResult, 1)
	go func() {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			ServerName: "carrier-conformance.local",
			RootCAs:    roots,
			MinVersion: tls.VersionTLS13,
		})
		dialCh <- dialResult{conn, err}
	}()

	serverTCP, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept tls: %v", err)
	}

	// yamux.Server reads from serverTCP, which drives the server-side TLS
	// handshake and unblocks the tls.Dial goroutine.
	serverSession, err := yamux.Server(serverTCP, YamuxConfig(0))
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}
	dr := <-dialCh
	if dr.err != nil {
		t.Fatalf("dial tls: %v", dr.err)
	}
	clientSession, err := yamux.Client(dr.conn, YamuxConfig(0))
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	return clientSession, serverSession
}

// quicPipe returns a connected client/server *quic.Conn pair over a real UDP
// loopback listener, using the shared QUICConfig on both ends.
func quicPipe(t *testing.T, ctx context.Context) (client, server *quic.Conn) {
	t.Helper()
	cert := selfSignedTestCert(t, "carrier-conformance.local")
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"carrier-conformance-test"},
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, QUICConfig())
	if err != nil {
		t.Fatalf("listen quic: %v", err)
	}

	type acceptResult struct {
		conn *quic.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		acceptCh <- acceptResult{conn, err}
	}()

	clientConn, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"carrier-conformance-test"},
	}, QUICConfig())
	if err != nil {
		t.Fatalf("dial quic: %v", err)
	}

	res := <-acceptCh
	if res.err != nil {
		t.Fatalf("accept quic: %v", res.err)
	}
	return clientConn, res.conn
}

// quicStreamPair returns a connected client/server *quic.Stream pair on an
// established connection. A QUIC stream is only announced to the peer once the
// opener writes on it (OpenStreamSync alone sends nothing on the wire, so a
// bare AcceptStream would block until the client's first byte). We prime the
// stream with a one-byte marker so the server's AcceptStream unblocks, then
// consume the marker on the server end so the caller sees a clean stream.
func quicStreamPair(t *testing.T, ctx context.Context, clientConn, serverConn *quic.Conn) (client, server *quic.Stream) {
	t.Helper()
	const prime = byte(0)
	clientStream, err := clientConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open quic client stream: %v", err)
	}
	if _, err := clientStream.Write([]byte{prime}); err != nil {
		t.Fatalf("prime quic client stream: %v", err)
	}
	serverStream, err := serverConn.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept quic server stream: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(serverStream, buf); err != nil {
		t.Fatalf("read quic prime byte: %v", err)
	}
	if buf[0] != prime {
		t.Fatalf("quic prime byte mismatch: got %d want %d", buf[0], prime)
	}
	return clientStream, serverStream
}

func selfSignedTestCert(t *testing.T, dnsName string) tls.Certificate {
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func mustParseCert(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return parsed
}
