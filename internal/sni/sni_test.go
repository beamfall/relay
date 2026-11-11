package sni

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPeekClientHelloExtractsSNIAndPreservesBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close() //nolint:errcheck // test connection cleanup.
	defer server.Close() //nolint:errcheck // test connection cleanup.

	errc := make(chan error, 1)
	go func() {
		tlsClient := tls.Client(client, &tls.Config{
			ServerName:         "home.relay.example",
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		})
		errc <- tlsClient.Handshake()
	}()

	result, err := PeekClientHello(server, 4096, 2*time.Second)
	if err != nil {
		t.Fatalf("peek client hello: %v", err)
	}
	if result.ServerName != "home.relay.example" {
		t.Fatalf("server name = %q", result.ServerName)
	}
	if len(result.Prefix) == 0 {
		t.Fatal("expected preserved prefix bytes")
	}
	if !bytes.Equal(result.Prefix[:5], []byte{0x16, 0x03, result.Prefix[2], result.Prefix[3], result.Prefix[4]}) {
		t.Fatal("prefix does not look like a TLS handshake record")
	}
}

func TestPeekClientHelloRejectsAbsentSNI(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close() //nolint:errcheck // test connection cleanup.
	defer server.Close() //nolint:errcheck // test connection cleanup.

	go func() {
		tlsClient := tls.Client(client, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		})
		_ = tlsClient.Handshake()
	}()

	_, err := PeekClientHello(server, 4096, 2*time.Second)
	if !errors.Is(err, ErrNoSNI) {
		t.Fatalf("err = %v, want ErrNoSNI", err)
	}
}

func TestPeekClientHelloHonorsSlowlorisDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close() //nolint:errcheck // test connection cleanup.
	defer server.Close() //nolint:errcheck // test connection cleanup.

	go func() {
		_, _ = client.Write([]byte{0x16})
		time.Sleep(200 * time.Millisecond)
	}()

	_, err := PeekClientHello(server, 4096, 25*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout")
	}
}

// TestPeekClientHelloReassemblesFragmentedHandshake asserts a ClientHello split
// across two TLS handshake records (legal fragmentation, as seen with PQ key
// shares / ECH) is reassembled and its SNI recovered, and the preserved prefix
// holds both records verbatim so the relay can splice the original bytes.
func TestPeekClientHelloReassemblesFragmentedHandshake(t *testing.T) {
	full := buildClientHello(t, "home.relay.example", nil)
	hs := full[5:] // handshake message bytes (drop the single 5-byte record header)

	// Split the handshake stream into two fragments carried by two records.
	split := len(hs) / 2
	rec1 := append([]byte{0x16, 0x03, 0x03}, uint16be(split)...)
	rec1 = append(rec1, hs[:split]...)
	rec2 := append([]byte{0x16, 0x03, 0x03}, uint16be(len(hs)-split)...)
	rec2 = append(rec2, hs[split:]...)
	wire := append(append([]byte(nil), rec1...), rec2...)

	client, server := net.Pipe()
	defer client.Close() //nolint:errcheck // test connection cleanup.
	defer server.Close() //nolint:errcheck // test connection cleanup.
	go func() {
		_, _ = client.Write(wire)
	}()

	result, err := PeekClientHello(server, 4096, 2*time.Second)
	if err != nil {
		t.Fatalf("peek fragmented client hello: %v", err)
	}
	if result.ServerName != "home.relay.example" {
		t.Fatalf("server name = %q, want home.relay.example", result.ServerName)
	}
	if !bytes.Equal(result.Prefix, wire) {
		t.Fatalf("preserved prefix did not match the two records verbatim")
	}
}

// TestPeekClientHelloBailsOnTooManyRecords feeds a pathological stream of many
// single-byte-body TLS records (each legal on its own, well under maxBytes in
// aggregate) and asserts the reassembly loop bails via the maxHandshakeRecords
// cap rather than relying solely on the caller's deadline as a backstop.
func TestPeekClientHelloBailsOnTooManyRecords(t *testing.T) {
	// First record: a valid client_hello handshake header (type=0x01) declaring a
	// huge handshake length, so the loop keeps waiting for more fragments instead
	// of bailing early on a type/length mismatch. Every following record adds one
	// filler byte, never reaching the declared length, so only the iteration cap
	// can stop the loop.
	var wire []byte
	wire = append(wire, 0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0xff, 0xff, 0xff)
	for i := 0; i < maxHandshakeRecords; i++ {
		wire = append(wire, 0x16, 0x03, 0x03, 0x00, 0x01, 0x00)
	}

	_, err := PeekClientHello(readDeadlineConn{Reader: bytes.NewReader(wire)}, 1<<20, 2*time.Second)
	if !errors.Is(err, ErrTooManyRecords) {
		t.Fatalf("err = %v, want ErrTooManyRecords", err)
	}
}

// TestReadRecordRejectsOversizedRecordBody asserts a single TLS record whose
// declared body length exceeds the RFC 8446 16384-byte record-body limit is
// rejected per-record, independent of the aggregate maxBytes cap.
func TestReadRecordRejectsOversizedRecordBody(t *testing.T) {
	oversized := uint16(maxTLSRecordBody + 1)
	hdr := []byte{0x16, 0x03, 0x03, byte(oversized >> 8), byte(oversized)}
	var prefix []byte
	_, err := readRecord(bytes.NewReader(hdr), 1<<20, &prefix)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

// TestReadRecordRejectsZeroLengthRecord asserts a TLS record whose declared
// body length is zero is rejected as a malformed/empty record (ErrShortHello),
// not misclassified as an oversized record (ErrTooLarge) — the two sentinels
// let callers distinguish "too big" from "malformed/empty" via errors.Is.
func TestReadRecordRejectsZeroLengthRecord(t *testing.T) {
	hdr := []byte{0x16, 0x03, 0x03, 0x00, 0x00}
	var prefix []byte
	_, err := readRecord(bytes.NewReader(hdr), 1<<20, &prefix)
	if !errors.Is(err, ErrShortHello) {
		t.Fatalf("err = %v, want ErrShortHello", err)
	}
	if errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, must not match ErrTooLarge", err)
	}
}

func TestPeekClientHelloRejectsOversizedHello(t *testing.T) {
	reader := strings.NewReader(string([]byte{0x16, 0x03, 0x03, 0x10, 0x01}))
	_, err := PeekClientHello(readDeadlineConn{Reader: reader}, 64, time.Second)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

type readDeadlineConn struct {
	io.Reader
}

func (readDeadlineConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (readDeadlineConn) Close() error                     { return nil }
func (readDeadlineConn) LocalAddr() net.Addr              { return nil }
func (readDeadlineConn) RemoteAddr() net.Addr             { return nil }
func (readDeadlineConn) SetDeadline(time.Time) error      { return nil }
func (readDeadlineConn) SetReadDeadline(time.Time) error  { return nil }
func (readDeadlineConn) SetWriteDeadline(time.Time) error { return nil }
