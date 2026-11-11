package sni

import (
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"testing"
)

func FuzzParseClientHelloRecord(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x00})
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01})
	f.Add(fuzzClientHelloSeed())

	f.Fuzz(func(t *testing.T, record []byte) {
		name, err := parseClientHelloRecord(record)
		if err != nil {
			return
		}
		if name == "" {
			t.Fatal("successful parse returned empty server name")
		}
		if name != strings.ToLower(name) {
			t.Fatalf("server name was not normalized: %q", name)
		}
		if strings.ContainsRune(name, 0) {
			t.Fatalf("server name contains NUL: %q", name)
		}
	})
}

func fuzzClientHelloSeed() []byte {
	client, server := net.Pipe()
	defer client.Close() //nolint:errcheck // fuzz connection cleanup.
	defer server.Close() //nolint:errcheck // fuzz connection cleanup.

	errc := make(chan error, 1)
	go func() {
		tlsClient := tls.Client(client, &tls.Config{
			ServerName:         "Home.Relay.Example",
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		})
		errc <- tlsClient.Handshake()
	}()

	var prefix []byte
	body, err := readRecord(server, 64*1024, &prefix)
	_ = client.Close()
	<-errc //nolint:errcheck // the handshake is cut short on purpose; only its exit matters.
	if err != nil {
		panic(err)
	}
	// readRecord returns the record body only and appends the full record
	// (5-byte header + body) to prefix. parseClientHelloRecord expects a full
	// record, so seed the fuzzer with prefix; sanity-check it ends with body.
	if !bytes.Equal(prefix[5:], body) {
		panic("record/prefix mismatch")
	}
	return prefix
}
