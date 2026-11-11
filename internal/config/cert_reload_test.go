package config

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCertReloadMtimeChangeServesNewCertificate(t *testing.T) {
	certFile, keyFile := certReloadWritePair(t, 1)
	reloader, err := NewCertificateReloader(certFile, keyFile, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewCertificateReloader: %v", err)
	}
	if got := certReloadHandshakeSerial(t, reloader.GetCertificate); got != 1 {
		t.Fatalf("initial handshake serial = %d, want 1", got)
	}

	certReloadReplacePair(t, certFile, keyFile, 2, time.Now().Add(time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go reloader.Watch(ctx, 5*time.Millisecond, nil)
	certReloadWaitForSerial(t, reloader, 2)

	if got := certReloadHandshakeSerial(t, reloader.GetCertificate); got != 2 {
		t.Fatalf("handshake after mtime reload serial = %d, want 2", got)
	}
}

func TestCertReloadSIGHUPServesNewCertificate(t *testing.T) {
	certFile, keyFile := certReloadWritePair(t, 11)
	reloader, err := NewCertificateReloader(certFile, keyFile, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewCertificateReloader: %v", err)
	}
	certInfo, err := os.Stat(certFile)
	if err != nil {
		t.Fatalf("stat certificate: %v", err)
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	certReloadReplacePair(t, certFile, keyFile, 12, certInfo.ModTime())
	if err := os.Chtimes(keyFile, keyInfo.ModTime(), keyInfo.ModTime()); err != nil {
		t.Fatalf("preserve key mtime: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	signals := make(chan os.Signal, 1)
	go reloader.Watch(ctx, time.Hour, signals)
	signals <- syscall.SIGHUP
	certReloadWaitForSerial(t, reloader, 12)

	if got := certReloadHandshakeSerial(t, reloader.GetCertificate); got != 12 {
		t.Fatalf("handshake after SIGHUP reload serial = %d, want 12", got)
	}
}

func TestCertReloadCorruptReplacementKeepsLastGoodAndWarns(t *testing.T) {
	certFile, keyFile := certReloadWritePair(t, 21)
	var logs bytes.Buffer
	reloader, err := NewCertificateReloader(certFile, keyFile, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("NewCertificateReloader: %v", err)
	}
	if err := os.WriteFile(certFile, []byte("corrupt certificate"), 0o600); err != nil {
		t.Fatalf("replace certificate: %v", err)
	}
	changed := time.Now().Add(time.Second)
	if err := os.Chtimes(certFile, changed, changed); err != nil {
		t.Fatalf("change certificate mtime: %v", err)
	}

	reloaded, err := reloader.ReloadIfChanged("mtime poll")
	if err == nil {
		t.Fatal("corrupt replacement reload succeeded")
	}
	if reloaded {
		t.Fatal("corrupt replacement reported a successful reload")
	}
	if got := certReloadHandshakeSerial(t, reloader.GetCertificate); got != 21 {
		t.Fatalf("handshake after corrupt replacement serial = %d, want last-good 21", got)
	}
	gotLogs := logs.String()
	if !strings.Contains(gotLogs, `"level":"WARN"`) {
		t.Fatalf("reload failure log missing Warn level: %s", gotLogs)
	}
	if !strings.Contains(gotLogs, "carrier TLS certificate reload failed") {
		t.Fatalf("reload failure log missing outcome: %s", gotLogs)
	}
}

func certReloadWaitForSerial(t *testing.T, reloader *CertificateReloader, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cert, err := reloader.GetCertificate(nil)
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("parse active certificate: %v", err)
		}
		if leaf.SerialNumber.Int64() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active certificate did not reach serial %d", want)
}

func certReloadHandshakeSerial(t *testing.T, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) int64 {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	serverTLS := tls.Server(serverConn, &tls.Config{
		GetCertificate: getCertificate,
		MinVersion:     tls.VersionTLS13,
	})
	clientTLS := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Generated, isolated test certificate.
		MinVersion:         tls.VersionTLS13,
	})
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- serverTLS.Handshake()
	}()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	state := clientTLS.ConnectionState()
	clientConn.Close() //nolint:errcheck // In-memory test connection cleanup.
	serverConn.Close() //nolint:errcheck // In-memory test connection cleanup.
	if len(state.PeerCertificates) != 1 {
		t.Fatalf("peer certificate count = %d, want 1", len(state.PeerCertificates))
	}
	return state.PeerCertificates[0].SerialNumber.Int64()
}

func certReloadWritePair(t *testing.T, serial int64) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "carrier.crt")
	keyFile := filepath.Join(dir, "carrier.key")
	certReloadReplacePair(t, certFile, keyFile, serial, time.Now())
	return certFile, keyFile
}

func certReloadReplacePair(t *testing.T, certFile, keyFile string, serial int64, modTime time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "carrier.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"carrier.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.Chtimes(certFile, modTime, modTime); err != nil {
		t.Fatalf("set certificate mtime: %v", err)
	}
	if err := os.Chtimes(keyFile, modTime, modTime); err != nil {
		t.Fatalf("set key mtime: %v", err)
	}
}
