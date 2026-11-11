package relay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestCarrierBackoffDoesNotOccupyCarrierSlot (SECREV-RELAY-8-T) is the
// end-to-end behavioral regression test for SECREV-RELAY-8: the per-source
// handshake backoff must run BEFORE a carrier slot is reserved, so a
// repeat-offender bad-token flood sitting in backoff cannot pin the scarce
// carrierSlots semaphore and starve legitimate carriers.
//
// The regression it guards: before SECREV-RELAY-8, acceptCarriers reserved a
// carrier slot and only then ran backoffBefore (from inside carrierHandshake),
// so a backing-off connection held its slot for the whole backoff sleep (up to
// handshakeBackoffMax). limiter_test.go covers backoffBefore in isolation and
// the accept path's slot bookkeeping is not exercised there; this test pins the
// slot-vs-backoff interaction end-to-end through a real carrier connection.
//
// Mechanism: MaxCarrierConns=1 (a single, maximally-sensitive slot). We preload
// one source past handshakeFreeFailures so its next connection incurs a real
// backoff, and we replace the throttle's sleeper with a barrier that signals the
// moment a backoff begins and blocks until the test releases it. We then drive a
// bad-token connection from that source; when it is provably parked in backoff,
// we assert the carrierSlots semaphore is EMPTY (len 0) and that the single slot
// is still acquirable -- exactly the "a legitimate carrier can still acquire a
// slot while the attacker is in backoff" guarantee. Under the regression the
// slot would be held (len 1) for the whole backoff and this acquire would block.
func TestCarrierBackoffDoesNotOccupyCarrierSlot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := startBackoffTestRelay(t, ctx)

	// A backoff barrier: backoffEntered fires when a connection enters the sleep,
	// and the sleep blocks on releaseBackoff so the connection stays parked in
	// backoff (holding no slot, under the fix) for as long as the test needs.
	backoffEntered := make(chan struct{}, 1)
	releaseBackoff := make(chan struct{})
	s.handshakeThrottle.sleep = func(ctx context.Context, _ time.Duration) {
		select {
		case backoffEntered <- struct{}{}:
		default:
		}
		select {
		case <-releaseBackoff:
		case <-ctx.Done():
		}
	}

	// Preload the loopback source (127.0.0.1) past the free-failure threshold so
	// its next handshake incurs a backoff before the slot reservation. The real
	// connection below dials from 127.0.0.1, so it shares this throttle bucket.
	src := fakeAddr("127.0.0.1:0")
	for i := 0; i < handshakeFreeFailures+1; i++ {
		s.handshakeThrottle.recordFailure(src)
	}

	// Drive a repeat-offender carrier connection. The accept goroutine runs
	// backoffBefore (which parks on the barrier) BEFORE the TLS handshake and
	// before reserving a slot, so a raw TCP connect is enough to reach backoff --
	// no completed handshake is needed, and completing one would deadlock here
	// (the server's lazy TLS handshake only runs after backoff, on the first
	// frame read). We must not occupy a carrierSlot while parked.
	addr := s.carrierListener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial carrier: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test connection cleanup.

	// Wait until the connection is provably parked in backoff.
	select {
	case <-backoffEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("connection never entered handshake backoff")
	}

	// The invariant under test: while a repeat-offender connection is in backoff,
	// the carrier slot semaphore is NOT occupied by it.
	if occupied := len(s.carrierSlots); occupied != 0 {
		t.Fatalf("carrierSlots occupied = %d during backoff, want 0: the backoff-sleep is holding a carrier slot (SECREV-RELAY-8 regression)", occupied)
	}

	// And the concrete consequence: the single slot is still acquirable, so a
	// legitimate carrier is not starved by the backing-off attacker. Under the
	// regression the slot would already be taken and this would block.
	select {
	case s.carrierSlots <- struct{}{}:
		<-s.carrierSlots // release immediately; we only needed to prove availability.
	default:
		t.Fatal("carrier slot unavailable during attacker backoff: a legitimate carrier would be starved (SECREV-RELAY-8 regression)")
	}

	// Release the parked connection so its accept goroutine unwinds (it then
	// reserves the slot, runs the handshake, and releases). t.Cleanup closes the
	// server, and ctx cancel keeps any still-parked sleep from lingering.
	close(releaseBackoff)
}

// TestCarrierBackoffAdmissionCapBoundsPreSlotHandlers proves a throttled-source
// flood cannot accumulate connections and goroutines while the handlers sleep
// before reserving carrier slots. With a one-entry admission budget, the first
// connection parks in backoff and the next accepted connection is closed
// promptly, while the carrier slot remains free (SECREV-RELAY-8).
func TestCarrierBackoffAdmissionCapBoundsPreSlotHandlers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := startBackoffTestRelay(t, ctx)
	backoffEntered := make(chan struct{}, 1)
	releaseBackoff := make(chan struct{})
	s.handshakeThrottle.sleep = func(ctx context.Context, _ time.Duration) {
		select {
		case backoffEntered <- struct{}{}:
		default:
		}
		select {
		case <-releaseBackoff:
		case <-ctx.Done():
		}
	}

	src := fakeAddr("127.0.0.1:0")
	for i := 0; i < handshakeFreeFailures+1; i++ {
		s.handshakeThrottle.recordFailure(src)
	}

	first, err := net.Dial("tcp", s.carrierListener.Addr().String())
	if err != nil {
		t.Fatalf("dial first carrier: %v", err)
	}
	defer first.Close() //nolint:errcheck // test connection cleanup.

	select {
	case <-backoffEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("first connection never entered handshake backoff")
	}
	if admitted := len(s.carrierAdmissions); admitted != 1 {
		t.Fatalf("carrier admissions = %d during backoff, want 1", admitted)
	}
	if occupied := len(s.carrierSlots); occupied != 0 {
		t.Fatalf("carrier slots = %d during backoff, want 0", occupied)
	}

	second, err := net.Dial("tcp", s.carrierListener.Addr().String())
	if err != nil {
		t.Fatalf("dial over-cap carrier: %v", err)
	}
	defer second.Close() //nolint:errcheck // test connection cleanup.
	if err := second.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set over-cap read deadline: %v", err)
	}
	var b [1]byte
	if _, err := second.Read(b[:]); err == nil {
		t.Fatal("over-cap carrier connection remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("over-cap carrier connection was not closed promptly: %v", err)
	}

	if admitted := len(s.carrierAdmissions); admitted != 1 {
		t.Fatalf("carrier admissions grew past cap: %d", admitted)
	}
	close(releaseBackoff)
}

// TestCloseCancelsBackoffSleep proves Close() unblocks an accept goroutine
// parked in handshakeThrottle.backoffBefore instead of leaving it to sleep out
// up to handshakeBackoffMax after the listeners are closed. Mechanism: replace
// the throttle's sleeper with one that blocks solely on ctx.Done() (never on a
// wall-clock timer or a test-controlled release channel), preload a source past
// the free-failure threshold, drive a connection from it so the accept goroutine
// parks in backoff, then call Close() and assert Wait() returns promptly. This
// is deterministic and cannot hang CI: under the fix Wait() returns as soon as
// forceClose cancels the internal ctx; under the regression the sleeper's
// select has no way to wake (no timer, no release), so Wait() would block
// forever and the test's own deadline fails it well under handshakeBackoffMax.
func TestCloseCancelsBackoffSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := startBackoffTestRelay(t, ctx)

	backoffEntered := make(chan struct{}, 1)
	s.handshakeThrottle.sleep = func(ctx context.Context, _ time.Duration) {
		select {
		case backoffEntered <- struct{}{}:
		default:
		}
		<-ctx.Done()
	}

	src := fakeAddr("127.0.0.1:0")
	for i := 0; i < handshakeFreeFailures+1; i++ {
		s.handshakeThrottle.recordFailure(src)
	}

	addr := s.carrierListener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial carrier: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test connection cleanup.

	select {
	case <-backoffEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("connection never entered handshake backoff")
	}

	// Close the raw, unauthenticated conn so that once backoff is cancelled the
	// post-backoff handshake read fails immediately instead of parking on the
	// unrelated carrierHandshakeT read deadline (a separate, already-bounded
	// timeout not in scope here) -- keeping this test isolated to the backoff
	// sleep cancellation this fix targets.
	_ = conn.Close()

	done := make(chan struct{})
	go func() {
		s.Close()
		s.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait() did not return promptly after Close() during handshake backoff")
	}
}

// startBackoffTestRelay starts an in-package relay with a single carrier slot and
// a static verifier that rejects the test's bad token. Kept local to this file so
// it can reach s.carrierSlots / s.handshakeThrottle directly (the external
// relay_test harness cannot).
func startBackoffTestRelay(t *testing.T, ctx context.Context) *Server {
	t.Helper()
	cert := backoffTestCert(t)
	s, err := Start(ctx, Config{
		PublicAddr:  "127.0.0.1:0",
		CarrierAddr: "127.0.0.1:0",
		CarrierTLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		},
		TokenVerifier: StaticTokenVerifier{
			Token:     []byte("the-real-token"),
			CarrierID: "carrier-1",
			Hostnames: []string{"home.relay.test"},
		},
		MaxCarrierConns: 1,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// backoffTestCert mints a throwaway self-signed cert for the carrier listener.
func backoffTestCert(t *testing.T) tls.Certificate {
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
		Subject:      pkix.Name{CommonName: "relay-carrier.local"},
		DNSNames:     []string{"relay-carrier.local"},
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
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	return cert
}

var _ net.Addr = fakeAddr("")
