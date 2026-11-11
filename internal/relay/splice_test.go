package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// blockingConn is a net.Conn whose Read blocks until Close is called, modelling a
// peer that is open but silent (e.g. an upstream that has gone quiet). Once
// closed, Read returns net.ErrClosed so a copy parked on it unwinds. Write is a
// no-op sink. The other net.Conn methods are unused by splice and panic if hit.
type blockingConn struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newBlockingConn() *blockingConn {
	return &blockingConn{closed: make(chan struct{})}
}

func (c *blockingConn) Read(p []byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *blockingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingConn) LocalAddr() net.Addr              { panic("unused") }
func (c *blockingConn) RemoteAddr() net.Addr             { panic("unused") }
func (c *blockingConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingConn) SetWriteDeadline(time.Time) error { return nil }

// erroringConn is a net.Conn whose Read returns an error immediately, modelling a
// peer that has disconnected abruptly (a reset/error, not a graceful EOF). Write
// is a no-op sink. Close is recorded so the test can assert the splice tore this
// half down too.
type erroringConn struct {
	mu     sync.Mutex
	closed bool
}

func (c *erroringConn) Read(p []byte) (int, error)  { return 0, errors.New("connection reset by peer") }
func (c *erroringConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *erroringConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *erroringConn) wasClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *erroringConn) LocalAddr() net.Addr              { panic("unused") }
func (c *erroringConn) RemoteAddr() net.Addr             { panic("unused") }
func (c *erroringConn) SetDeadline(time.Time) error      { return nil }
func (c *erroringConn) SetReadDeadline(time.Time) error  { return nil }
func (c *erroringConn) SetWriteDeadline(time.Time) error { return nil }

// TestSpliceTearsDownBothHalvesOnAbruptDisconnect pins the connection-plane
// invariant that when one direction of the byte-blind pipe ends with an error (a
// peer disconnected abruptly), the OTHER direction — which may be parked reading
// a silent-but-open peer — is torn down too, so the public handler returns
// instead of leaking a goroutine, fd, stream-cap slot, and public-conn semaphore
// slot.
//
// Setup: the client side reads with an immediate error (abrupt disconnect); the
// upstream side is open but silent (Read blocks until Close). With the fix, the
// client-side error makes splice force-close both conns, which unblocks the
// parked upstream read and lets splice return. Without the fix, splice blocks
// forever on the second direction and this test times out. The deterministic
// fakes avoid the FIN-vs-RST OS race that makes a socket-level reproduction flaky.
func TestSpliceTearsDownBothHalvesOnAbruptDisconnect(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c := &carrier{} // no limiter, no fair-use: recordBytes/copyWithLimit handle nil

	upstream := newBlockingConn()
	client := &erroringConn{}

	// clientReader mirrors handlePublicConn: the client conn is the read source for
	// the client->upstream direction. Here it errors immediately (abrupt).
	clientReader := io.Reader(client)

	returned := make(chan struct{})
	go func() {
		s.splice(context.Background(), c, upstream, client, clientReader)
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("splice did not return after an abrupt disconnect: the surviving direction was not torn down (goroutine/fd leak)")
	}

	// Both halves must have been torn down. The blocking upstream only unblocks via
	// Close, so splice returning at all proves upstream was closed; assert the
	// client side was closed too.
	if !client.wasClosed() {
		t.Fatal("splice returned but did not close the client conn (half-teardown)")
	}
}

// TestSpliceRateLimitedCopyUnblocksOnContextCancel pins the ShutdownGrace
// contract end-to-end through splice: when byte rate-limiting is enabled and a
// splice goroutine is parked inside the limiter's out-of-tokens sleep,
// cancelling the ctx passed into splice (as handlePublicConn does on shutdown
// or connection teardown) must wake it promptly instead of waiting out the
// full proportional sleep. Before threading ctx through splice/copyWithLimit/
// Wait, this ctx was never reached and the goroutine could only be woken by
// closing the underlying conns, not by shutdown context cancellation alone.
func TestSpliceRateLimitedCopyUnblocksOnContextCancel(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	// A very low rate with no accrued tokens forces the client->upstream copy
	// into the out-of-tokens sleep on its first byte.
	c := &carrier{limiter: newByteLimiter(1, 1)}
	c.limiter.mu.Lock()
	c.limiter.tokens = 0
	c.limiter.last = time.Now()
	c.limiter.mu.Unlock()

	clientReader := bytes.NewReader(bytes.Repeat([]byte{'x'}, 1<<20)) // large deficit
	upstream := &capturingConn{}
	client := &capturingConn{readErr: io.EOF}

	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan struct{})
	go func() {
		s.splice(ctx, c, upstream, client, clientReader)
		close(returned)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("splice did not return promptly after ctx cancel: rate-limited Wait ignored shutdown context")
	}
}

// TestSpliceWaitsForBothHalvesOnCleanHalfClose pins the opposing requirement: a
// graceful half-close (clean EOF) on one direction must NOT tear down the live
// other direction. The client->upstream direction hits a clean EOF while the
// upstream->client direction is still flowing; splice must keep waiting (not
// return) until the second direction also completes. This guards the
// half-close-download/upload feature against an over-eager teardown.
func TestSpliceWaitsForBothHalvesOnCleanHalfClose(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c := &carrier{}

	// Client side: a reader that returns clean EOF immediately (write-half-close).
	clientReader := io.Reader(eofReader{})
	// Client write sink (the half-close CloseWrite target is the *net.Conn*; a plain
	// sink without CloseWrite is fine — the branch is a no-op then).
	client := &blockingConn{closed: make(chan struct{})}

	// Upstream: still flowing. Gate its EOF so we can observe that splice is still
	// waiting after the clean half-close.
	upstream := newGatedConn()

	returned := make(chan struct{})
	go func() {
		s.splice(context.Background(), c, upstream, client, clientReader)
		close(returned)
	}()

	// The client->upstream copy hits EOF immediately, but the upstream->client copy
	// is still live, so splice must NOT have returned yet.
	select {
	case <-returned:
		t.Fatal("splice returned on a clean half-close while the other direction was still live (would truncate the download)")
	case <-time.After(150 * time.Millisecond):
		// Good: still waiting for the live direction.
	}

	// Now let the upstream finish cleanly; splice should return promptly.
	upstream.finish()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("splice did not return after the live direction completed")
	}
}

// eofReader returns clean EOF on first Read (a graceful write-half-close).
type eofReader struct{}

func (eofReader) Read(p []byte) (int, error) { return 0, io.EOF }

// gatedConn is a net.Conn whose Read blocks until finish() is called, then
// returns clean EOF (modelling an upstream that keeps flowing then closes
// gracefully). Write is a no-op sink.
type gatedConn struct {
	once sync.Once
	gate chan struct{}
}

func newGatedConn() *gatedConn { return &gatedConn{gate: make(chan struct{})} }

func (c *gatedConn) finish() { c.once.Do(func() { close(c.gate) }) }

func (c *gatedConn) Read(p []byte) (int, error) {
	<-c.gate
	return 0, io.EOF
}

func (c *gatedConn) Write(p []byte) (int, error)     { return len(p), nil }
func (c *gatedConn) Close() error                    { return nil }
func (c *gatedConn) LocalAddr() net.Addr             { panic("unused") }
func (c *gatedConn) RemoteAddr() net.Addr            { panic("unused") }
func (c *gatedConn) SetDeadline(time.Time) error     { return nil }
func (c *gatedConn) SetReadDeadline(time.Time) error { return nil }
func (c *gatedConn) SetWriteDeadline(time.Time) error {
	return nil
}

// TestSpliceReplaysSNIPrefixBeforeRemainingClientBytes (audit F13) pins the
// SNI-replay ordering: the bytes peeked off the wire while parsing the
// ClientHello (sni.Result.Prefix) MUST be replayed to the upstream verbatim and
// in order, ahead of the remaining client bytes. handlePublicConn builds the
// client read source as io.MultiReader(bytesReader(result.Prefix), conn); this
// test exercises that exact construction through splice and asserts the upstream
// receives prefix-then-remainder with no reordering, duplication, or loss. A
// regression that dropped the prefix, sent it after the body, or replayed it
// twice would corrupt the relayed TLS handshake and is otherwise only covered
// implicitly by the end-to-end TLS test.
func TestSpliceReplaysSNIPrefixBeforeRemainingClientBytes(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c := &carrier{}

	// prefix models the verbatim handshake-record bytes peeked for SNI; remainder
	// models the post-ClientHello client bytes still buffered on the conn.
	prefix := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 'H', 'E', 'L', 'L', 'O'}
	remainder := []byte("APPLICATION-BYTES-AFTER-HANDSHAKE")
	want := append(append([]byte(nil), prefix...), remainder...)

	// clientReader is constructed exactly as handlePublicConn does: the peeked
	// prefix replayed first, then the live client conn.
	clientConn := &readerConn{r: bytes.NewReader(remainder)}
	clientReader := io.MultiReader(bytesReader(prefix), clientConn)

	upstream := &capturingConn{}
	// The upstream->client direction must complete so splice returns; an immediate
	// clean EOF on that side models an upstream that sends nothing back.
	client := &capturingConn{readErr: io.EOF}

	returned := make(chan struct{})
	go func() {
		s.splice(context.Background(), c, upstream, client, clientReader)
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("splice did not return")
	}

	got := upstream.written()
	if !bytes.Equal(got, want) {
		t.Fatalf("upstream received %q, want SNI prefix replayed before remaining client bytes: %q", got, want)
	}
}

// readerConn adapts an io.Reader into a net.Conn whose Read drains the reader
// then returns clean EOF. Write is a no-op sink; the other methods are unused.
type readerConn struct{ r io.Reader }

func (c *readerConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *readerConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *readerConn) Close() error                     { return nil }
func (c *readerConn) LocalAddr() net.Addr              { panic("unused") }
func (c *readerConn) RemoteAddr() net.Addr             { panic("unused") }
func (c *readerConn) SetDeadline(time.Time) error      { return nil }
func (c *readerConn) SetReadDeadline(time.Time) error  { return nil }
func (c *readerConn) SetWriteDeadline(time.Time) error { return nil }

// capturingConn records everything written to it (so a test can assert the exact
// byte stream and its order) and returns readErr on Read. Writes are guarded so
// the splice's two copy goroutines stay race-clean under -race.
type capturingConn struct {
	mu      sync.Mutex
	buf     []byte
	readErr error
}

func (c *capturingConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return 0, io.EOF
}

func (c *capturingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p...)
	return len(p), nil
}

func (c *capturingConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

func (c *capturingConn) Close() error                     { return nil }
func (c *capturingConn) LocalAddr() net.Addr              { panic("unused") }
func (c *capturingConn) RemoteAddr() net.Addr             { panic("unused") }
func (c *capturingConn) SetDeadline(time.Time) error      { return nil }
func (c *capturingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *capturingConn) SetWriteDeadline(time.Time) error { return nil }
