package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestCopyWithLimitEnforcesByteRate(t *testing.T) {
	limiter := newByteLimiter(512, 512)
	start := time.Now()
	n, err := copyWithLimit(context.Background(), io.Discard, bytes.NewReader(bytes.Repeat([]byte{'x'}, 1024)), limiter, nil, nil)
	if err != nil {
		t.Fatalf("copy with limit: %v", err)
	}
	if n != 1024 {
		t.Fatalf("copied = %d, want 1024", n)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("rate limit elapsed = %s, want at least 900ms", elapsed)
	}
}

// Throughput must stay bounded near the configured rate (no exceeding it) while the
// out-of-tokens path coalesces into proportional sleeps rather than spinning on
// sub-timer-resolution waits. We bound both sides: at least ~rate-worth of time must
// elapse (correctness), and it must not overshoot wildly (the coalesced sleep keeps
// the deadline tight, not a per-token spin).
func TestCopyWithLimitBoundsThroughputNearRate(t *testing.T) {
	const rate = 1 << 20  // 1 MiB/s
	const total = 2 << 20 // 2 MiB => ~1s of accrual beyond the initial burst
	limiter := newByteLimiter(rate, rate)
	start := time.Now()
	n, err := copyWithLimit(context.Background(), io.Discard, bytes.NewReader(bytes.Repeat([]byte{'x'}, total)), limiter, nil, nil)
	if err != nil {
		t.Fatalf("copy with limit: %v", err)
	}
	if n != total {
		t.Fatalf("copied = %d, want %d", n, total)
	}
	elapsed := time.Since(start)
	// One burst (rate) is free; the remaining (total-rate) must be paced at rate.
	minWant := time.Duration(float64(total-rate) / float64(rate) * float64(time.Second))
	if elapsed < minWant {
		t.Fatalf("elapsed = %s, want at least %s (throughput exceeded the rate)", elapsed, minWant)
	}
	// Coalesced sleeps keep us close to the target; a runaway spin or unbounded sleep
	// would blow well past this generous ceiling.
	if elapsed > 5*time.Second {
		t.Fatalf("elapsed = %s, want under 5s (paced sleep should be tight, not a spin/overshoot)", elapsed)
	}
}

// Pins the no-spin floor. The proportional wait for a 1-byte deficit at this rate is
// 1/rate s = 1ms, below the minSleep floor; the old code slept exactly that
// time.Second/rate, busy-cycling the byte path on sub-resolution waits. The floor must
// coalesce it into one real ~minSleep sleep. A regression dropping the floor would
// return in ~1ms (or, at the old higher rates, near-zero), well under the floor.
// Rate is low enough that the few microseconds elapsed before the deficit branch
// accrue <1 token, so the out-of-tokens path is taken deterministically.
func TestWaitFloorsSubResolutionSleeps(t *testing.T) {
	const rate = 1000 // 1 KB/s => proportional wait for 1 byte = 1ms < minSleep (5ms)
	limiter := newByteLimiter(rate, rate)
	// Force the out-of-tokens path deterministically: no tokens, last = now.
	limiter.mu.Lock()
	limiter.tokens = 0
	limiter.last = time.Now()
	limiter.mu.Unlock()

	start := time.Now()
	limiter.Wait(context.Background(), 1)
	elapsed := time.Since(start)

	// Must be a real floored sleep, not the ~1ms unfloored proportional wait or a spin.
	// Allow modest scheduler slop below the nominal floor.
	if elapsed < minSleep-time.Millisecond {
		t.Fatalf("out-of-tokens Wait returned in %s, want >= ~%s (floor not applied; byte path would spin/sleep sub-resolution)", elapsed, minSleep)
	}
}

// TestWaitAtLowRateEventuallyAccruesFractionalTokens guards the accrual branch's
// invariant: l.last must only advance when a whole token was actually credited.
// Advancing it on a zero-gain wake (the old code did this unconditionally)
// discards fractional progress for that tick; if a future caller ever drives
// Wait from a cadence other than the internal deficit-sleep (e.g. very frequent
// small requests), zero-gain wakes become possible and would permanently starve
// accrual. This pins a low, sub-200 B/s rate — where a single minSleep tick
// alone would only earn a fraction of a token — and asserts Wait still resolves
// well within a generous deadline rather than relying on unbounded catch-up.
func TestWaitAtLowRateEventuallyAccruesFractionalTokens(t *testing.T) {
	const rate = 50 // 50 B/s: a single minSleep (5ms) tick alone would earn 0.25 tokens.
	limiter := newByteLimiter(rate, rate)
	limiter.mu.Lock()
	limiter.tokens = 0
	limiter.last = time.Now()
	limiter.mu.Unlock()

	done := make(chan struct{})
	go func() {
		limiter.Wait(context.Background(), 1)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return within 5s; fractional token accrual is livelocked")
	}
}

// TestWaitUnblocksPromptlyOnContextCancel pins the shutdown-grace contract for
// rate-limited splices: a Wait parked on a long out-of-tokens sleep must wake
// as soon as ctx is cancelled (connection close/server shutdown), not wait out
// the full proportional sleep. Before threading ctx through to ctxSleep, Wait
// used time.Sleep directly and could not be woken early, holding the splice
// goroutine open past ShutdownGrace.
func TestWaitUnblocksPromptlyOnContextCancel(t *testing.T) {
	const rate = 100 // 100 B/s => waiting out a large deficit would take seconds
	limiter := newByteLimiter(rate, rate)
	// Drain tokens and force the out-of-tokens sleep path deterministically.
	limiter.mu.Lock()
	limiter.tokens = 0
	limiter.last = time.Now()
	limiter.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	limiter.Wait(ctx, rate*5) // deficit alone would sleep ~5s uninterrupted
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Fatalf("Wait took %s to return after ctx cancel, want prompt return (shutdown grace violated)", elapsed)
	}
}

// fakeAddr is a minimal net.Addr for throttle tests.
type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// TestHandshakeThrottleBacksOffAfterThreshold proves the failed-handshake
// throttle is silent under the free-failure threshold and imposes a growing,
// capped backoff above it, keyed per source IP. A no-op injectable sleeper makes
// the assertion deterministic instead of timing-based.
func TestHandshakeThrottleBacksOffAfterThreshold(t *testing.T) {
	h := newHandshakeThrottle()
	var slept []time.Duration
	h.sleep = func(_ context.Context, d time.Duration) { slept = append(slept, d) }

	src := fakeAddr("203.0.113.7:5555")
	ctx := context.Background()

	// Record up to the free-failure threshold, checking backoff before each: no
	// backoff while at or under the threshold (excess <= 0).
	for i := 0; i < handshakeFreeFailures; i++ {
		h.backoffBefore(ctx, src)
		h.recordFailure(src)
	}
	// failures == handshakeFreeFailures now: still excess 0, no backoff yet.
	h.backoffBefore(ctx, src)
	if len(slept) != 0 {
		t.Fatalf("backoff applied at/under threshold: %v", slept)
	}

	// Each further failure pushes excess up: backoff is base << (excess-1).
	h.recordFailure(src) // failures = free+1 -> excess 1
	h.backoffBefore(ctx, src)
	h.recordFailure(src) // failures = free+2 -> excess 2
	h.backoffBefore(ctx, src)
	if len(slept) != 2 {
		t.Fatalf("expected 2 backoff sleeps, got %d: %v", len(slept), slept)
	}
	if slept[0] != handshakeBackoffBase {
		t.Fatalf("first backoff = %s, want %s", slept[0], handshakeBackoffBase)
	}
	if slept[1] != 2*handshakeBackoffBase {
		t.Fatalf("second backoff = %s, want %s", slept[1], 2*handshakeBackoffBase)
	}
}

// TestHandshakeThrottleCapsBackoff proves backoff never exceeds the cap.
func TestHandshakeThrottleCapsBackoff(t *testing.T) {
	h := newHandshakeThrottle()
	var last time.Duration
	h.sleep = func(_ context.Context, d time.Duration) { last = d }
	src := fakeAddr("198.51.100.4:1")
	for i := 0; i < handshakeFreeFailures+40; i++ {
		h.recordFailure(src)
	}
	h.backoffBefore(context.Background(), src)
	if last != handshakeBackoffMax {
		t.Fatalf("backoff = %s, want cap %s", last, handshakeBackoffMax)
	}
}

// TestHandshakeThrottleSuccessClearsAndSeparateSources proves a successful
// handshake clears the source's penalty and that distinct source IPs are
// throttled independently.
func TestHandshakeThrottleSuccessClearsAndSeparateSources(t *testing.T) {
	h := newHandshakeThrottle()
	h.sleep = func(context.Context, time.Duration) {}
	a := fakeAddr("203.0.113.1:9")
	b := fakeAddr("203.0.113.2:9")

	for i := 0; i < handshakeFreeFailures+2; i++ {
		h.recordFailure(a)
	}
	if h.FailureCount(a) != handshakeFreeFailures+2 {
		t.Fatalf("source a failures = %d", h.FailureCount(a))
	}
	if h.FailureCount(b) != 0 {
		t.Fatalf("source b should be untouched, got %d", h.FailureCount(b))
	}
	h.recordSuccess(a)
	if h.FailureCount(a) != 0 {
		t.Fatalf("success did not clear source a: %d", h.FailureCount(a))
	}
}

// TestHandshakeThrottleIPv6Prefix proves two addresses in one /64 share the
// handshake-failure budget while a neighboring /64 remains independent.
func TestHandshakeThrottleIPv6Prefix(t *testing.T) {
	h := newHandshakeThrottle()
	a := fakeAddr("[2001:db8:1:2::1]:9")
	b := fakeAddr("[2001:db8:1:2::ffff]:10")
	c := fakeAddr("[2001:db8:1:3::1]:11")

	h.recordFailure(a)
	if h.FailureCount(b) != 1 {
		t.Fatalf("same /64 failure count = %d, want 1", h.FailureCount(b))
	}
	if h.FailureCount(c) != 0 {
		t.Fatalf("neighboring /64 failure count = %d, want 0", h.FailureCount(c))
	}
}

// TestHandshakeThrottlePrunesIdleEntries proves idle entries are evicted so the
// map cannot grow without bound under a churn of attacker source IPs.
func TestHandshakeThrottlePrunesIdleEntries(t *testing.T) {
	h := newHandshakeThrottle()
	now := time.Now()
	h.now = func() time.Time { return now }
	old := fakeAddr("192.0.2.9:1")
	h.recordFailure(old)

	// Advance past the TTL and trigger a prune via backoffBefore on a fresh source.
	now = now.Add(handshakeEntryTTL + time.Minute)
	h.backoffBefore(context.Background(), fakeAddr("192.0.2.10:1"))
	if h.FailureCount(old) != 0 {
		t.Fatalf("idle entry not pruned: %d", h.FailureCount(old))
	}
}

// TestCtxSleepHonorsCancellation proves a backoff sleep returns promptly when
// the context is cancelled, keeping shutdown prompt mid-backoff.
func TestCtxSleepHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	ctxSleep(ctx, time.Hour)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("ctxSleep ignored cancellation: slept %s", elapsed)
	}
}

// CORE-1407: a refused fair-use reservation stops the copy before the chunk
// reaches the destination, and every admitted chunk is settled with the bytes
// actually written.
func TestCopyWithLimitReservesBeforeWriting(t *testing.T) {
	var dst bytes.Buffer
	admitted := 0
	var settled []int64
	n, err := copyWithLimit(context.Background(), &dst, bytes.NewReader(bytes.Repeat([]byte{'x'}, 3*int(fairUseCopyChunkMax))), nil,
		func(n int64) bool {
			if admitted == 2 {
				return false
			}
			admitted++
			return true
		},
		func(reserved, written int64) {
			if reserved != written {
				t.Errorf("settled reserved=%d written=%d, want a full write", reserved, written)
			}
			settled = append(settled, written)
		})
	if !errors.Is(err, errFairUseBound) {
		t.Fatalf("copy error = %v, want errFairUseBound", err)
	}
	if want := 2 * fairUseCopyChunkMax; n != want || int64(dst.Len()) != want {
		t.Fatalf("copied %d (dst %d), want only the %d admitted bytes", n, dst.Len(), want)
	}
	if len(settled) != 2 {
		t.Fatalf("settled %d chunks, want 2", len(settled))
	}
}

// shortWriter accepts at most limit bytes per call and then returns err.
type shortWriter struct {
	limit int
	err   error
	got   int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	n := min(len(p), w.limit)
	w.got += n
	return n, w.err
}

// CORE-1407: a chunk the destination only partly accepts, or rejects, still
// releases its whole reservation and records only the bytes actually written.
func TestCopyWithLimitSettlesShortAndFailedWrites(t *testing.T) {
	cases := []struct {
		name    string
		limit   int
		err     error
		wantErr error
	}{
		{"partial write with error", 1000, errors.New("peer reset"), nil},
		{"zero-byte failure", 0, errors.New("peer reset"), nil},
		{"short write without error", 1000, nil, io.ErrShortWrite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &countingFairUseStore{}
			store.healthy.Store(true)
			limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
			limiter.store = store
			defer limiter.close()
			c := &carrier{id: "opaque-server", fairUse: limiter, usage: limiter.tunnel("opaque-server")}
			dst := &shortWriter{limit: tc.limit, err: tc.err}

			n, err := copyWithLimit(context.Background(), dst, bytes.NewReader(bytes.Repeat([]byte{'x'}, int(fairUseCopyChunkMax))), nil,
				c.reserveBytes, func(reserved, written int64) { c.settleBytes(reserved, written) })
			want := tc.err
			if want == nil {
				want = tc.wantErr
			}
			if !errors.Is(err, want) {
				t.Fatalf("copy error = %v, want %v", err, want)
			}
			if n != int64(dst.got) {
				t.Fatalf("copy reported %d bytes, destination accepted %d", n, dst.got)
			}
			// The flush worker may already have committed the bytes; flushMu is
			// held across a commit, so pending, retry and committed bytes read
			// under it are a consistent split of everything accounted.
			c.usage.flushMu.Lock()
			c.usage.mu.Lock()
			inflight := c.usage.inflight
			accounted := c.usage.pending + c.usage.retryBytes + store.addedBytes.Load()
			c.usage.mu.Unlock()
			c.usage.flushMu.Unlock()
			if inflight != 0 {
				t.Fatalf("in-flight reservation leaked: %d bytes", inflight)
			}
			if accounted != int64(dst.got) {
				t.Fatalf("accounted %d bytes, want the %d actually written", accounted, dst.got)
			}
			if got := c.bytesRelayed.Load(); got != int64(dst.got) {
				t.Fatalf("carrier bytesRelayed = %d, want %d", got, dst.got)
			}
		})
	}
}
