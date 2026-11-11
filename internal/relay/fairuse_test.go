package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestFairUseWindowRollsAndEvictsIdleTunnels(t *testing.T) {
	clock := &fakeClock{now: time.Unix(100*int64(time.Hour/time.Second), 0)}
	var logs bytes.Buffer
	limiter := newFairUseLimiter(FairUseConfig{
		Enabled:           true,
		WindowDays:        1,
		SoftLimitBytes:    100,
		HardLimitBytes:    200,
		ThrottledMaxConns: 1,
		Clock:             clock.Now,
	}, slog.New(slog.NewTextHandler(&logs, nil)))
	usage := limiter.tunnel("server-prod-1/client-198.51.100.8")

	usage.add(80)
	if snapshot := limiter.snapshot(); snapshot.windowBytes != 80 {
		t.Fatalf("window bytes after first add = %d, want 80", snapshot.windowBytes)
	}

	clock.Advance(23 * time.Hour)
	usage.add(30)
	snapshot := limiter.snapshot()
	if snapshot.windowBytes != 110 {
		t.Fatalf("window bytes before expiry = %d, want 110", snapshot.windowBytes)
	}
	if snapshot.softTunnels != 1 {
		t.Fatalf("soft tunnels = %d, want 1", snapshot.softTunnels)
	}
	if !strings.Contains(logs.String(), "fair_use_soft_limit_crossed tunnel=tunnel-1") {
		t.Fatalf("soft crossing was not logged once: %s", logs.String())
	}
	if strings.Contains(logs.String(), "server-prod-1") || strings.Contains(logs.String(), "198.51.100.8") {
		t.Fatalf("fair-use log exposed raw server/client identifiers: %s", logs.String())
	}

	clock.Advance(2 * time.Hour)
	snapshot = limiter.snapshot()
	if snapshot.windowBytes != 30 {
		t.Fatalf("window bytes after expiry = %d, want 30", snapshot.windowBytes)
	}
	if snapshot.softTunnels != 0 {
		t.Fatalf("soft tunnels after expiry = %d, want 0", snapshot.softTunnels)
	}

	clock.Advance(25 * time.Hour)
	if snapshot := limiter.snapshot(); snapshot.windowBytes != 0 {
		t.Fatalf("window bytes after idle eviction = %d, want 0", snapshot.windowBytes)
	}
	if got := len(limiter.tunnels); got != 0 {
		t.Fatalf("tracked tunnels after idle eviction = %d, want 0", got)
	}
}

func TestFairUseHardLimitAndSampledRefusalLogs(t *testing.T) {
	clock := &fakeClock{now: time.Unix(200*int64(time.Hour/time.Second), 0)}
	var logs bytes.Buffer
	limiter := newFairUseLimiter(FairUseConfig{
		Enabled:           true,
		WindowDays:        30,
		SoftLimitBytes:    10,
		HardLimitBytes:    20,
		ThrottledMaxConns: 2,
		Clock:             clock.Now,
		LogSampleInterval: time.Minute,
	}, slog.New(slog.NewTextHandler(&logs, nil)))
	usage := limiter.tunnel("server-prod-2/client-203.0.113.9")

	usage.add(25)
	if !usage.hardLimited() {
		t.Fatal("usage should be hard-limited")
	}
	snapshot := limiter.snapshot()
	if snapshot.throttledTunnels != 1 {
		t.Fatalf("throttled tunnels = %d, want 1", snapshot.throttledTunnels)
	}
	if !strings.Contains(logs.String(), "fair_use_hard_limit_crossed tunnel=tunnel-1") {
		t.Fatalf("hard crossing was not logged: %s", logs.String())
	}
	if strings.Contains(logs.String(), "server-prod-2") || strings.Contains(logs.String(), "203.0.113.9") {
		t.Fatalf("fair-use log exposed raw server/client identifiers: %s", logs.String())
	}
	if !usage.shouldLogRefusal() {
		t.Fatal("first refusal should be logged")
	}
	if usage.shouldLogRefusal() {
		t.Fatal("second refusal inside sample interval should not be logged")
	}
	clock.Advance(time.Minute)
	if !usage.shouldLogRefusal() {
		t.Fatal("refusal after sample interval should be logged")
	}
}

func TestFairUseConcurrentAccounting(t *testing.T) {
	clock := &fakeClock{now: time.Unix(300*int64(time.Hour/time.Second), 0)}
	limiter := newFairUseLimiter(FairUseConfig{
		Enabled:           true,
		WindowDays:        30,
		HardLimitBytes:    1 << 60,
		ThrottledMaxConns: 4,
		Clock:             clock.Now,
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	usage := limiter.tunnel("tunnel-a")

	const goroutines = 16
	const addsPerGoroutine = 1000
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < addsPerGoroutine; j++ {
				usage.add(1)
			}
		}()
	}
	wg.Wait()

	want := int64(goroutines * addsPerGoroutine)
	if snapshot := limiter.snapshot(); snapshot.windowBytes != want {
		t.Fatalf("window bytes = %d, want %d", snapshot.windowBytes, want)
	}
}

// Task 4: recordBytes accounts via the cached *tunnelUsage (set once at connect
// time) rather than re-resolving through the global limiter lock + full scan on
// every chunk. Correctness: the cached pointer is the same instance the limiter
// holds, and bytes recorded through it show up in the limiter snapshot.
func TestRecordBytesUsesCachedTunnelUsage(t *testing.T) {
	clock := &fakeClock{now: time.Unix(400*int64(time.Hour/time.Second), 0)}
	limiter := newFairUseLimiter(FairUseConfig{
		Enabled:        true,
		WindowDays:     30,
		HardLimitBytes: 1 << 60,
		Clock:          clock.Now,
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	c := &carrier{id: "tunnel-a", fairUse: limiter}
	c.usage = limiter.tunnel(c.id)
	if c.usage != limiter.tunnel(c.id) {
		t.Fatal("cached usage is not the same instance the limiter holds")
	}

	const chunk = 32 * 1024
	const chunks = 100
	for i := 0; i < chunks; i++ {
		c.recordBytes(chunk)
	}

	want := int64(chunk * chunks)
	if snapshot := limiter.snapshot(); snapshot.windowBytes != want {
		t.Fatalf("window bytes = %d, want %d", snapshot.windowBytes, want)
	}
}

// Pins the actual perf invariant of the fix: the byte hot path must NOT take the
// limiter's global lock per chunk. We hold the global lock on another goroutine and
// assert recordBytes still completes — accounting goes through the cached per-tunnel
// pointer (and its own per-tunnel mu), never l.mu. A regression that re-routed
// recordBytes back through l.tunnel(id) (or any global-lock + full-scan path) would
// block here until the global lock released, and the test would time out.
func TestRecordBytesDoesNotTakeGlobalLockPerChunk(t *testing.T) {
	clock := &fakeClock{now: time.Unix(400*int64(time.Hour/time.Second), 0)}
	limiter := newFairUseLimiter(FairUseConfig{
		Enabled:        true,
		WindowDays:     30,
		HardLimitBytes: 1 << 60,
		Clock:          clock.Now,
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	c := &carrier{id: "tunnel-a", fairUse: limiter}
	c.usage = limiter.tunnel(c.id)

	// Hold the limiter's global lock for the duration of the recording loop.
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	const chunk = 32 * 1024
	const chunks = 1000
	done := make(chan struct{})
	go func() {
		for i := 0; i < chunks; i++ {
			c.recordBytes(chunk)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recordBytes blocked while the limiter's global lock was held: " +
			"the byte hot path is taking the global lock per chunk")
	}

	// And the bytes landed in the cached tunnel's usage (read under its own lock,
	// independent of the held global lock).
	c.usage.mu.Lock()
	got := c.usage.total
	c.usage.mu.Unlock()
	if want := int64(chunk * chunks); got != want {
		t.Fatalf("tunnel total = %d, want %d", got, want)
	}
}

func TestFairUseLiveAndReplayUseSameDurableDigestBatchAndHour(t *testing.T) {
	clock := &fakeClock{now: time.Unix(2_010_000_123, 0)}
	store := &recordingDigestFairUseStore{failFirst: true}
	store.healthy.Store(true)
	outbox := openTestFairUseOutbox(t, testFairUseOutboxPath(t))
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true, WindowDays: 1, Clock: clock.Now}, nil)
	limiter.store = store
	limiter.outbox = outbox
	usage := limiter.tunnel("live-replay-raw-id")
	usage.mu.Lock()
	usage.pending = 321
	usage.mu.Unlock()

	if usage.flush() {
		t.Fatal("injected live response failure was not surfaced")
	}
	if outbox.count() != 1 {
		t.Fatal("failed live commit did not retain one durable authority")
	}
	if err := outbox.replay(context.Background(), store, clock.Now()); err != nil {
		t.Fatal(err)
	}
	calls := store.digestCalls()
	if len(calls) != 2 {
		t.Fatalf("digest calls = %d, want live attempt plus replay", len(calls))
	}
	if calls[0] != calls[1] {
		t.Fatalf("live/replay authority differs: live=%+v replay=%+v", calls[0], calls[1])
	}
	if calls[0].digest != fairUseTunnelDigest("live-replay-raw-id") {
		t.Fatal("live path did not use the durable tunnel digest")
	}
	if calls[0].createdAt.Unix() != clock.Now().Unix() {
		t.Fatalf("recorded time = %v, want %v", calls[0].createdAt, clock.Now())
	}
	limiter.close()
}

func TestRedisFairUseOlderReplayCannotShortenNewerBatchDedupeTTL(t *testing.T) {
	backend := miniredis.RunT(t)
	base := time.Unix(2_020_000_000, 0).Truncate(time.Hour)
	liveAt := base.Add(23 * time.Hour)
	backend.SetTime(liveAt)
	store := newTestRedisFairUseStore(t, backend, 24)
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	const rawID = "ttl-race-raw-id"
	digest := fairUseTunnelDigest(rawID)
	newer := testFairUseOutboxRecord(rawID, 200, 101)
	newer.CreatedAt = liveAt.Unix()
	newer.ExpiresAt = liveAt.Add(24 * time.Hour).Unix()
	if err := outbox.enqueue(newer); err != nil {
		t.Fatal(err)
	}
	ambiguous := &ambiguousDigestStore{sharedFairUseStore: store, digestStore: store}
	if err := outbox.replay(context.Background(), ambiguous, liveAt); err == nil {
		t.Fatal("crash-before-delete response loss was not surfaced")
	}

	_, _, _, batchesKey := store.keysDigest(digest)
	newerTTL := backend.TTL(batchesKey)
	olderBatchID := fmt.Sprintf("%032x", 102)
	if _, err := store.AddDigestAt(context.Background(), digest, olderBatchID, 100, base); err != nil {
		t.Fatal(err)
	}
	afterOlderTTL := backend.TTL(batchesKey)
	if afterOlderTTL < newerTTL {
		t.Fatalf("older replay shortened batch dedupe TTL from %v to %v", newerTTL, afterOlderTTL)
	}
	allowed, _, _, err := store.Reserve(context.Background(), rawID, "current-traffic", 3, 1000, 1, fairUseLeaseTTL)
	if err != nil || !allowed {
		t.Fatalf("current reservation allowed=%v err=%v", allowed, err)
	}
	if err := store.Release(context.Background(), rawID, "current-traffic"); err != nil {
		t.Fatal(err)
	}
	if err := outbox.close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	backend.FastForward(3 * time.Hour)
	backend.SetTime(base.Add(26 * time.Hour))
	restartedStore := newTestRedisFairUseStore(t, backend, 24)
	restartedOutbox := openTestFairUseOutbox(t, path)
	if err := restartedOutbox.replay(context.Background(), restartedStore, base.Add(26*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, total, _, err := restartedStore.Reserve(context.Background(), rawID, "verify-total", 3, 1000, 1, fairUseLeaseTTL)
	if err != nil || total != newer.Bytes {
		t.Fatalf("post-boundary total = %d err=%v, want exactly-once newer total %d", total, err, newer.Bytes)
	}
}

func TestFairUseShutdownCancelsAndJoinsLiveReservationHeartbeat(t *testing.T) {
	store := newReservationLifecycleStore(false)
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
	limiter.store = store
	limiter.heartbeatInterval = time.Millisecond
	limiter.leaseTTL = time.Second
	limiter.fenceMargin = 100 * time.Millisecond
	usage := limiter.tunnel("live-reservation")
	reservation, err := usage.reserve(3)
	if err != nil {
		t.Fatal(err)
	}
	reservation.start(func() {})
	waitTestSignal(t, store.refreshStarted, "reservation heartbeat did not enter Refresh")

	closed := make(chan struct{})
	go func() {
		limiter.close()
		close(closed)
	}()
	waitTestSignal(t, closed, "shutdown did not cancel and join the live heartbeat")
	waitTestSignal(t, store.refreshExited, "in-flight Refresh did not observe worker cancellation")
	waitTestSignal(t, reservation.workerDone, "reservation worker was not joined")
	reservation.release()
	if got := store.releaseCalls.Load(); got != 1 {
		t.Fatalf("reservation releases = %d, want exactly one", got)
	}
	if got := store.closeCalls.Load(); got != 1 {
		t.Fatalf("store closes = %d, want one", got)
	}
	if store.afterCloseCalls.Load() != 0 {
		t.Fatal("reservation touched the store after close")
	}
}

func TestFairUseShutdownWaitsForConcurrentReservationAdmission(t *testing.T) {
	store := newReservationLifecycleStore(true)
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
	limiter.store = store
	usage := limiter.tunnel("concurrent-reservation")
	result := make(chan error, 1)
	go func() {
		_, err := usage.reserve(3)
		result <- err
	}()
	waitTestSignal(t, store.reserveStarted, "reservation did not enter store admission")

	closed := make(chan struct{})
	go func() {
		limiter.close()
		close(closed)
	}()
	waitLimiterClosed(t, limiter)
	select {
	case <-closed:
		t.Fatal("shutdown closed the store before in-flight reservation admission returned")
	default:
	}
	close(store.allowReserve)
	if err := <-result; err == nil || !strings.Contains(err.Error(), "stopping") {
		t.Fatalf("concurrent reserve err = %v, want stopping fence", err)
	}
	waitTestSignal(t, closed, "shutdown did not finish after reservation admission drained")
	if got := store.releaseCalls.Load(); got != 1 {
		t.Fatalf("late reservation releases = %d, want exactly one", got)
	}
	if got := store.closeCalls.Load(); got != 1 {
		t.Fatalf("store closes = %d, want one", got)
	}
	if store.afterCloseCalls.Load() != 0 {
		t.Fatal("late reservation touched the store after close")
	}
}

func TestFairUseShutdownJoinsConcurrentReservationRelease(t *testing.T) {
	store := newReservationLifecycleStore(false)
	store.blockRelease = true
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
	limiter.store = store
	reservation, err := limiter.tunnel("concurrent-release").reserve(3)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() {
		reservation.release()
		close(released)
	}()
	waitTestSignal(t, store.releaseStarted, "reservation release did not enter the store")

	closed := make(chan struct{})
	go func() {
		limiter.close()
		close(closed)
	}()
	waitLimiterClosed(t, limiter)
	select {
	case <-closed:
		t.Fatal("shutdown closed the store before the concurrent release completed")
	default:
	}
	close(store.allowRelease)
	waitTestSignal(t, released, "concurrent reservation release did not complete")
	waitTestSignal(t, closed, "shutdown did not join the concurrent reservation release")
	if got := store.releaseCalls.Load(); got != 1 {
		t.Fatalf("reservation releases = %d, want exactly one", got)
	}
	if got := store.closeCalls.Load(); got != 1 {
		t.Fatalf("store closes = %d, want one", got)
	}
	if store.afterCloseCalls.Load() != 0 {
		t.Fatal("concurrent release touched the store after close")
	}
}

type digestFairUseCall struct {
	digest    string
	batchID   string
	bytes     int64
	createdAt time.Time
}

type recordingDigestFairUseStore struct {
	countingFairUseStore
	mu        sync.Mutex
	calls     []digestFairUseCall
	failFirst bool
}

func (s *recordingDigestFairUseStore) AddDigestAt(_ context.Context, digest, batchID string, bytes int64, createdAt time.Time) (int64, error) {
	s.mu.Lock()
	s.calls = append(s.calls, digestFairUseCall{digest: digest, batchID: batchID, bytes: bytes, createdAt: createdAt})
	fail := s.failFirst
	s.failFirst = false
	s.mu.Unlock()
	if fail {
		return 0, errors.New("response lost")
	}
	return s.addedBytes.Add(bytes), nil
}

func (s *recordingDigestFairUseStore) digestCalls() []digestFairUseCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]digestFairUseCall(nil), s.calls...)
}

type reservationLifecycleStore struct {
	countingFairUseStore
	blockReserve    bool
	blockRelease    bool
	reserveStarted  chan struct{}
	allowReserve    chan struct{}
	releaseStarted  chan struct{}
	allowRelease    chan struct{}
	refreshStarted  chan struct{}
	refreshExited   chan struct{}
	reserveOnce     sync.Once
	releaseOnce     sync.Once
	refreshOnce     sync.Once
	refreshExitOnce sync.Once
	releaseCalls    atomic.Int64
	afterCloseCalls atomic.Int64
	closed          atomic.Bool
}

func newReservationLifecycleStore(blockReserve bool) *reservationLifecycleStore {
	store := &reservationLifecycleStore{
		blockReserve:   blockReserve,
		reserveStarted: make(chan struct{}),
		allowReserve:   make(chan struct{}),
		releaseStarted: make(chan struct{}),
		allowRelease:   make(chan struct{}),
		refreshStarted: make(chan struct{}),
		refreshExited:  make(chan struct{}),
	}
	store.healthy.Store(true)
	return store
}

func (s *reservationLifecycleStore) Reserve(ctx context.Context, _ string, _ string, _ int, _ int64, _ int, _ time.Duration) (bool, int64, time.Time, error) {
	s.reserveOnce.Do(func() { close(s.reserveStarted) })
	if s.blockReserve {
		select {
		case <-ctx.Done():
			return false, 0, time.Time{}, ctx.Err()
		case <-s.allowReserve:
		}
	}
	if s.closed.Load() {
		s.afterCloseCalls.Add(1)
	}
	return true, 0, time.Now(), nil
}

func (s *reservationLifecycleStore) Refresh(ctx context.Context, _ string, _ string, _ time.Duration) (time.Time, bool, error) {
	s.refreshOnce.Do(func() { close(s.refreshStarted) })
	<-ctx.Done()
	s.refreshExitOnce.Do(func() { close(s.refreshExited) })
	if s.closed.Load() {
		s.afterCloseCalls.Add(1)
	}
	return time.Time{}, false, ctx.Err()
}

func (s *reservationLifecycleStore) Release(context.Context, string, string) error {
	s.releaseOnce.Do(func() { close(s.releaseStarted) })
	if s.blockRelease {
		<-s.allowRelease
	}
	if s.closed.Load() {
		s.afterCloseCalls.Add(1)
	}
	s.releaseCalls.Add(1)
	return nil
}

func (s *reservationLifecycleStore) Close() error {
	s.closed.Store(true)
	s.closeCalls.Add(1)
	return nil
}

func waitTestSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func waitLimiterClosed(t *testing.T, limiter *fairUseLimiter) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		limiter.mu.Lock()
		closed := limiter.closed
		limiter.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("limiter did not enter stopping state")
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
