package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func newTestRedisFairUseStore(t *testing.T, backend *miniredis.Miniredis, windowHours int64) *redisFairUseStore {
	t.Helper()
	store, err := newRedisFairUseStore(context.Background(), "redis://"+backend.Addr(), windowHours)
	if err != nil {
		t.Fatalf("new redis fair-use store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestRedisFairUseFleetWideReservationAndCrashExpiry(t *testing.T) {
	backend := miniredis.RunT(t)
	now := time.Unix(1_800_000_000, 0)
	backend.SetTime(now)
	first := newTestRedisFairUseStore(t, backend, 24)
	second := newTestRedisFairUseStore(t, backend, 24)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		store := first
		if i%2 == 1 {
			store = second
		}
		allowed, _, _, err := store.Reserve(ctx, "opaque-server", "lease-"+string(rune('a'+i)), 3, 100, 1, fairUseLeaseTTL)
		if err != nil || !allowed {
			t.Fatalf("reservation %d: allowed=%v err=%v", i, allowed, err)
		}
	}
	allowed, _, _, err := second.Reserve(ctx, "opaque-server", "lease-d", 3, 100, 1, fairUseLeaseTTL)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("fourth fleet-wide reservation succeeded above ADR-0018 three-stream cap")
	}
	if err := first.Release(ctx, "opaque-server", "lease-a"); err != nil {
		t.Fatal(err)
	}
	allowed, _, _, err = second.Reserve(ctx, "opaque-server", "lease-d", 3, 100, 1, fairUseLeaseTTL)
	if err != nil || !allowed {
		t.Fatalf("reservation after release: allowed=%v err=%v", allowed, err)
	}

	backend.FastForward(fairUseLeaseTTL + time.Second)
	backend.SetTime(now.Add(fairUseLeaseTTL + time.Second))
	for i := 0; i < 3; i++ {
		allowed, _, _, err = first.Reserve(ctx, "opaque-server", "after-crash-"+string(rune('a'+i)), 3, 100, 1, fairUseLeaseTTL)
		if err != nil || !allowed {
			t.Fatalf("post-crash reservation %d: allowed=%v err=%v", i, allowed, err)
		}
	}
}

func TestRedisFairUseAtomicTotalsPersistAcrossRestartAndThrottle(t *testing.T) {
	backend := miniredis.RunT(t)
	store := newTestRedisFairUseStore(t, backend, 24)
	ctx := context.Background()
	const workers = 16
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Add(ctx, "opaque-server", "batch-"+newTestID(), 10); err != nil {
				t.Errorf("add: %v", err)
			}
		}()
	}
	wg.Wait()
	_ = store.Close()

	restarted := newTestRedisFairUseStore(t, backend, 24)
	allowed, total, _, err := restarted.Reserve(ctx, "opaque-server", "restart-lease", 3, 100, 1, fairUseLeaseTTL)
	if err != nil {
		t.Fatal(err)
	}
	if total != workers*10 {
		t.Fatalf("rolling total after restart = %d, want %d", total, workers*10)
	}
	if !allowed {
		t.Fatal("first hard-limited reservation should be admitted")
	}
	allowed, _, _, err = restarted.Reserve(ctx, "opaque-server", "restart-lease-2", 3, 100, 1, fairUseLeaseTTL)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("second instance decision exceeded hard-limit cap")
	}
}

func TestRedisFairUseBatchRetryIsIdempotent(t *testing.T) {
	backend := miniredis.RunT(t)
	store := newTestRedisFairUseStore(t, backend, 24)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		total, err := store.Add(ctx, "opaque-server", "same-ambiguous-batch", 1024)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1024 {
			t.Fatalf("retry %d total = %d, want 1024", i, total)
		}
	}
}

func TestRedisServerTimeControlsRollingExpiry(t *testing.T) {
	backend := miniredis.RunT(t)
	base := time.Unix(1_800_000_000, 0)
	backend.SetTime(base)
	store := newTestRedisFairUseStore(t, backend, 24)
	ctx := context.Background()
	if _, err := store.Add(ctx, "opaque-server", "first", 40); err != nil {
		t.Fatal(err)
	}
	backend.SetTime(base.Add(23 * time.Hour))
	if _, err := store.Add(ctx, "opaque-server", "second", 2); err != nil {
		t.Fatal(err)
	}
	_, total, _, err := store.Reserve(ctx, "opaque-server", "before-expiry", 3, 100, 1, fairUseLeaseTTL)
	if err != nil || total != 42 {
		t.Fatalf("total before server-time expiry = %d err=%v, want 42", total, err)
	}
	backend.SetTime(base.Add(25 * time.Hour))
	_, total, _, err = store.Reserve(ctx, "opaque-server", "after-expiry", 3, 100, 1, fairUseLeaseTTL)
	if err != nil || total != 2 {
		t.Fatalf("total after server-time expiry = %d err=%v, want 2", total, err)
	}
}

func TestSharedStoreLossMakesReadinessFailClosed(t *testing.T) {
	backend := miniredis.RunT(t)
	store := newTestRedisFairUseStore(t, backend, 24)
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
	limiter.store = store
	m := &metrics{fairUse: limiter}
	m.carriersConnected.Store(1)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	m.readyz(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("healthy shared store readiness = %d, want 200", rr.Code)
	}
	backend.Close()
	if err := store.Ping(context.Background()); err == nil {
		t.Fatal("ping unexpectedly succeeded after backend close")
	}
	rr = httptest.NewRecorder()
	m.readyz(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed shared store readiness = %d, want 503", rr.Code)
	}
}

func TestRedisFairUseStorageContainsOnlyOpaqueBoundedData(t *testing.T) {
	backend := miniredis.RunT(t)
	store := newTestRedisFairUseStore(t, backend, 24)
	const rawID = "server-private-do-not-persist"
	if _, err := store.Add(context.Background(), rawID, "batch-private", 42); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Reserve(context.Background(), rawID, "0123456789abcdef0123456789abcdef", 3, 100, 1, fairUseLeaseTTL); err != nil {
		t.Fatal(err)
	}
	for _, key := range backend.Keys() {
		if strings.Contains(key, rawID) {
			t.Fatalf("Redis key contains raw server identifier: %q", key)
		}
		if ttl := backend.TTL(key); ttl <= 0 || ttl > 25*time.Hour {
			t.Fatalf("key %q TTL = %v, want bounded positive retention", key, ttl)
		}
	}
}

func newTestID() string {
	id, _ := newLeaseID()
	return id
}

func TestQuietStreamIsFencedBeforeUnconfirmedLeaseExpiry(t *testing.T) {
	backend := miniredis.RunT(t)
	store := newTestRedisFairUseStore(t, backend, 24)
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true, WindowDays: 1}, nil)
	limiter.store = store
	defer limiter.close()
	usage := limiter.tunnel("opaque-server")
	fenced := make(chan struct{}, 1)
	reservation := &fairUseReservation{
		usage: usage, id: "quiet", streamCap: 3,
		confirmed: time.Now().Add(-fairUseLeaseTTL), done: make(chan struct{}),
	}
	limiter.reservationsMu.Lock()
	limiter.reservations[reservation] = true
	limiter.reservationsMu.Unlock()
	reservation.start(func() { fenced <- struct{}{} })
	select {
	case <-fenced:
	case <-time.After(time.Second):
		t.Fatal("quiet stream outlived its unconfirmed reservation")
	}
	reservation.release()
}

func TestFairUseEvictionAndShutdownOwnWorkers(t *testing.T) {
	t.Run("eviction flushes and joins exactly once", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(1_900_000_000, 0)}
		store := &countingFairUseStore{}
		store.healthy.Store(true)
		limiter := newFairUseLimiter(FairUseConfig{
			Enabled:    true,
			WindowDays: 1,
			Clock:      clock.Now,
		}, nil)
		limiter.store = store
		usage := limiter.tunnel("evicted")
		if usage.workerDone == nil {
			t.Fatal("shared-store tunnel has no owned flush worker")
		}
		if !usage.add(123) {
			t.Fatal("healthy usage add was rejected")
		}

		clock.Advance(25 * time.Hour)
		_ = limiter.snapshot()
		assertWorkerStopped(t, usage)
		if got := store.addedBytes.Load(); got != 123 {
			t.Fatalf("persisted bytes after eviction = %d, want 123", got)
		}
		if got := store.addCalls.Load(); got != 1 {
			t.Fatalf("store adds after eviction = %d, want 1", got)
		}

		_ = limiter.snapshot()
		limiter.close()
		limiter.close()
		if got := store.addCalls.Load(); got != 1 {
			t.Fatalf("repeated eviction/shutdown added the final delta %d times, want 1", got)
		}
	})

	t.Run("shutdown drains batches before cancel and rejects new workers", func(t *testing.T) {
		store := &countingFairUseStore{}
		store.healthy.Store(true)
		limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
		limiter.store = store
		usage := limiter.tunnel("shutdown")
		const finalBytes = fairUseBatchBytes + 123
		if !usage.add(finalBytes) {
			t.Fatal("healthy usage add was rejected")
		}

		var closes sync.WaitGroup
		closes.Add(2)
		go func() {
			defer closes.Done()
			limiter.close()
		}()
		go func() {
			defer closes.Done()
			limiter.close()
		}()
		closes.Wait()

		assertWorkerStopped(t, usage)
		if got := store.addedBytes.Load(); got != finalBytes {
			t.Fatalf("persisted bytes after shutdown = %d, want %d", got, finalBytes)
		}
		if got := store.addCalls.Load(); got != 2 {
			t.Fatalf("store adds after batched shutdown = %d, want 2", got)
		}
		if got := store.closeCalls.Load(); got != 1 {
			t.Fatalf("store closes after concurrent shutdown = %d, want 1", got)
		}

		late := limiter.tunnel("after-shutdown")
		if late.workerDone != nil {
			t.Fatal("shutdown admitted a new flush worker")
		}
		if late.add(1) {
			t.Fatal("shutdown tunnel accepted usage with no persistence worker")
		}
	})

	t.Run("failed final flush retries before cancellation and persists exactly once", func(t *testing.T) {
		store := newInterruptibleFairUseStore()
		limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
		limiter.store = store
		usage := limiter.tunnel("interrupted")
		if !usage.add(456) {
			t.Fatal("usage add was rejected before shutdown")
		}

		closed := make(chan struct{})
		go func() {
			limiter.close()
			close(closed)
		}()
		select {
		case <-store.addStarted:
		case <-time.After(time.Second):
			t.Fatal("shutdown did not attempt the final flush")
		}
		select {
		case <-store.addContextCanceled:
			t.Fatal("owner context was canceled before the final flush completed")
		default:
		}
		close(store.releaseAdd)
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("shutdown did not recover the interrupted final flush")
		}
		assertWorkerStopped(t, usage)
		if got := store.addCalls.Load(); got != 2 {
			t.Fatalf("final delta attempts = %d, want failure plus retry", got)
		}
		if got := store.addedBytes.Load(); got != 456 {
			t.Fatalf("persisted bytes after recovery = %d, want 456", got)
		}
		if got := store.uniqueBatchIDs(); got != 1 {
			t.Fatalf("final delta used %d batch IDs, want one idempotent replay authority", got)
		}
		if got := store.closeCalls.Load(); got != 1 {
			t.Fatalf("store closes after interrupted shutdown = %d, want 1", got)
		}
	})

	t.Run("permanent failure has a bounded shutdown and leaves no worker", func(t *testing.T) {
		store := &countingFairUseStore{failAdd: true}
		store.healthy.Store(true)
		limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
		limiter.store = store
		outboxPath := testFairUseOutboxPath(t)
		limiter.outbox = openTestFairUseOutbox(t, outboxPath)
		limiter.finalFlushTimeout = 25 * time.Millisecond
		usage := limiter.tunnel("permanent-outage")
		const acceptedBytes = fairUseBatchBytes + 789
		if !usage.add(acceptedBytes) {
			t.Fatal("usage add was rejected before shutdown")
		}

		closed := make(chan struct{})
		go func() {
			limiter.close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("permanent store failure hung shutdown")
		}
		assertWorkerStopped(t, usage)
		if got := store.addCalls.Load(); got < 2 {
			t.Fatalf("final delta attempts = %d, want at least one retry", got)
		}
		if got := store.closeCalls.Load(); got != 1 {
			t.Fatalf("store closes after permanent failure = %d, want 1", got)
		}
		restarted := openTestFairUseOutbox(t, outboxPath)
		records, err := restarted.records()
		if err != nil {
			t.Fatal(err)
		}
		var durableBytes int64
		batchIDs := make(map[string]struct{}, len(records))
		for _, record := range records {
			durableBytes += record.Bytes
			batchIDs[record.BatchID] = struct{}{}
		}
		if len(records) != 2 || durableBytes != acceptedBytes || len(batchIDs) != 2 {
			t.Fatalf("durable final records = %+v, want two stable batches totaling %d", records, acceptedBytes)
		}
		for _, record := range records {
			if strings.Contains(record.TunnelDigest, "permanent-outage") {
				t.Fatal("durable record contains the raw tunnel id")
			}
		}
	})

	t.Run("one global shutdown deadline still attempts every tunnel", func(t *testing.T) {
		store := &countingFairUseStore{failAdd: true}
		store.healthy.Store(true)
		limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
		limiter.store = store
		outboxPath := testFairUseOutboxPath(t)
		limiter.outbox = openTestFairUseOutbox(t, outboxPath)
		limiter.finalFlushTimeout = 25 * time.Millisecond
		usages := []*tunnelUsage{
			limiter.tunnel("outage-a"),
			limiter.tunnel("outage-b"),
			limiter.tunnel("outage-c"),
		}
		for _, usage := range usages {
			if !usage.add(1) {
				t.Fatal("usage add was rejected before shutdown")
			}
		}

		limiter.close()

		for _, usage := range usages {
			assertWorkerStopped(t, usage)
		}
		if got := store.addCalls.Load(); got < int64(2*len(usages)) {
			t.Fatalf("final attempts across all tunnels = %d, want at least two per tunnel", got)
		}
		restarted := openTestFairUseOutbox(t, outboxPath)
		if got := restarted.count(); got != len(usages) {
			t.Fatalf("durable final records = %d, want %d", got, len(usages))
		}
	})

	t.Run("outbox replayer is owned joined and closes the store once", func(t *testing.T) {
		store := &countingFairUseStore{}
		store.healthy.Store(true)
		limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
		limiter.store = store
		outboxPath := testFairUseOutboxPath(t)
		limiter.outbox = openTestFairUseOutbox(t, outboxPath)
		limiter.startReplayer()
		usage := limiter.tunnel("owned-replayer")
		if !usage.add(51) {
			t.Fatal("usage add was rejected")
		}
		limiter.close()
		limiter.close()
		assertWorkerStopped(t, usage)
		select {
		case <-limiter.replayDone:
		default:
			t.Fatal("outbox replayer was not joined")
		}
		if got := store.closeCalls.Load(); got != 1 {
			t.Fatalf("store close calls = %d, want 1", got)
		}
		reopened := openTestFairUseOutbox(t, outboxPath)
		if reopened.count() != 0 {
			t.Fatal("joined replayer left confirmed durable state")
		}
	})
}

func TestFairUseAmbiguousRedisFinalFlushReplaysExactlyOnce(t *testing.T) {
	backend := miniredis.RunT(t)
	redisStore := newTestRedisFairUseStore(t, backend, 24)
	store := &ambiguousDigestStore{sharedFairUseStore: redisStore, digestStore: redisStore}
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
	limiter.store = store
	usage := limiter.tunnel("ambiguous-commit")
	if !usage.add(789) {
		t.Fatal("usage add was rejected before shutdown")
	}

	limiter.close()
	limiter.close()

	if got := store.calls.Load(); got != 2 {
		t.Fatalf("Redis final delta attempts = %d, want ambiguous commit plus replay", got)
	}
	if got := store.uniqueBatchIDs(); got != 1 {
		t.Fatalf("Redis final delta used %d batch IDs, want one", got)
	}
	_, total, _, err := redisStore.Reserve(context.Background(), "ambiguous-commit", "verify-total", 3, 1<<20, 1, fairUseLeaseTTL)
	if err != nil {
		t.Fatal(err)
	}
	if total != 789 {
		t.Fatalf("Redis total after ambiguous replay = %d, want 789", total)
	}
	assertWorkerStopped(t, usage)
}

func assertWorkerStopped(t *testing.T, usage *tunnelUsage) {
	t.Helper()
	select {
	case <-usage.workerDone:
	case <-time.After(time.Second):
		t.Fatal("fair-use flush worker was not joined")
	}
}

func TestFairUseAbruptCrashLossBound(t *testing.T) {
	store := &countingFairUseStore{failAdd: true}
	store.healthy.Store(true)
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
	limiter.store = store
	defer limiter.close()
	usage := limiter.tunnel("opaque-server")
	for usage.add(fairUseCopyChunkMax) {
	}
	usage.mu.Lock()
	got := usage.pending + usage.retryBytes
	usage.mu.Unlock()
	if got >= fairUseCrashLossMax {
		t.Fatalf("uncommitted bytes = %d, must remain strictly below 2 MiB", got)
	}
	if store.addCalls.Load() == 0 {
		t.Fatal("test did not exercise failed shared-store flush")
	}
}

func TestSharedFairUseBatchesCopyHotPath(t *testing.T) {
	store := &countingFairUseStore{}
	store.healthy.Store(true)
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
	limiter.store = store
	defer limiter.close()
	usage := limiter.tunnel("opaque-server")
	for i := 0; i < 100; i++ {
		if !usage.add(fairUseCopyChunkMax) {
			t.Fatal("healthy store unexpectedly exceeded pending bound")
		}
	}
	// Full batches commit on the tunnel's flush worker, off the copy path.
	waitFairUseCondition(t, 5*time.Second, "flush worker never drained full batches", func() bool {
		usage.mu.Lock()
		defer usage.mu.Unlock()
		return usage.pending < fairUseBatchBytes
	})
	// Drain the final partial batch and join the worker before checking committed bytes.
	limiter.close()
	if got, want := store.addedBytes.Load(), int64(100*fairUseCopyChunkMax); got != want {
		t.Fatalf("Redis committed bytes = %d for 100 copied chunks, want %d", got, want)
	}
}

type countingFairUseStore struct {
	addCalls   atomic.Int64
	addedBytes atomic.Int64
	closeCalls atomic.Int64
	healthy    atomic.Bool
	failAdd    bool
}

func (s *countingFairUseStore) Add(ctx context.Context, _ string, _ string, bytes int64) (int64, error) {
	s.addCalls.Add(1)
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.failAdd {
		s.healthy.Store(false)
		return 0, errors.New("backend unavailable")
	}
	return s.addedBytes.Add(bytes), nil
}
func (s *countingFairUseStore) Reserve(context.Context, string, string, int, int64, int, time.Duration) (bool, int64, time.Time, error) {
	return true, 0, time.Now(), nil
}
func (s *countingFairUseStore) Refresh(context.Context, string, string, time.Duration) (time.Time, bool, error) {
	return time.Now(), true, nil
}
func (s *countingFairUseStore) Release(context.Context, string, string) error { return nil }
func (s *countingFairUseStore) Ping(context.Context) error                    { return nil }
func (s *countingFairUseStore) Healthy() bool                                 { return s.healthy.Load() }
func (s *countingFairUseStore) Close() error {
	s.closeCalls.Add(1)
	return nil
}

type interruptibleFairUseStore struct {
	countingFairUseStore
	addStarted         chan struct{}
	addContextCanceled chan struct{}
	releaseAdd         chan struct{}
	startOnce          sync.Once
	cancelOnce         sync.Once
	batchMu            sync.Mutex
	batchIDs           map[string]struct{}
}

func newInterruptibleFairUseStore() *interruptibleFairUseStore {
	store := &interruptibleFairUseStore{
		addStarted:         make(chan struct{}),
		addContextCanceled: make(chan struct{}),
		releaseAdd:         make(chan struct{}),
		batchIDs:           make(map[string]struct{}),
	}
	store.healthy.Store(true)
	return store
}

func (s *interruptibleFairUseStore) Add(ctx context.Context, _ string, batchID string, bytes int64) (int64, error) {
	call := s.addCalls.Add(1)
	s.batchMu.Lock()
	s.batchIDs[batchID] = struct{}{}
	s.batchMu.Unlock()
	if call > 1 {
		s.healthy.Store(true)
		return s.addedBytes.Add(bytes), nil
	}
	s.startOnce.Do(func() { close(s.addStarted) })
	select {
	case <-ctx.Done():
		s.cancelOnce.Do(func() { close(s.addContextCanceled) })
		return 0, ctx.Err()
	case <-s.releaseAdd:
		s.healthy.Store(false)
		return 0, errors.New("interrupted")
	}
}

func (s *interruptibleFairUseStore) uniqueBatchIDs() int {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	return len(s.batchIDs)
}
