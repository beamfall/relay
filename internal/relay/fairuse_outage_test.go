package relay

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
)

const fairUseOutageDuration = 30 * time.Second

// redisPause holds every command the backend receives while paused and runs
// it on resume, so a command the client already timed out on can still
// commit late, as in a real failover. Backend methods must not be called
// while paused.
type redisPause struct {
	mu      sync.Mutex
	release chan struct{}
}

func pauseableMiniredis(t *testing.T) (*miniredis.Miniredis, *redisPause) {
	t.Helper()
	backend := miniredis.RunT(t)
	pause := &redisPause{}
	backend.Server().SetPreHook(func(*server.Peer, string, ...string) bool {
		pause.mu.Lock()
		release := pause.release
		pause.mu.Unlock()
		if release != nil {
			<-release
		}
		return false
	})
	t.Cleanup(pause.resume)
	return backend, pause
}

func (p *redisPause) pause() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.release == nil {
		p.release = make(chan struct{})
	}
}

func (p *redisPause) resume() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.release != nil {
		close(p.release)
		p.release = nil
	}
}

// newRedisOutageLimiter builds the production redis wiring (durable outbox
// and replayer) with the default lease settings.
func newRedisOutageLimiter(t *testing.T, backend *miniredis.Miniredis, pause *redisPause) *fairUseLimiter {
	t.Helper()
	limiter, err := newFairUseLimiterContext(context.Background(), FairUseConfig{
		Enabled:    true,
		WindowDays: 1,
		Store:      "redis",
		RedisURL:   "redis://" + backend.Addr(),
		OutboxPath: testFairUseOutboxPath(t),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pause.resume()
		limiter.close()
	})
	return limiter
}

// outageCopier feeds one live stream's bytes through the copy-path hook the
// way splice does, recording cuts and the slowest single call.
type outageCopier struct {
	stop    chan struct{}
	done    chan struct{}
	copied  int64
	cuts    int64
	slowest time.Duration
}

func startOutageCopier(usage *tunnelUsage) *outageCopier {
	c := &outageCopier{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-ticker.C:
			}
			started := time.Now()
			ok := usage.add(fairUseCopyChunkMax)
			c.slowest = max(c.slowest, time.Since(started))
			c.copied += fairUseCopyChunkMax
			if !ok {
				c.cuts++
			}
		}
	}()
	return c
}

func (c *outageCopier) finish() {
	close(c.stop)
	<-c.done
}

func pollFairUseCondition(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

func waitFairUseCondition(t *testing.T, timeout time.Duration, message string, cond func() bool) {
	t.Helper()
	if !pollFairUseCondition(timeout, cond) {
		t.Fatal(message)
	}
}

func TestFairUseRedisOutage30sCutsNoLiveStream(t *testing.T) {
	t.Parallel()
	backend, pause := pauseableMiniredis(t)
	limiter := newRedisOutageLimiter(t, backend, pause)
	if limiter.leaseTTL != DefaultFairUseLeaseTTL || limiter.fenceMargin != DefaultFairUseFenceMargin {
		t.Fatalf("lease settings = %s/%s, want defaults %s/%s", limiter.leaseTTL, limiter.fenceMargin, DefaultFairUseLeaseTTL, DefaultFairUseFenceMargin)
	}

	ids := []string{"outage-a", "outage-b", "outage-c"}
	var fences atomic.Int64
	copiers := make([]*outageCopier, len(ids))
	for i, id := range ids {
		usage := limiter.tunnel(id)
		reservation, err := usage.reserve(3)
		if err != nil {
			t.Fatalf("open before outage: %v", err)
		}
		reservation.start(func() { fences.Add(1) })
		copiers[i] = startOutageCopier(usage)
	}
	time.Sleep(time.Second)

	pause.pause()
	pausedAt := time.Now()
	waitFairUseCondition(t, 15*time.Second, "readiness stayed up while Redis was unreachable", func() bool {
		return !limiter.ready()
	})
	openStarted := time.Now()
	if _, err := limiter.tunnel(ids[0]).reserve(3); err == nil {
		t.Fatal("new open was admitted while Redis was unreachable")
	}
	t.Logf("new open refused after %s during the outage", time.Since(openStarted).Round(time.Millisecond))
	time.Sleep(fairUseOutageDuration - time.Since(pausedAt))
	pausedFor := time.Since(pausedAt)
	pause.resume()
	resumedAt := time.Now()

	// A fenced reservation stays unconfirmed here (the harness has no carrier
	// to close), so recovery is asserted after the fence count it depends on.
	recovered := pollFairUseCondition(30*time.Second, func() bool {
		return limiter.ready() && limiter.outbox.count() == 0
	})
	recoveredIn := time.Since(resumedAt)
	var copied, cuts int64
	var slowest time.Duration
	for _, copier := range copiers {
		copier.finish()
		copied += copier.copied
		cuts += copier.cuts
		slowest = max(slowest, copier.slowest)
	}
	t.Logf("paused %s; recovered in %s; copied %d bytes; cuts %d; fences %d; slowest copy-path add %s",
		pausedFor.Round(time.Millisecond), recoveredIn.Round(time.Millisecond), copied, cuts, fences.Load(), slowest.Round(time.Microsecond))
	if pausedFor < fairUseOutageDuration {
		t.Fatalf("outage lasted %s, want at least %s", pausedFor, fairUseOutageDuration)
	}
	if got := fences.Load(); got != 0 {
		t.Fatalf("%d live streams were fenced by a %s Redis outage, want 0", got, pausedFor.Round(time.Second))
	}
	if cuts != 0 {
		t.Fatalf("%d copy-path calls hit the crash-loss bound during the outage, want 0", cuts)
	}
	if slowest >= time.Second {
		t.Fatalf("slowest copy-path add = %s, want no wait on a Redis round trip", slowest)
	}
	if !recovered {
		t.Fatal("relay did not recover readiness and drain its outbox after Redis returned")
	}

	limiter.close()
	verify := newTestRedisFairUseStore(t, backend, 24)
	for i, id := range ids {
		_, total, _, err := verify.Reserve(context.Background(), id, "verify-total", 1000, 0, 1, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if total != copiers[i].copied {
			t.Fatalf("Redis total for %s = %d, want every copied byte exactly once (%d)", id, total, copiers[i].copied)
		}
	}
}

func TestFairUseRedisOutageIdleRelayRecoversAdmission(t *testing.T) {
	t.Parallel()
	backend, pause := pauseableMiniredis(t)
	limiter := newRedisOutageLimiter(t, backend, pause)
	usage := limiter.tunnel("idle-relay")

	pause.pause()
	if _, err := usage.reserve(3); err == nil {
		t.Fatal("new open was admitted while Redis was unreachable")
	}
	if limiter.ready() {
		t.Fatal("readiness stayed up while Redis was unreachable")
	}
	pause.resume()

	waitFairUseCondition(t, 10*time.Second, "idle relay never regained readiness after Redis returned", limiter.ready)
	reservation, err := usage.reserve(3)
	if err != nil {
		t.Fatalf("new open after Redis returned: %v", err)
	}
	reservation.release()
}

func TestFairUseOutageCopyPathNeverWaitsOnStore(t *testing.T) {
	t.Parallel()
	store := &stalledFairUseStore{}
	store.healthy.Store(true)
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true, WindowDays: 1}, nil)
	limiter.store = store
	limiter.outbox = openTestFairUseOutbox(t, testFairUseOutboxPath(t))
	limiter.finalFlushTimeout = 25 * time.Millisecond
	defer limiter.close()
	usage := limiter.tunnel("stalled-store")

	const accepted = 8 * fairUseBatchBytes
	var slowest time.Duration
	for copied := int64(0); copied < accepted; copied += fairUseCopyChunkMax {
		started := time.Now()
		if !usage.add(fairUseCopyChunkMax) {
			t.Fatalf("stream cut after %d bytes while the shared store stalled", copied)
		}
		slowest = max(slowest, time.Since(started))
	}
	if slowest >= time.Second {
		t.Fatalf("slowest copy-path add = %s, want no wait on the stalled store round trip", slowest)
	}
	waitFairUseCondition(t, 5*time.Second, "flush worker never reached the stalled store", func() bool {
		return store.addCalls.Load() > 0
	})
	usage.flushMu.Lock()
	usage.mu.Lock()
	held := usage.pending + limiter.outbox.pendingBytes()
	usage.mu.Unlock()
	usage.flushMu.Unlock()
	if held != accepted {
		t.Fatalf("pending plus durable bytes = %d, want every accepted byte %d", held, accepted)
	}
}

func TestFairUseRedisLeaseConfigDefaultsAndValidation(t *testing.T) {
	t.Parallel()
	if budget := fairUseOutageBudget(DefaultFairUseLeaseTTL, DefaultFairUseFenceMargin); budget < 60*time.Second {
		t.Fatalf("default outage budget = %s, want at least a 60s managed-Redis failover", budget)
	}
	limiter, err := newFairUseLimiterContext(context.Background(), FairUseConfig{Enabled: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if limiter.leaseTTL != DefaultFairUseLeaseTTL || limiter.fenceMargin != DefaultFairUseFenceMargin {
		t.Fatalf("zero config lease settings = %s/%s, want defaults", limiter.leaseTTL, limiter.fenceMargin)
	}
	limiter.close()
	limiter, err = newFairUseLimiterContext(context.Background(), FairUseConfig{Enabled: true, LeaseTTL: 2 * time.Minute, FenceMargin: 15 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if limiter.leaseTTL != 2*time.Minute || limiter.fenceMargin != 15*time.Second {
		t.Fatalf("configured lease settings = %s/%s, want 2m0s/15s", limiter.leaseTTL, limiter.fenceMargin)
	}
	limiter.close()
	for _, cfg := range []FairUseConfig{
		{Enabled: true, FenceMargin: -time.Second},
		{Enabled: true, LeaseTTL: -time.Second},
		{Enabled: true, LeaseTTL: 20 * time.Second, FenceMargin: 10 * time.Second},
	} {
		if _, err := newFairUseLimiterContext(context.Background(), cfg, nil); err == nil {
			t.Fatalf("lease TTL %s / fence margin %s accepted, want startup refusal", cfg.LeaseTTL, cfg.FenceMargin)
		}
	}
}

// stalledFairUseStore never answers a commit before its deadline, like a
// Redis primary that stopped responding mid-failover.
type stalledFairUseStore struct {
	countingFairUseStore
}

func (s *stalledFairUseStore) Add(ctx context.Context, _ string, _ string, _ int64) (int64, error) {
	s.addCalls.Add(1)
	<-ctx.Done()
	s.healthy.Store(false)
	return 0, ctx.Err()
}
