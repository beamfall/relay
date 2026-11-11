package relay

import (
	"context"
	"net"
	"sync"
	"time"
)

// minSleep coalesces tiny waits into a single sleep so the hot path neither spins
// on sub-timer-resolution durations nor re-acquires the lock thousands of times per
// 32 KiB copy. It bounds the rate-limit granularity, not throughput: tokens accrue
// at exactly rate/sec regardless of how long we slept.
const minSleep = 5 * time.Millisecond

type byteLimiter struct {
	mu       sync.Mutex
	rate     int64
	capacity int64
	tokens   int64
	last     time.Time
}

func newByteLimiter(rate, burst int64) *byteLimiter {
	if rate <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = rate
	}
	now := time.Now()
	return &byteLimiter{rate: rate, capacity: burst, tokens: burst, last: now}
}

// Wait blocks until n bytes' worth of tokens are available, or ctx is
// cancelled. Threading ctx through the sleep keeps a rate-limited splice
// goroutine responsive to connection close/shutdown instead of parking out
// the full sleep duration regardless of ctx state.
func (l *byteLimiter) Wait(ctx context.Context, n int) {
	if l == nil || n <= 0 {
		return
	}
	remaining := int64(n)
	for remaining > 0 {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.last)
		if elapsed > 0 {
			// Only advance l.last when at least one whole token accrued. At low
			// rates a single tick's elapsed time can truncate to zero tokens; if
			// l.last still advanced, that fractional progress would be discarded
			// forever and Wait would livelock on repeated zero-gain wakes.
			// Leaving l.last behind lets elapsed keep accumulating across wakes
			// until a whole token is earned; the capacity clamp below still
			// bounds any resulting catch-up burst.
			if gain := int64(elapsed.Seconds() * float64(l.rate)); gain > 0 {
				l.tokens += gain
				if l.tokens > l.capacity {
					l.tokens = l.capacity
				}
				l.last = now
			}
		}
		if l.tokens > 0 {
			take := l.tokens
			if take > remaining {
				take = remaining
			}
			l.tokens -= take
			remaining -= take
			l.mu.Unlock()
			continue
		}
		// Out of tokens: sleep long enough to accrue the full deficit (capped at the
		// burst capacity so a single huge Wait doesn't sleep unboundedly), with a floor
		// so we don't spin on sub-timer-resolution sleeps. One sleep replaces what was
		// previously thousands of lock+sleep iterations on the byte hot path.
		deficit := remaining
		if deficit > l.capacity {
			deficit = l.capacity
		}
		wait := time.Duration(float64(deficit) / float64(l.rate) * float64(time.Second))
		l.mu.Unlock()
		if wait < minSleep {
			wait = minSleep
		}
		ctxSleep(ctx, wait)
		if ctx.Err() != nil {
			return
		}
	}
}

const (
	// handshakeFreeFailures is the number of failed carrier handshakes a single
	// remote source may make before backoff begins. A legitimate operator who
	// fat-fingers a token a few times during a restart is unaffected; a brute
	// forcer hits the wall quickly.
	handshakeFreeFailures = 5
	// handshakeBackoffBase is the first backoff applied once a source is over the
	// free-failure threshold. It doubles per excess failure up to the cap.
	handshakeBackoffBase = 100 * time.Millisecond
	// handshakeBackoffMax caps the per-attempt backoff so a flood of failures can
	// never park a handler for an unbounded time (and so shutdown stays prompt).
	handshakeBackoffMax = 2 * time.Second
	// handshakeEntryTTL bounds throttle-map memory: entries untouched for this
	// long are pruned, so a churn of distinct attacker source IPs cannot grow the
	// map without bound.
	handshakeEntryTTL = 10 * time.Minute
)

// handshakeThrottle imposes a per-source backoff on repeated failed carrier
// handshakes. It is keyed by remote IPv4 /32 or IPv6 /64 so an attacker cannot
// dodge the penalty by re-dialing from fresh ephemeral ports or rotating IPv6
// interface identifiers. A successful handshake clears the source's record;
// idle records are pruned to bound memory.
type handshakeThrottle struct {
	mu      sync.Mutex
	entries map[string]*throttleEntry
	now     func() time.Time                     // injectable clock for deterministic tests
	sleep   func(context.Context, time.Duration) // injectable sleeper for deterministic tests
}

type throttleEntry struct {
	failures int
	last     time.Time
}

func newHandshakeThrottle() *handshakeThrottle {
	return &handshakeThrottle{
		entries: make(map[string]*throttleEntry),
		now:     time.Now,
		sleep:   ctxSleep,
	}
}

// ctxSleep sleeps for d but returns early if ctx is cancelled, keeping shutdown
// prompt even mid-backoff.
func ctxSleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// backoffBefore consults the per-source failure record and, if the source is
// over the free-failure threshold, sleeps for an exponentially growing, capped
// backoff. It also opportunistically prunes idle entries.
func (h *handshakeThrottle) backoffBefore(ctx context.Context, remote net.Addr) {
	if h == nil {
		return
	}
	key := sourcePrefix(remote)
	h.mu.Lock()
	h.pruneLocked()
	e := h.entries[key]
	var excess int
	if e != nil {
		excess = e.failures - handshakeFreeFailures
	}
	h.mu.Unlock()
	if excess <= 0 {
		return
	}
	wait := handshakeBackoffBase << (excess - 1)
	if wait > handshakeBackoffMax || wait <= 0 {
		wait = handshakeBackoffMax
	}
	h.sleep(ctx, wait)
}

// recordFailure increments the failure count for a source.
func (h *handshakeThrottle) recordFailure(remote net.Addr) {
	if h == nil {
		return
	}
	key := sourcePrefix(remote)
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.entries[key]
	if e == nil {
		e = &throttleEntry{}
		h.entries[key] = e
	}
	e.failures++
	e.last = h.now()
}

// recordSuccess clears a source's failure record after an authorized handshake.
func (h *handshakeThrottle) recordSuccess(remote net.Addr) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.entries, sourcePrefix(remote))
}

// FailureCount returns the recorded failure count for a source IP. Exported so
// tests can assert throttle state deterministically without timing.
func (h *handshakeThrottle) FailureCount(remote net.Addr) int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.entries[sourcePrefix(remote)]; e != nil {
		return e.failures
	}
	return 0
}

// pruneLocked drops entries idle past the TTL. Caller holds h.mu.
func (h *handshakeThrottle) pruneLocked() {
	cutoff := h.now().Add(-handshakeEntryTTL)
	for k, e := range h.entries {
		if e.last.Before(cutoff) {
			delete(h.entries, k)
		}
	}
}
