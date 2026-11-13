package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

const (
	fairUseFinalFlushTimeout        = 5 * time.Second
	fairUseFinalFlushInitialBackoff = 10 * time.Millisecond
	fairUseFinalFlushMaxBackoff     = 250 * time.Millisecond
)

// Redis-mode stream lease defaults. A live stream survives any Redis outage
// shorter than fairUseOutageBudget (70s here, longer than a typical
// managed-Redis failover). Once LeaseTTL-FenceMargin (80s here) passes
// without a confirmed refresh, the relay closes the stream before Redis can
// expire its lease and admit a replacement over the fleet stream cap.
const (
	DefaultFairUseLeaseTTL    = 90 * time.Second
	DefaultFairUseFenceMargin = 10 * time.Second
)

type FairUseConfig struct {
	Enabled           bool
	WindowDays        int
	SoftLimitBytes    int64
	HardLimitBytes    int64
	ThrottledMaxConns int
	// Store is "memory" (the default) or "redis". Redis is required for
	// multi-instance hosted accounting; RedisURL may contain credentials and is
	// never logged.
	Store      string
	RedisURL   string
	OutboxPath string
	// LeaseTTL and FenceMargin size the redis-mode stream lease; zero selects
	// DefaultFairUseLeaseTTL and DefaultFairUseFenceMargin.
	LeaseTTL    time.Duration
	FenceMargin time.Duration

	Clock             func() time.Time
	LogSampleInterval time.Duration
}

type fairUseLimiter struct {
	mu                sync.Mutex
	tunnels           map[string]*tunnelUsage
	windowHours       int64
	softLimitBytes    int64
	hardLimitBytes    int64
	throttledMaxConns int
	clock             func() time.Time
	logger            *slog.Logger
	logSampleInterval time.Duration
	nextPseudonym     int64
	store             sharedFairUseStore
	outbox            *fileFairUseOutbox
	ctx               context.Context
	cancel            context.CancelFunc
	replayCancel      context.CancelFunc
	replayWake        chan struct{}
	replayDone        chan struct{}
	closed            bool
	closeDone         chan struct{}
	workerWG          sync.WaitGroup
	reservationOpWG   sync.WaitGroup
	reservationWorkWG sync.WaitGroup
	reservationsMu    sync.Mutex
	reservations      map[*fairUseReservation]bool
	finalFlushTimeout time.Duration
	batchID           func() (string, error)
	leaseTTL          time.Duration
	heartbeatInterval time.Duration
	fenceMargin       time.Duration
}

type fairUseLevel int

const (
	fairUseUnder fairUseLevel = iota
	fairUseSoft
	fairUseHard
)

type fairUseBucket struct {
	used  bool
	hour  int64
	bytes int64
}

type tunnelUsage struct {
	mu             sync.Mutex
	id             string
	pseudonym      string
	parent         *fairUseLimiter
	buckets        []fairUseBucket
	total          int64
	lastSeen       time.Time
	lastSweepHour  int64
	lastLevel      fairUseLevel
	lastRefusalLog time.Time
	pending        int64
	flushMu        sync.Mutex
	retryBytes     int64
	retryBatchID   string
	stopping       bool
	workerCancel   context.CancelFunc
	workerDone     chan struct{}
	flushWake      chan struct{}
	stopOnce       sync.Once
}

type fairUseSnapshot struct {
	windowBytes      int64
	softTunnels      int64
	throttledTunnels int64
}

func newFairUseLimiter(cfg FairUseConfig, logger *slog.Logger) *fairUseLimiter {
	limiter, _ := newFairUseLimiterContext(context.Background(), cfg, logger)
	return limiter
}

func newFairUseLimiterContext(ctx context.Context, cfg FairUseConfig, logger *slog.Logger) (*fairUseLimiter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.WindowDays <= 0 {
		cfg.WindowDays = 30
	}
	if cfg.Store == "redis" && cfg.WindowDays > int(maxFairUseOutboxRetention/(24*time.Hour)) {
		return nil, errors.New("redis fair-use window exceeds durable outbox retention limit")
	}
	if cfg.ThrottledMaxConns <= 0 {
		cfg.ThrottledMaxConns = 4
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.LogSampleInterval <= 0 {
		cfg.LogSampleInterval = time.Minute
	}
	if cfg.LeaseTTL == 0 {
		cfg.LeaseTTL = DefaultFairUseLeaseTTL
	}
	if cfg.FenceMargin == 0 {
		cfg.FenceMargin = DefaultFairUseFenceMargin
	}
	if cfg.FenceMargin < 0 {
		return nil, errors.New("fair-use fence margin must not be negative")
	}
	if fairUseOutageBudget(cfg.LeaseTTL, cfg.FenceMargin) <= 0 {
		return nil, fmt.Errorf("fair-use lease TTL %s must exceed fence margin %s plus two %s heartbeats", cfg.LeaseTTL, cfg.FenceMargin, fairUseHeartbeat)
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	lifetimeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	limiter := &fairUseLimiter{
		tunnels:           make(map[string]*tunnelUsage),
		windowHours:       int64(cfg.WindowDays * 24),
		softLimitBytes:    cfg.SoftLimitBytes,
		hardLimitBytes:    cfg.HardLimitBytes,
		throttledMaxConns: cfg.ThrottledMaxConns,
		clock:             cfg.Clock,
		logger:            logger,
		logSampleInterval: cfg.LogSampleInterval,
		ctx:               lifetimeCtx,
		cancel:            cancel,
		closeDone:         make(chan struct{}),
		reservations:      make(map[*fairUseReservation]bool),
		finalFlushTimeout: fairUseFinalFlushTimeout,
		batchID:           newLeaseID,
		leaseTTL:          cfg.LeaseTTL,
		heartbeatInterval: fairUseHeartbeat,
		fenceMargin:       cfg.FenceMargin,
	}
	if cfg.Store == "redis" {
		store, err := newRedisFairUseStore(ctx, cfg.RedisURL, limiter.windowHours)
		if err != nil {
			cancel()
			return nil, err
		}
		limiter.store = store
		outbox, err := newFileFairUseOutbox(cfg.OutboxPath)
		if err != nil {
			_ = store.Close()
			cancel()
			return nil, err
		}
		limiter.outbox = outbox
		replayCtx, replayCancel := context.WithTimeout(ctx, fairUseFinalFlushTimeout)
		err = outbox.replay(replayCtx, store, limiter.clock())
		replayCancel()
		if err != nil {
			_ = outbox.close()
			_ = store.Close()
			cancel()
			return nil, fmt.Errorf("replay fair-use outbox: %w", err)
		}
		limiter.startReplayer()
	} else if cfg.Store != "" && cfg.Store != "memory" {
		cancel()
		return nil, fmt.Errorf("unknown fair-use store %q", cfg.Store)
	}
	return limiter, nil
}

func (l *fairUseLimiter) tunnel(id string) *tunnelUsage {
	now := l.clock()
	l.mu.Lock()
	evicted := l.evictLocked(now)
	if usage := l.tunnels[id]; usage != nil {
		usage.touch(now)
		l.mu.Unlock()
		stopTunnelUsage(evicted)
		return usage
	}
	usage := &tunnelUsage{
		id:            id,
		pseudonym:     l.nextTunnelPseudonymLocked(),
		parent:        l,
		buckets:       make([]fairUseBucket, l.windowHours),
		lastSeen:      now,
		lastSweepHour: hourOf(now),
	}
	if l.closed {
		usage.stopping = true
		l.mu.Unlock()
		stopTunnelUsage(evicted)
		return usage
	}
	l.tunnels[id] = usage
	if l.store != nil {
		usage.startFlushWorkerLocked()
	}
	l.mu.Unlock()
	stopTunnelUsage(evicted)
	return usage
}

func (u *tunnelUsage) startFlushWorkerLocked() {
	ctx, cancel := context.WithCancel(context.Background())
	u.workerCancel = cancel
	u.workerDone = make(chan struct{})
	u.flushWake = make(chan struct{}, 1)
	u.parent.workerWG.Add(1)
	go func() {
		defer u.parent.workerWG.Done()
		defer close(u.workerDone)
		u.flushLoop(ctx)
	}()
}

func (l *fairUseLimiter) nextTunnelPseudonymLocked() string {
	l.nextPseudonym++
	return fmt.Sprintf("tunnel-%d", l.nextPseudonym)
}

func (l *fairUseLimiter) evictLocked(now time.Time) []*tunnelUsage {
	if l.windowHours <= 0 {
		return nil
	}
	window := time.Duration(l.windowHours) * time.Hour
	var evicted []*tunnelUsage
	for id, usage := range l.tunnels {
		usage.mu.Lock()
		idle := now.Sub(usage.lastSeen)
		if idle > window {
			usage.stopping = true
		}
		usage.mu.Unlock()
		if idle > window {
			delete(l.tunnels, id)
			evicted = append(evicted, usage)
		}
	}
	return evicted
}

func (l *fairUseLimiter) snapshot() fairUseSnapshot {
	now := l.clock()
	l.mu.Lock()
	evicted := l.evictLocked(now)
	var snapshot fairUseSnapshot
	for _, usage := range l.tunnels {
		total, level := usage.snapshot(now)
		snapshot.windowBytes += total
		switch level {
		case fairUseHard:
			if l.softLimitBytes > 0 {
				snapshot.softTunnels++
			}
			snapshot.throttledTunnels++
		case fairUseSoft:
			snapshot.softTunnels++
		}
	}
	l.mu.Unlock()
	stopTunnelUsage(evicted)
	return snapshot
}

func stopTunnelUsage(usages []*tunnelUsage) {
	for _, usage := range usages {
		usage.stop()
	}
}

func (u *tunnelUsage) add(n int64) bool {
	if n <= 0 {
		return true
	}
	if u.parent.store != nil {
		now := u.parent.clock()
		u.mu.Lock()
		if u.stopping {
			u.mu.Unlock()
			return false
		}
		u.pending += n
		u.lastSeen = now
		full := u.pending >= fairUseBatchBytes
		u.mu.Unlock()
		if full {
			u.wakeFlush()
		}
		if u.pendingWithinBound() {
			return true
		}
		u.shedOverBound()
		return u.pendingWithinBound()
	}
	now := u.parent.clock()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.stopping {
		return false
	}
	u.advanceLocked(now)
	idx := int(hourOf(now) % int64(len(u.buckets)))
	bucket := &u.buckets[idx]
	if bucket.used && bucket.hour != hourOf(now) {
		u.total -= bucket.bytes
		bucket.bytes = 0
	}
	bucket.used = true
	bucket.hour = hourOf(now)
	bucket.bytes += n
	u.total += n
	u.lastSeen = now
	u.updateLevelLocked(true)
	return true
}

// wakeFlush hands a full batch to the tunnel's flush worker without waiting.
func (u *tunnelUsage) wakeFlush() {
	select {
	case u.flushWake <- struct{}{}:
	default:
	}
}

// shedOverBound runs on the copy path only when the flush worker has fallen
// behind, for example while it waits out a Redis timeout. It moves one batch
// to the local durable outbox and leaves the Redis commit to the worker and
// replayer, so byte copying never waits on a Redis round trip. Without an
// outbox (test-only wiring) there is nowhere durable to shed to, so it
// commits inline.
func (u *tunnelUsage) shedOverBound() {
	if u.parent.outbox == nil {
		u.flush()
		return
	}
	if _, ok := u.persistBatch(); ok {
		u.parent.signalReplay()
	}
}

func (u *tunnelUsage) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(fairUseFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-u.flushWake:
			u.flushFull()
		case <-ticker.C:
			u.flushFull()
			// While Redis is unhealthy a durable relay keeps partial batches
			// in RAM (inside the crash-loss bound) so an outage writes one
			// outbox record per MiB copied, not four per tunnel per second.
			if u.parent.outbox == nil || u.parent.store.Healthy() {
				u.flush()
			}
		}
	}
}

// flushFull commits every complete batch the copy path has accumulated.
func (u *tunnelUsage) flushFull() {
	for {
		u.mu.Lock()
		full := u.pending >= fairUseBatchBytes
		u.mu.Unlock()
		if !full || !u.flush() {
			return
		}
	}
}

func (u *tunnelUsage) flush() bool {
	return u.flushContext(u.parent.ctx)
}

func (u *tunnelUsage) flushContext(ctx context.Context) bool {
	if u.parent.store == nil {
		return true
	}
	if u.parent.outbox == nil {
		return u.flushDirect(ctx)
	}
	record, ok := u.persistBatch()
	if !ok {
		return false
	}
	if record.Bytes == 0 {
		return u.parent.store.Healthy()
	}
	return u.publish(ctx, record)
}

// nextBatch picks the retained retry batch first, else up to one batch of
// pending bytes under a fresh batch ID. The caller holds flushMu.
func (u *tunnelUsage) nextBatch() (batch int64, batchID string, fromRetry bool, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.retryBytes > 0 {
		return u.retryBytes, u.retryBatchID, true, nil
	}
	batch = min(u.pending, fairUseBatchBytes)
	if batch == 0 {
		return 0, "", false, nil
	}
	batchID, err = u.parent.batchID()
	return batch, batchID, false, err
}

// persistBatch moves the next batch from RAM into the durable outbox. It
// holds flushMu only for local disk work, never across a Redis round trip.
// A zero-byte record means nothing was pending.
func (u *tunnelUsage) persistBatch() (fairUseOutboxRecord, bool) {
	u.flushMu.Lock()
	defer u.flushMu.Unlock()
	batch, batchID, fromRetry, err := u.nextBatch()
	if err != nil {
		return fairUseOutboxRecord{}, false
	}
	if batch == 0 {
		return fairUseOutboxRecord{}, true
	}
	now := u.parent.clock()
	record := fairUseOutboxRecord{
		TunnelDigest: fairUseTunnelDigest(u.id),
		Bytes:        batch,
		BatchID:      batchID,
		CreatedAt:    now.Unix(),
		ExpiresAt:    now.Add(time.Duration(u.parent.windowHours) * time.Hour).Unix(),
	}
	if err := u.parent.outbox.enqueue(record); err != nil {
		u.parent.logger.Error("fair_use_outbox_write_failed", "err", err)
		return fairUseOutboxRecord{}, false
	}
	u.mu.Lock()
	if fromRetry && u.retryBatchID == batchID {
		u.retryBytes = 0
		u.retryBatchID = ""
	} else {
		u.pending -= batch
	}
	u.mu.Unlock()
	return record, true
}

// publish commits one durable record to Redis and drops it from the outbox.
// On failure the record stays durable for the replayer.
func (u *tunnelUsage) publish(ctx context.Context, record fairUseOutboxRecord) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	createdAt := time.Unix(record.CreatedAt, 0)
	if _, err := addFairUseDigest(ctx, u.parent.store, record.TunnelDigest, record.BatchID, record.Bytes, createdAt); err != nil {
		u.parent.signalReplay()
		return false
	}
	if err := u.parent.outbox.remove(record.BatchID); err != nil {
		u.parent.logger.Error("fair_use_outbox_delete_failed", "err", err)
		return false
	}
	return true
}

// flushDirect commits a batch straight to Redis for a limiter wired without
// an outbox, retaining the batch ID so a retry stays idempotent.
func (u *tunnelUsage) flushDirect(ctx context.Context) bool {
	u.flushMu.Lock()
	defer u.flushMu.Unlock()
	batch, batchID, fromRetry, err := u.nextBatch()
	if err != nil {
		return false
	}
	if batch == 0 {
		return u.parent.store.Healthy()
	}
	if !fromRetry {
		// Park the batch in the retry slot while the store call is in flight, so
		// pendingWithinBound and sharedPressure still count bytes that are neither
		// pending nor durably stored. Otherwise a slow failing Add lets the copy
		// loop admit a further crash-loss window of unaccounted bytes.
		u.mu.Lock()
		u.pending -= batch
		u.retryBytes = batch
		u.retryBatchID = batchID
		u.mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := u.parent.store.Add(ctx, u.id, batchID, batch); err != nil {
		u.mu.Lock()
		u.retryBytes = batch
		u.retryBatchID = batchID
		u.mu.Unlock()
		return false
	}
	u.mu.Lock()
	if u.retryBatchID == batchID {
		u.retryBytes = 0
		u.retryBatchID = ""
	}
	u.mu.Unlock()
	return true
}

func (u *tunnelUsage) flushAll(ctx context.Context) bool {
	attempt := 0
	for {
		u.mu.Lock()
		before := u.pending + u.retryBytes
		u.mu.Unlock()
		if before == 0 {
			return true
		}
		if !u.flushContext(ctx) {
			u.mu.Lock()
			after := u.pending + u.retryBytes
			u.mu.Unlock()
			if u.parent.outbox != nil {
				if after >= before {
					return false
				}
				continue
			}
			if !waitFairUseRetry(ctx, fairUseFinalFlushBackoff(attempt)) {
				return false
			}
			attempt++
			continue
		}
		attempt = 0
	}
}

func (u *tunnelUsage) stop() {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(u.parent.ctx), u.parent.finalFlushTimeout)
	defer cancel()
	u.stopContext(ctx)
}

func (u *tunnelUsage) stopContext(ctx context.Context) {
	u.stopOnce.Do(func() {
		u.mu.Lock()
		u.stopping = true
		u.mu.Unlock()

		// Keep the store alive while an idempotent batch is retried. A bounded
		// deadline prevents permanent Redis loss from hanging eviction or
		// process shutdown forever; transient failures inside that window retain
		// the same batch ID, so an ambiguous commit is never double-counted.
		if !u.flushAll(ctx) {
			u.parent.logger.Error("fair_use_final_flush_incomplete", "tunnel", u.pseudonym)
		}
		if u.workerCancel != nil {
			u.workerCancel()
			<-u.workerDone
		}
	})
}

func fairUseFinalFlushBackoff(attempt int) time.Duration {
	delay := fairUseFinalFlushInitialBackoff
	for i := 0; i < attempt && delay < fairUseFinalFlushMaxBackoff; i++ {
		delay *= 2
	}
	return min(delay, fairUseFinalFlushMaxBackoff)
}

func waitFairUseRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// fairUseOutageBudget is the longest Redis outage a live stream is guaranteed
// to survive, less the first post-outage refresh round trip. The fence fires
// leaseTTL-fenceMargin after the last confirmed refresh, which lands at most
// one heartbeat before the outage begins; after Redis returns, the next
// refresh starts within one heartbeat.
func fairUseOutageBudget(leaseTTL, fenceMargin time.Duration) time.Duration {
	return leaseTTL - fenceMargin - 2*fairUseHeartbeat
}

func (u *tunnelUsage) pendingWithinBound() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.pending+u.retryBytes < fairUseCrashLossMax-fairUseCopyChunkMax
}

func (l *fairUseLimiter) startReplayer() {
	ctx, cancel := context.WithCancel(l.ctx)
	l.replayCancel = cancel
	l.replayWake = make(chan struct{}, 1)
	l.replayDone = make(chan struct{})
	go func() {
		defer close(l.replayDone)
		ticker := time.NewTicker(fairUseFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-l.replayWake:
			}
			attemptCtx, attemptCancel := context.WithTimeout(ctx, 2*time.Second)
			err := l.outbox.replay(attemptCtx, l.store, l.clock())
			if err == nil && !l.store.Healthy() {
				// An idle relay has nothing to replay or refresh after an
				// outage; without this probe it would keep refusing new
				// opens and failing readiness after Redis returns.
				_ = l.store.Ping(attemptCtx)
			}
			attemptCancel()
			if err != nil && ctx.Err() == nil {
				l.logger.Error("fair_use_outbox_replay_failed", "err", err)
			}
		}
	}()
}

func (l *fairUseLimiter) signalReplay() {
	if l.replayWake == nil {
		return
	}
	select {
	case l.replayWake <- struct{}{}:
	default:
	}
}

func (u *tunnelUsage) hardLimited() bool {
	if u.parent.store != nil {
		return false
	}
	now := u.parent.clock()
	u.mu.Lock()
	defer u.mu.Unlock()
	u.advanceLocked(now)
	u.lastSeen = now
	return u.updateLevelLocked(false) == fairUseHard
}

func (l *fairUseLimiter) ready() bool {
	if l == nil || l.store == nil {
		return true
	}
	if !l.store.Healthy() {
		return false
	}
	if l.outbox != nil && !l.outbox.healthy() {
		return false
	}
	l.reservationsMu.Lock()
	defer l.reservationsMu.Unlock()
	for _, confirmed := range l.reservations {
		if !confirmed {
			return false
		}
	}
	return true
}

func (l *fairUseLimiter) sharedPressure() (pendingBytes, reservations int64) {
	if l == nil || l.store == nil {
		return 0, 0
	}
	l.mu.Lock()
	for _, usage := range l.tunnels {
		usage.mu.Lock()
		pendingBytes += usage.pending + usage.retryBytes
		usage.mu.Unlock()
	}
	l.mu.Unlock()
	if l.outbox != nil {
		pendingBytes += l.outbox.pendingBytes()
	}
	l.reservationsMu.Lock()
	reservations = int64(len(l.reservations))
	l.reservationsMu.Unlock()
	return pendingBytes, reservations
}

func (l *fairUseLimiter) close() {
	if l == nil || l.cancel == nil {
		return
	}
	l.mu.Lock()
	if l.closed {
		done := l.closeDone
		l.mu.Unlock()
		<-done
		return
	}
	l.closed = true
	usages := make([]*tunnelUsage, 0, len(l.tunnels))
	for id, usage := range l.tunnels {
		usage.mu.Lock()
		usage.stopping = true
		usage.mu.Unlock()
		usages = append(usages, usage)
		delete(l.tunnels, id)
	}
	l.mu.Unlock()

	flushCtx, flushCancel := context.WithTimeout(context.WithoutCancel(l.ctx), l.finalFlushTimeout)
	var stopWG sync.WaitGroup
	for _, usage := range usages {
		stopWG.Add(1)
		go func() {
			defer stopWG.Done()
			usage.stopContext(flushCtx)
		}()
	}
	stopWG.Wait()
	l.workerWG.Wait()
	l.reservationOpWG.Wait()
	l.reservationsMu.Lock()
	reservations := make([]*fairUseReservation, 0, len(l.reservations))
	for reservation := range l.reservations {
		reservations = append(reservations, reservation)
	}
	l.reservationsMu.Unlock()
	var releaseWG sync.WaitGroup
	for _, reservation := range reservations {
		releaseWG.Add(1)
		go func() {
			defer releaseWG.Done()
			reservation.release()
		}()
	}
	releaseWG.Wait()
	l.reservationWorkWG.Wait()
	if l.outbox != nil {
		_ = l.outbox.replay(flushCtx, l.store, l.clock())
		if l.replayCancel != nil {
			l.replayCancel()
			<-l.replayDone
		}
	}
	flushCancel()
	l.cancel()
	if l.store != nil {
		_ = l.store.Close()
	}
	if l.outbox != nil {
		if err := l.outbox.close(); err != nil {
			l.logger.Error("fair_use_outbox_close_failed", "err", err)
		}
	}
	close(l.closeDone)
}

func (u *tunnelUsage) shouldLogRefusal() bool {
	now := u.parent.clock()
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.lastRefusalLog.IsZero() && now.Sub(u.lastRefusalLog) < u.parent.logSampleInterval {
		return false
	}
	u.lastRefusalLog = now
	return true
}

func (u *tunnelUsage) touch(now time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.lastSeen = now
}

func (u *tunnelUsage) snapshot(now time.Time) (int64, fairUseLevel) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.advanceLocked(now)
	return u.total, u.updateLevelLocked(false)
}

func (u *tunnelUsage) advanceLocked(now time.Time) {
	currentHour := hourOf(now)
	if currentHour == u.lastSweepHour {
		return
	}
	for i := range u.buckets {
		bucket := &u.buckets[i]
		if bucket.used && currentHour-bucket.hour >= int64(len(u.buckets)) {
			u.total -= bucket.bytes
			bucket.used = false
			bucket.bytes = 0
		}
	}
	u.lastSweepHour = currentHour
}

func (u *tunnelUsage) updateLevelLocked(emitLogs bool) fairUseLevel {
	level := fairUseUnder
	if u.parent.hardLimitBytes > 0 && u.total >= u.parent.hardLimitBytes {
		level = fairUseHard
	} else if u.parent.softLimitBytes > 0 && u.total >= u.parent.softLimitBytes {
		level = fairUseSoft
	}
	if level == fairUseUnder {
		u.lastLevel = fairUseUnder
		return level
	}
	if emitLogs && u.parent.logger != nil {
		if u.parent.softLimitBytes > 0 && u.lastLevel < fairUseSoft && level >= fairUseSoft {
			u.parent.logger.Warn("fair_use_soft_limit_crossed", "tunnel", u.pseudonym, "window_bytes", u.total, "soft_limit_bytes", u.parent.softLimitBytes)
		}
		if u.lastLevel < fairUseHard && level >= fairUseHard {
			u.parent.logger.Warn("fair_use_hard_limit_crossed", "tunnel", u.pseudonym, "window_bytes", u.total, "hard_limit_bytes", u.parent.hardLimitBytes, "throttled_max_conns", u.parent.throttledMaxConns)
		}
	}
	u.lastLevel = level
	return level
}

func hourOf(t time.Time) int64 {
	return t.UTC().Unix() / int64(time.Hour/time.Second)
}

type fairUseThrottleError struct {
	limit int
}

func (e fairUseThrottleError) Error() string {
	return fmt.Sprintf("fair use throttle reached throttled_max_conns=%d", e.limit)
}

func errFairUseThrottled(limit int) error {
	return fairUseThrottleError{limit: limit}
}

func isFairUseThrottled(err error) bool {
	var throttle fairUseThrottleError
	return errors.As(err, &throttle)
}
