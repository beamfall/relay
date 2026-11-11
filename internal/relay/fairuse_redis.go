package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	fairUseBatchBytes    = int64(1 << 20)
	fairUseFlushInterval = 250 * time.Millisecond
	fairUseLeaseTTL      = DefaultFairUseLeaseTTL
	fairUseHeartbeat     = 5 * time.Second
	fairUseFenceMargin   = DefaultFairUseFenceMargin
	fairUseCopyChunkMax  = int64(32 * 1024)
	fairUseCrashLossMax  = 2 * fairUseBatchBytes
)

type sharedFairUseStore interface {
	Add(context.Context, string, string, int64) (int64, error)
	Reserve(context.Context, string, string, int, int64, int, time.Duration) (bool, int64, time.Time, error)
	Refresh(context.Context, string, string, time.Duration) (time.Time, bool, error)
	Release(context.Context, string, string) error
	Ping(context.Context) error
	Healthy() bool
	Close() error
}

type redisFairUseStore struct {
	client      *redis.Client
	prefix      string
	windowHours int64
	healthy     atomic.Bool
}

var redisAddScript = redis.NewScript(`
local now = redis.call('TIME')
local now_sec = tonumber(now[1])
local hour = math.floor(now_sec / 3600)
local cutoff = hour - tonumber(ARGV[3]) + 1
local record_hour = tonumber(ARGV[4])
if record_hour < 0 then record_hour = hour end
local expired = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', cutoff - 1)
local total = tonumber(redis.call('HGET', KEYS[1], 'total') or '0')
if redis.call('HEXISTS', KEYS[3], ARGV[1]) == 1 then return total end
for _, h in ipairs(expired) do
  local field = 'b:' .. h
  total = total - tonumber(redis.call('HGET', KEYS[1], field) or '0')
  redis.call('HDEL', KEYS[1], field)
end
if #expired > 0 then redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', cutoff - 1) end
if record_hour < cutoff then return total end
local field = 'b:' .. record_hour
redis.call('HINCRBY', KEYS[1], field, ARGV[2])
total = total + tonumber(ARGV[2])
redis.call('HSET', KEYS[1], 'total', total)
redis.call('HSET', KEYS[3], ARGV[1], 1)
redis.call('ZADD', KEYS[2], record_hour, record_hour)
local remaining_hours = record_hour + tonumber(ARGV[3]) - hour + 1
local ttl = remaining_hours * 3600 * 1000
local function expire_max(key, requested)
  local current = redis.call('PTTL', key)
  if current < 0 or current < requested then redis.call('PEXPIRE', key, requested) end
end
expire_max(KEYS[1], ttl)
expire_max(KEYS[2], ttl)
expire_max(KEYS[3], ttl)
return total
`)

var redisReserveScript = redis.NewScript(`
local now = redis.call('TIME')
local now_sec = tonumber(now[1])
local now_ms = now_sec * 1000 + math.floor(tonumber(now[2]) / 1000)
local hour = math.floor(now_sec / 3600)
local cutoff = hour - tonumber(ARGV[2]) + 1
local expired = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', cutoff - 1)
local total = tonumber(redis.call('HGET', KEYS[1], 'total') or '0')
for _, h in ipairs(expired) do
  local field = 'b:' .. h
  total = total - tonumber(redis.call('HGET', KEYS[1], field) or '0')
  redis.call('HDEL', KEYS[1], field)
end
if #expired > 0 then redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', cutoff - 1) end
redis.call('HSET', KEYS[1], 'total', total)
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now_ms)
local cap = tonumber(ARGV[4])
if tonumber(ARGV[3]) > 0 and total >= tonumber(ARGV[3]) then
  cap = math.min(cap, tonumber(ARGV[5]))
end
if tonumber(redis.call('ZCARD', KEYS[3])) >= cap then return {0, total, now_ms} end
redis.call('ZADD', KEYS[3], 'NX', now_ms + tonumber(ARGV[6]), ARGV[1])
local ttl = math.max((tonumber(ARGV[2]) * 3600 + 3600) * 1000, tonumber(ARGV[6]) * 2)
redis.call('PEXPIRE', KEYS[1], ttl)
redis.call('PEXPIRE', KEYS[2], ttl)
redis.call('PEXPIRE', KEYS[3], ttl)
return {1, total, now_ms}
`)

var redisRefreshScript = redis.NewScript(`
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_ms)
if not redis.call('ZSCORE', KEYS[1], ARGV[1]) then return {0, now_ms} end
redis.call('ZADD', KEYS[1], now_ms + tonumber(ARGV[2]), ARGV[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]) * 2)
return {1, now_ms}
`)

func newRedisFairUseStore(ctx context.Context, rawURL string, windowHours int64) (*redisFairUseStore, error) {
	if rawURL == "" {
		return nil, errors.New("redis fair-use store requires a URL")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse fair-use redis URL: %w", err)
	}
	store := &redisFairUseStore{client: redis.NewClient(options), prefix: "beamfall:fairuse:", windowHours: windowHours}
	if err := store.Ping(ctx); err != nil {
		_ = store.client.Close()
		return nil, fmt.Errorf("connect fair-use redis store: %w", err)
	}
	return store, nil
}

func (s *redisFairUseStore) keys(id string) (string, string, string, string) {
	return s.keysDigest(fairUseTunnelDigest(id))
}

func (s *redisFairUseStore) keysDigest(digest string) (string, string, string, string) {
	base := s.prefix + digest
	return base + ":bytes", base + ":hours", base + ":leases", base + ":batches"
}

func (s *redisFairUseStore) Add(ctx context.Context, id, batchID string, n int64) (int64, error) {
	bytesKey, hoursKey, _, batchesKey := s.keys(id)
	result, err := redisAddScript.Run(ctx, s.client, []string{bytesKey, hoursKey, batchesKey}, batchID, n, s.windowHours, -1).Int64()
	s.mark(err)
	return result, err
}

func (s *redisFairUseStore) AddDigestAt(ctx context.Context, digest, batchID string, n int64, createdAt time.Time) (int64, error) {
	if !validLowerHex(digest, sha256HexLength) {
		return 0, errors.New("invalid fair-use tunnel digest")
	}
	bytesKey, hoursKey, _, batchesKey := s.keysDigest(digest)
	recordHour := createdAt.UTC().Unix() / int64(time.Hour/time.Second)
	result, err := redisAddScript.Run(ctx, s.client, []string{bytesKey, hoursKey, batchesKey}, batchID, n, s.windowHours, recordHour).Int64()
	s.mark(err)
	return result, err
}

func (s *redisFairUseStore) Reserve(ctx context.Context, id, lease string, streamCap int, hardLimit int64, throttledCap int, ttl time.Duration) (bool, int64, time.Time, error) {
	bytesKey, hoursKey, leasesKey, _ := s.keys(id)
	values, err := redisReserveScript.Run(ctx, s.client, []string{bytesKey, hoursKey, leasesKey}, lease, s.windowHours, hardLimit, streamCap, throttledCap, ttl.Milliseconds()).Slice()
	if err != nil {
		s.mark(err)
		return false, 0, time.Time{}, err
	}
	s.mark(nil)
	allowed, err := redisInt64(values[0])
	if err != nil {
		return false, 0, time.Time{}, err
	}
	total, err := redisInt64(values[1])
	if err != nil {
		return false, 0, time.Time{}, err
	}
	nowMS, err := redisInt64(values[2])
	if err != nil {
		return false, 0, time.Time{}, err
	}
	return allowed == 1, total, time.UnixMilli(nowMS), nil
}

func (s *redisFairUseStore) Refresh(ctx context.Context, id, lease string, ttl time.Duration) (time.Time, bool, error) {
	_, _, leasesKey, _ := s.keys(id)
	values, err := redisRefreshScript.Run(ctx, s.client, []string{leasesKey}, lease, ttl.Milliseconds()).Slice()
	if err != nil {
		s.mark(err)
		return time.Time{}, false, err
	}
	s.mark(nil)
	found, err := redisInt64(values[0])
	if err != nil {
		return time.Time{}, false, err
	}
	nowMS, err := redisInt64(values[1])
	if err != nil {
		return time.Time{}, false, err
	}
	return time.UnixMilli(nowMS), found == 1, nil
}

func (s *redisFairUseStore) Release(ctx context.Context, id, lease string) error {
	_, _, leasesKey, _ := s.keys(id)
	err := s.client.ZRem(ctx, leasesKey, lease).Err()
	s.mark(err)
	return err
}

func (s *redisFairUseStore) Ping(ctx context.Context) error {
	err := s.client.Ping(ctx).Err()
	s.mark(err)
	return err
}

func (s *redisFairUseStore) Healthy() bool  { return s.healthy.Load() }
func (s *redisFairUseStore) Close() error   { return s.client.Close() }
func (s *redisFairUseStore) mark(err error) { s.healthy.Store(err == nil) }

func redisInt64(value any) (int64, error) {
	switch value := value.(type) {
	case int64:
		return value, nil
	case string:
		return strconv.ParseInt(value, 10, 64)
	case []byte:
		return strconv.ParseInt(string(value), 10, 64)
	default:
		return 0, fmt.Errorf("unexpected redis integer %T", value)
	}
}

func newLeaseID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func fairUseTunnelDigest(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

type fairUseDigestStore interface {
	AddDigestAt(context.Context, string, string, int64, time.Time) (int64, error)
}

func addFairUseDigest(ctx context.Context, store sharedFairUseStore, digest, batchID string, n int64, createdAt time.Time) (int64, error) {
	if digestStore, ok := store.(fairUseDigestStore); ok {
		return digestStore.AddDigestAt(ctx, digest, batchID, n, createdAt)
	}
	return store.Add(ctx, digest, batchID, n)
}

type fairUseReservation struct {
	usage      *tunnelUsage
	id         string
	streamCap  int
	confirmed  time.Time
	done       chan struct{}
	once       sync.Once
	startOnce  sync.Once
	closeFence func()
	released   atomic.Bool
	workerCtx  context.Context
	workerStop context.CancelFunc
	workerDone chan struct{}
}

func (u *tunnelUsage) reserve(streamCap int) (*fairUseReservation, error) {
	if u.parent.store == nil {
		return nil, nil
	}
	u.parent.mu.Lock()
	if u.parent.closed {
		u.parent.mu.Unlock()
		return nil, errors.New("fair-use limiter is stopping")
	}
	u.parent.reservationOpWG.Add(1)
	u.parent.mu.Unlock()
	defer u.parent.reservationOpWG.Done()
	u.mu.Lock()
	stopping := u.stopping
	u.mu.Unlock()
	if stopping {
		return nil, errors.New("fair-use tunnel is stopping")
	}
	if !u.flush() || !u.pendingWithinBound() {
		return nil, errors.New("fair-use shared store unavailable")
	}
	leaseID, err := newLeaseID()
	if err != nil {
		return nil, fmt.Errorf("create fair-use reservation: %w", err)
	}
	ctx, cancel := context.WithTimeout(u.parent.ctx, 2*time.Second)
	defer cancel()
	allowed, total, _, err := u.parent.store.Reserve(ctx, u.id, leaseID, streamCap, u.parent.hardLimitBytes, u.parent.throttledMaxConns, u.parent.leaseTTL)
	if err != nil {
		return nil, errors.New("fair-use shared store unavailable")
	}
	if !allowed {
		if u.parent.hardLimitBytes > 0 && total >= u.parent.hardLimitBytes {
			return nil, errFairUseThrottled(min(streamCap, u.parent.throttledMaxConns))
		}
		return nil, errors.New("stream cap reached")
	}
	r := &fairUseReservation{usage: u, id: leaseID, streamCap: streamCap, confirmed: time.Now(), done: make(chan struct{})}
	u.parent.mu.Lock()
	if u.parent.closed {
		u.parent.mu.Unlock()
		r.release()
		return nil, errors.New("fair-use limiter is stopping")
	}
	u.parent.reservationsMu.Lock()
	u.parent.reservations[r] = true
	u.parent.reservationsMu.Unlock()
	u.parent.mu.Unlock()
	return r, nil
}

func (r *fairUseReservation) start(closeFence func()) {
	r.startOnce.Do(func() {
		r.closeFence = closeFence
		parent := r.usage.parent
		parent.mu.Lock()
		if parent.closed || r.released.Load() {
			parent.mu.Unlock()
			r.release()
			return
		}
		r.workerCtx, r.workerStop = context.WithCancel(parent.ctx)
		r.workerDone = make(chan struct{})
		parent.reservationWorkWG.Add(1)
		parent.mu.Unlock()
		go func() {
			defer parent.reservationWorkWG.Done()
			defer close(r.workerDone)
			r.heartbeat()
		}()
	})
}

func (r *fairUseReservation) heartbeat() {
	ticker := time.NewTicker(r.usage.parent.heartbeatInterval)
	defer ticker.Stop()
	for {
		deadline := time.Until(r.confirmed.Add(r.usage.parent.leaseTTL - r.usage.parent.fenceMargin))
		if deadline <= 0 {
			r.fence()
			return
		}
		timer := time.NewTimer(deadline)
		select {
		case <-r.done:
			timer.Stop()
			return
		case <-r.workerCtx.Done():
			timer.Stop()
			return
		case <-timer.C:
			r.fence()
			return
		case <-ticker.C:
			timer.Stop()
			ctx, cancel := context.WithTimeout(r.workerCtx, 2*time.Second)
			_, found, err := r.usage.parent.store.Refresh(ctx, r.usage.id, r.id, r.usage.parent.leaseTTL)
			cancel()
			r.usage.parent.reservationsMu.Lock()
			if !r.released.Load() {
				r.usage.parent.reservations[r] = err == nil && found
			}
			r.usage.parent.reservationsMu.Unlock()
			if err == nil && found {
				r.confirmed = time.Now()
			}
		}
	}
}

func (r *fairUseReservation) fence() {
	if r.closeFence != nil {
		r.closeFence()
	}
}

func (r *fairUseReservation) release() {
	r.once.Do(func() {
		r.released.Store(true)
		close(r.done)
		r.usage.parent.mu.Lock()
		if r.workerStop != nil {
			r.workerStop()
		}
		r.usage.parent.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = r.usage.parent.store.Release(ctx, r.usage.id, r.id)
		cancel()
		r.usage.parent.reservationsMu.Lock()
		delete(r.usage.parent.reservations, r)
		r.usage.parent.reservationsMu.Unlock()
	})
}
