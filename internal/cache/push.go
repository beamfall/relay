package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/beamfall/relay/internal/protocol"
)

type PushRequest struct {
	SegmentSetID string
	Segment      string
	ContentType  string
	ExpiresAt    time.Time
	Body         []byte
}

type PullRequest struct {
	CarrierID    string
	SegmentSetID string
	Segment      string
}

type PullFetcher func(context.Context, PullRequest) (Entry, bool, error)

type PushAck struct {
	Status string
	Error  string
	Quota  QuotaState
}

type PushGovernor struct {
	rate  int64
	burst int64
	slots chan struct{}

	mu      sync.Mutex
	buckets map[string]*pushBucket
	now     func() time.Time
	sleep   func(context.Context, time.Duration) error
}

type pushBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func NewPushGovernor(rateBytesPerSecond, burstBytes int64, globalConcurrent int) *PushGovernor {
	if burstBytes <= 0 {
		burstBytes = rateBytesPerSecond
	}
	var slots chan struct{}
	if globalConcurrent > 0 {
		slots = make(chan struct{}, globalConcurrent)
	}
	return &PushGovernor{
		rate:    rateBytesPerSecond,
		burst:   burstBytes,
		slots:   slots,
		buckets: make(map[string]*pushBucket),
		now:     time.Now,
		sleep:   sleepContext,
	}
}

func (g *PushGovernor) Wait(ctx context.Context, tenant string, bytes int64) error {
	if g == nil || bytes <= 0 {
		return nil
	}
	if err := g.acquire(ctx); err != nil {
		return err
	}
	defer g.release()
	if g.rate <= 0 {
		return nil
	}
	b := g.bucket(tenant)
	b.mu.Lock()
	defer b.mu.Unlock()
	now := g.now()
	if b.last.IsZero() {
		b.last = now
		b.tokens = float64(g.burst)
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(float64(g.burst), b.tokens+elapsed*float64(g.rate))
	b.last = now
	if b.tokens >= float64(bytes) {
		b.tokens -= float64(bytes)
		return nil
	}
	missing := float64(bytes) - b.tokens
	wait := time.Duration(missing / float64(g.rate) * float64(time.Second))
	b.tokens = 0
	b.last = now.Add(wait)
	return g.sleep(ctx, wait)
}

func (g *PushGovernor) acquire(ctx context.Context) error {
	if g.slots == nil {
		return nil
	}
	select {
	case g.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *PushGovernor) release() {
	if g.slots != nil {
		<-g.slots
	}
}

func (g *PushGovernor) bucket(tenant string) *pushBucket {
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.buckets[tenant]
	if b == nil {
		b = &pushBucket{}
		g.buckets[tenant] = b
	}
	return b
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type CarrierHandler struct {
	Store    *Store
	Governor *PushGovernor
	Pull     PullFetcher
}

func (h CarrierHandler) Serve(ctx context.Context, session protocol.Session) error {
	if h.Store == nil && h.Pull == nil {
		return errors.New("cache store is required")
	}
	for {
		conn, err := session.Accept()
		if err != nil {
			if session.IsClosed() || ctx.Err() != nil {
				return nil
			}
			return err
		}
		go h.handle(ctx, conn)
	}
}

func (h CarrierHandler) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close() //nolint:errcheck // stream cleanup.
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		return
	}
	switch frame.Type {
	case protocol.FrameCachePush:
		h.handlePush(ctx, conn, frame.CachePush)
	case protocol.FrameCacheInventoryRequest:
		h.handleInventory(conn, frame.CacheInventoryRequest)
	case protocol.FrameCachePullRequest:
		h.handlePull(ctx, conn, frame.CachePullRequest)
	}
}

func (h CarrierHandler) handlePush(ctx context.Context, rw io.ReadWriter, push *protocol.CachePush) {
	if h.Store == nil {
		_ = writeCacheAck(rw, PushAck{Status: "rejected", Error: "cache_error"})
		return
	}
	if push == nil {
		_ = writeCacheAck(rw, PushAck{Status: "rejected", Error: "invalid_push"})
		return
	}
	if push.Bytes < 0 || push.Bytes > h.Store.TenantCapBytes {
		ack := h.ack(push.SegmentSetID, "rejected", ErrQuotaExceeded.Error())
		_ = writeCacheAck(rw, ack)
		return
	}
	if err := h.Governor.Wait(ctx, push.SegmentSetID, push.Bytes); err != nil {
		// Drain the still-unread body before acking: closing on the deferred
		// conn.Close() with unread bytes pending can RST the connection and
		// lose this ack, wedging the peer's Push instead of returning
		// "rate_limited" cleanly.
		_, _ = io.Copy(io.Discard, io.LimitReader(rw, push.Bytes))
		_ = writeCacheAck(rw, PushAck{Status: "rejected", Error: "rate_limited"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(rw, push.Bytes))
	if err != nil || int64(len(body)) != push.Bytes {
		_ = writeCacheAck(rw, PushAck{Status: "rejected", Error: "invalid_push"})
		return
	}
	err = h.Store.Put(push.SegmentSetID, push.Segment, Entry{
		Bytes:       body,
		ContentType: push.ContentType,
		ExpiresAt:   push.ExpiresAt,
	})
	if errors.Is(err, ErrQuotaExceeded) {
		_ = writeCacheAck(rw, h.ack(push.SegmentSetID, "rejected", ErrQuotaExceeded.Error()))
		return
	}
	if err != nil {
		_ = writeCacheAck(rw, PushAck{Status: "rejected", Error: "cache_error"})
		return
	}
	_ = writeCacheAck(rw, h.ack(push.SegmentSetID, "stored", ""))
}

func (h CarrierHandler) handleInventory(rw io.Writer, req *protocol.CacheInventoryRequest) {
	if req == nil || h.Store == nil {
		return
	}
	inv, err := h.Store.Inventory(req.SegmentSetID)
	if err != nil {
		return
	}
	_ = protocol.WriteFrame(rw, protocol.Frame{
		Type:           protocol.FrameCacheInventory,
		CacheInventory: toProtocolInventory(inv),
	})
}

func (h CarrierHandler) handlePull(ctx context.Context, rw io.ReadWriter, req *protocol.CachePullRequest) {
	if req == nil || h.Pull == nil {
		_ = writeCachePullResponse(rw, protocol.CachePullResponse{Status: "rejected", Error: "pull_unavailable"})
		return
	}
	entry, ok, err := h.Pull(ctx, PullRequest{SegmentSetID: req.SegmentSetID, Segment: req.Segment})
	if err != nil {
		_ = writeCachePullResponse(rw, protocol.CachePullResponse{Status: "rejected", Error: "pull_error"})
		return
	}
	if !ok {
		_ = writeCachePullResponse(rw, protocol.CachePullResponse{Status: "not_found"})
		return
	}
	if err := writeCachePullResponse(rw, protocol.CachePullResponse{
		Status:      "found",
		ContentType: entry.ContentType,
		ExpiresAt:   entry.ExpiresAt,
		Bytes:       int64(len(entry.Bytes)),
	}); err != nil {
		return
	}
	_, _ = rw.Write(entry.Bytes)
}

func (h CarrierHandler) ack(segmentSetID, status, code string) PushAck {
	quota, err := h.Store.Quota(segmentSetID)
	if err != nil {
		return PushAck{Status: status, Error: code}
	}
	return PushAck{Status: status, Error: code, Quota: quota}
}

type CarrierClient struct {
	Session protocol.Session
}

func (c CarrierClient) Push(ctx context.Context, req PushRequest) (PushAck, error) {
	if c.Session == nil {
		return PushAck{}, errors.New("cache carrier session is required")
	}
	stream, err := c.Session.Open()
	if err != nil {
		return PushAck{}, err
	}
	defer stream.Close() //nolint:errcheck // stream cleanup.
	if err := protocol.WriteFrame(stream, protocol.Frame{
		Type: protocol.FrameCachePush,
		CachePush: &protocol.CachePush{
			SegmentSetID: req.SegmentSetID,
			Segment:      req.Segment,
			ContentType:  req.ContentType,
			ExpiresAt:    req.ExpiresAt,
			Bytes:        int64(len(req.Body)),
		},
	}); err != nil {
		return PushAck{}, err
	}
	if _, err := stream.Write(req.Body); err != nil {
		return PushAck{}, err
	}
	frame, err := readFrameContext(ctx, stream)
	if err != nil {
		return PushAck{}, err
	}
	if frame.Type != protocol.FrameCacheAck || frame.CacheAck == nil {
		return PushAck{}, fmt.Errorf("unexpected cache ack frame %q", frame.Type)
	}
	return fromProtocolAck(frame.CacheAck), nil
}

func (c CarrierClient) Inventory(ctx context.Context, segmentSetID string) (Inventory, error) {
	if c.Session == nil {
		return Inventory{}, errors.New("cache carrier session is required")
	}
	stream, err := c.Session.Open()
	if err != nil {
		return Inventory{}, err
	}
	defer stream.Close() //nolint:errcheck // stream cleanup.
	if err := protocol.WriteFrame(stream, protocol.Frame{
		Type:                  protocol.FrameCacheInventoryRequest,
		CacheInventoryRequest: &protocol.CacheInventoryRequest{SegmentSetID: segmentSetID},
	}); err != nil {
		return Inventory{}, err
	}
	frame, err := readFrameContext(ctx, stream)
	if err != nil {
		return Inventory{}, err
	}
	if frame.Type != protocol.FrameCacheInventory || frame.CacheInventory == nil {
		return Inventory{}, fmt.Errorf("unexpected cache inventory frame %q", frame.Type)
	}
	return fromProtocolInventory(frame.CacheInventory), nil
}

func (c CarrierClient) Pull(ctx context.Context, req PullRequest) (Entry, bool, error) {
	if c.Session == nil {
		return Entry{}, false, errors.New("cache carrier session is required")
	}
	stream, err := c.Session.Open()
	if err != nil {
		return Entry{}, false, err
	}
	defer stream.Close() //nolint:errcheck // stream cleanup.
	if err := protocol.WriteFrame(stream, protocol.Frame{
		Type:             protocol.FrameCachePullRequest,
		CachePullRequest: &protocol.CachePullRequest{SegmentSetID: req.SegmentSetID, Segment: req.Segment},
	}); err != nil {
		return Entry{}, false, err
	}
	frame, err := readFrameContext(ctx, stream)
	if err != nil {
		return Entry{}, false, err
	}
	if frame.Type != protocol.FrameCachePullResponse || frame.CachePullResponse == nil {
		return Entry{}, false, fmt.Errorf("unexpected cache pull frame %q", frame.Type)
	}
	resp := frame.CachePullResponse
	if resp.Status == "not_found" {
		return Entry{}, false, nil
	}
	if resp.Status != "found" {
		return Entry{}, false, fmt.Errorf("cache pull rejected: %s", resp.Error)
	}
	// CarrierClient has no Store to check a tenant's actual cap against (it's
	// the client side of a pull, not the handler); DefaultTenantCapBytes is
	// the same hard ceiling Store falls back to, so an oversized or lying
	// resp.Bytes still can't force an unbounded allocation here.
	if resp.Bytes < 0 || resp.Bytes > DefaultTenantCapBytes {
		return Entry{}, false, errors.New("invalid cache pull body")
	}
	body, err := io.ReadAll(io.LimitReader(stream, resp.Bytes))
	if err != nil || int64(len(body)) != resp.Bytes {
		return Entry{}, false, errors.New("invalid cache pull body")
	}
	return Entry{Bytes: body, ContentType: resp.ContentType, ExpiresAt: resp.ExpiresAt}, true, nil
}

func readFrameContext(ctx context.Context, conn net.Conn) (protocol.Frame, error) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	frame, err := protocol.ReadFrame(conn)
	close(done)
	return frame, err
}

func writeCacheAck(w io.Writer, ack PushAck) error {
	return protocol.WriteFrame(w, protocol.Frame{
		Type:     protocol.FrameCacheAck,
		CacheAck: toProtocolAck(ack),
	})
}

func writeCachePullResponse(w io.Writer, resp protocol.CachePullResponse) error {
	return protocol.WriteFrame(w, protocol.Frame{
		Type:              protocol.FrameCachePullResponse,
		CachePullResponse: &resp,
	})
}

func toProtocolAck(ack PushAck) *protocol.CacheAck {
	return &protocol.CacheAck{
		Status: ack.Status,
		Error:  ack.Error,
		Quota: protocol.CacheQuotaState{
			UsedBytes: ack.Quota.UsedBytes,
			CapBytes:  ack.Quota.CapBytes,
		},
	}
}

func fromProtocolAck(ack *protocol.CacheAck) PushAck {
	return PushAck{
		Status: ack.Status,
		Error:  ack.Error,
		Quota: QuotaState{
			UsedBytes: ack.Quota.UsedBytes,
			CapBytes:  ack.Quota.CapBytes,
		},
	}
}

func toProtocolInventory(inv Inventory) *protocol.CacheInventory {
	entries := make([]protocol.CacheInventoryEntry, 0, len(inv.Entries))
	for _, entry := range inv.Entries {
		entries = append(entries, protocol.CacheInventoryEntry{
			Segment:     entry.Segment,
			Bytes:       entry.Bytes,
			ContentType: entry.ContentType,
			ExpiresAt:   entry.ExpiresAt,
		})
	}
	return &protocol.CacheInventory{
		Entries: entries,
		Quota: protocol.CacheQuotaState{
			UsedBytes: inv.Quota.UsedBytes,
			CapBytes:  inv.Quota.CapBytes,
		},
	}
}

func fromProtocolInventory(inv *protocol.CacheInventory) Inventory {
	entries := make([]InventoryEntry, 0, len(inv.Entries))
	for _, entry := range inv.Entries {
		entries = append(entries, InventoryEntry{
			Segment:     entry.Segment,
			Bytes:       entry.Bytes,
			ContentType: entry.ContentType,
			ExpiresAt:   entry.ExpiresAt,
		})
	}
	return Inventory{
		Entries: entries,
		Quota: QuotaState{
			UsedBytes: inv.Quota.UsedBytes,
			CapBytes:  inv.Quota.CapBytes,
		},
	}
}
