package cache

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func TestPushGovernorTokenBucketRateCap(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	var slept time.Duration
	g := NewPushGovernor(10, 10, 0)
	g.now = func() time.Time { return now }
	g.sleep = func(ctx context.Context, d time.Duration) error {
		slept += d
		now = now.Add(d)
		return nil
	}
	if err := g.Wait(context.Background(), "tenant-a", 25); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if slept != 1500*time.Millisecond {
		t.Fatalf("slept = %s, want 1.5s", slept)
	}
}

func TestPushGovernorKeepsTwoTenantBucketsFair(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	var slept time.Duration
	g := NewPushGovernor(10, 10, 0)
	g.now = func() time.Time { return now }
	g.sleep = func(ctx context.Context, d time.Duration) error {
		slept += d
		now = now.Add(d)
		return nil
	}
	if err := g.Wait(context.Background(), "tenant-a", 10); err != nil {
		t.Fatalf("tenant-a first wait: %v", err)
	}
	if err := g.Wait(context.Background(), "tenant-a", 1); err != nil {
		t.Fatalf("tenant-a second wait: %v", err)
	}
	if slept == 0 {
		t.Fatal("tenant-a did not hit its rate cap")
	}
	slept = 0
	if err := g.Wait(context.Background(), "tenant-b", 10); err != nil {
		t.Fatalf("tenant-b wait: %v", err)
	}
	if slept != 0 {
		t.Fatalf("tenant-b slept %s; tenant-a drained its bucket", slept)
	}
}

func TestPushGovernorTwoTenantsContendIndependently(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	sleeping := make(chan struct{})
	release := make(chan struct{})
	g := NewPushGovernor(10, 10, 0)
	g.now = func() time.Time { return now }
	g.sleep = func(ctx context.Context, d time.Duration) error {
		close(sleeping)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := g.Wait(context.Background(), "tenant-a", 10); err != nil {
		t.Fatalf("tenant-a drain: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- g.Wait(context.Background(), "tenant-a", 10)
	}()
	<-sleeping
	tenantBDone := make(chan error, 1)
	go func() {
		tenantBDone <- g.Wait(context.Background(), "tenant-b", 10)
	}()
	select {
	case err := <-tenantBDone:
		if err != nil {
			t.Fatalf("tenant-b wait: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("tenant-b blocked behind tenant-a token bucket")
	}
	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("tenant-a wait: %v", err)
	}
}

func TestCarrierPushAndInventoryRoundTrip(t *testing.T) {
	clientSession, serverSession := cacheCarrierPair(t)
	store, err := NewStore(t.TempDir(), testKey, 1024)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- (CarrierHandler{Store: store}).Serve(ctx, serverSession)
	}()
	client := CarrierClient{Session: clientSession}
	expires := time.Now().Add(time.Hour)
	ack, err := client.Push(ctx, PushRequest{
		SegmentSetID: "segset",
		Segment:      "0001.m4s",
		ContentType:  "video/mp4",
		ExpiresAt:    expires,
		Body:         []byte("ciphertext"),
	})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if ack.Status != "stored" || ack.Quota.CapBytes != 1024 {
		t.Fatalf("ack = %#v", ack)
	}
	inv, err := client.Inventory(ctx, "segset")
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inv.Entries) != 1 || inv.Entries[0].Segment != "0001.m4s" {
		t.Fatalf("inventory = %#v", inv)
	}
	cancel()
	_ = clientSession.Close()
	_ = serverSession.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

func TestCarrierPullRoundTrip(t *testing.T) {
	clientSession, serverSession := cacheCarrierPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- (CarrierHandler{
			Pull: func(ctx context.Context, req PullRequest) (Entry, bool, error) {
				if req.SegmentSetID != "segset" || req.Segment != "0001.m4s" {
					return Entry{}, false, errors.New("unexpected pull request")
				}
				return Entry{Bytes: []byte("ciphertext"), ContentType: "video/mp4", ExpiresAt: time.Now().Add(time.Hour)}, true, nil
			},
		}).Serve(ctx, serverSession)
	}()
	entry, ok, err := (CarrierClient{Session: clientSession}).Pull(ctx, PullRequest{SegmentSetID: "segset", Segment: "0001.m4s"})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if !ok || string(entry.Bytes) != "ciphertext" || entry.ContentType != "video/mp4" {
		t.Fatalf("entry = %#v ok=%v", entry, ok)
	}
	cancel()
	_ = clientSession.Close()
	_ = serverSession.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

func TestCarrierPushQuotaAckRejectsWithoutEvicting(t *testing.T) {
	clientSession, serverSession := cacheCarrierPair(t)
	store, err := NewStore(t.TempDir(), testKey, 512)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- (CarrierHandler{Store: store}).Serve(ctx, serverSession)
	}()
	client := CarrierClient{Session: clientSession}
	expires := time.Now().Add(time.Hour)
	if _, err := client.Push(ctx, PushRequest{SegmentSetID: "segset", Segment: "0001.m4s", ExpiresAt: expires, Body: []byte("keep")}); err != nil {
		t.Fatalf("push existing: %v", err)
	}
	ack, err := client.Push(ctx, PushRequest{SegmentSetID: "segset", Segment: "0002.m4s", ExpiresAt: expires, Body: make([]byte, 1024)})
	if err != nil {
		t.Fatalf("push over quota: %v", err)
	}
	if ack.Status != "rejected" || ack.Error != ErrQuotaExceeded.Error() {
		t.Fatalf("ack = %#v, want quota reject", ack)
	}
	entry, ok, err := store.Get("segset", "0001.m4s")
	if err != nil || !ok || string(entry.Bytes) != "keep" {
		t.Fatalf("existing entry after reject: ok=%v entry=%#v err=%v", ok, entry, err)
	}
	cancel()
	_ = clientSession.Close()
	_ = serverSession.Close()
	if err := <-errCh; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("serve: %v", err)
	}
}

// TestAckDoesNotWalkTenantDirectory proves the push-ack path (CarrierHandler.ack)
// reads the O(1) used-bytes cache instead of walking the tenant directory the
// way Store.Inventory does. It tampers with the tenant directory out-of-band
// (bypassing Store, so the incremental cache is NOT updated) and asserts the
// ack's quota is unaffected - if ack() called Inventory, the walk would
// recompute `used` from disk and observe the tamper.
func TestAckDoesNotWalkTenantDirectory(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey, 1<<20)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	expires := time.Now().Add(time.Hour)
	for i := range 5 {
		seg := fmt.Sprintf("%04d.m4s", i)
		if err := store.Put("segset", seg, Entry{Bytes: []byte("xxxx"), ExpiresAt: expires}); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	h := CarrierHandler{Store: store}
	before := h.ack("segset", "stored", "")
	if before.Quota.UsedBytes <= 0 {
		t.Fatalf("expected nonzero used bytes before tamper, got %#v", before.Quota)
	}

	tenantDir := store.tenantDir("segset")
	dirEntries, err := os.ReadDir(tenantDir)
	if err != nil {
		t.Fatalf("read tenant dir: %v", err)
	}
	if len(dirEntries) == 0 {
		t.Fatal("expected tenant dir entries to tamper with")
	}
	for _, e := range dirEntries {
		if err := os.Remove(filepath.Join(tenantDir, e.Name())); err != nil {
			t.Fatalf("remove %s: %v", e.Name(), err)
		}
	}

	after := h.ack("segset", "stored", "")
	if after.Quota.UsedBytes != before.Quota.UsedBytes {
		t.Fatalf("ack quota changed after out-of-band disk tamper (used=%d, want unchanged %d); "+
			"ack must read the cache, not walk the tenant directory", after.Quota.UsedBytes, before.Quota.UsedBytes)
	}
}

// BenchmarkCarrierHandlerAck demonstrates the ack path's cost is flat
// regardless of how many segments a tenant has cached; a directory-walk-based
// ack (the pre-fix behaviour, via Inventory) would scale with `segments`.
func BenchmarkCarrierHandlerAck(b *testing.B) {
	store, err := NewStore(b.TempDir(), testKey, 1<<30)
	if err != nil {
		b.Fatalf("new store: %v", err)
	}
	expires := time.Now().Add(time.Hour)
	const segments = 2000
	for i := range segments {
		seg := fmt.Sprintf("%05d.m4s", i)
		if err := store.Put("segset", seg, Entry{Bytes: make([]byte, 4096), ExpiresAt: expires}); err != nil {
			b.Fatalf("put %d: %v", i, err)
		}
	}
	h := CarrierHandler{Store: store}
	b.ResetTimer()
	for range b.N {
		_ = h.ack("segset", "stored", "")
	}
}

func cacheCarrierPair(t *testing.T) (*yamux.Session, *yamux.Session) {
	t.Helper()
	left, right := net.Pipe()
	serverCh := make(chan *yamux.Session, 1)
	errCh := make(chan error, 2)
	go func() {
		session, err := yamux.Server(right, nil)
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- session
	}()
	client, err := yamux.Client(left, nil)
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	select {
	case server := <-serverCh:
		return client, server
	case err := <-errCh:
		t.Fatalf("yamux server: %v", err)
		return nil, nil
	}
}
