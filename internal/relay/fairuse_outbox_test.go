package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestFairUseOutboxPersistsOnlyDigestAndPrivateState(t *testing.T) {
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	const rawID = "raw-tunnel-id-must-never-reach-disk"
	record := testFairUseOutboxRecord(rawID, 123, 1)
	if err := outbox.enqueue(record); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), rawID) {
		t.Fatal("outbox persisted a raw tunnel identifier")
	}
	if !strings.Contains(string(raw), record.TunnelDigest) {
		t.Fatal("outbox omitted the opaque tunnel digest")
	}
	assertPrivateMode(t, path, 0o600)
	assertPrivateMode(t, path+".lock", 0o600)
	assertPrivateMode(t, filepath.Dir(path), 0o700)
}

func TestFairUseOutboxReplayUsesStableBatchWithoutDigestDoubleHash(t *testing.T) {
	backend := miniredis.RunT(t)
	now := time.Unix(2_000_000_000, 0)
	backend.SetTime(now)
	store := newTestRedisFairUseStore(t, backend, 24)
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	const rawID = "opaque-but-raw-tunnel"
	record := testFairUseOutboxRecord(rawID, 777, 2)
	record.CreatedAt = now.Unix()
	record.ExpiresAt = now.Add(24 * time.Hour).Unix()
	if err := outbox.enqueue(record); err != nil {
		t.Fatal(err)
	}
	if err := outbox.replay(context.Background(), store, now); err != nil {
		t.Fatal(err)
	}
	if outbox.count() != 0 {
		t.Fatal("confirmed replay was not durably removed")
	}
	bytesKey, _, _, _ := store.keysDigest(record.TunnelDigest)
	if !backend.Exists(bytesKey) {
		t.Fatalf("digest key %q was not written", bytesKey)
	}
	doubleDigest := fairUseTunnelDigest(record.TunnelDigest)
	doubleKey, _, _, _ := store.keysDigest(doubleDigest)
	if backend.Exists(doubleKey) {
		t.Fatal("replay double-hashed the persisted tunnel digest")
	}
	_, total, _, err := store.Reserve(context.Background(), rawID, "verify", 3, 1000, 1, fairUseLeaseTTL)
	if err != nil || total != 777 {
		t.Fatalf("replayed total = %d, err=%v, want 777", total, err)
	}
}

func TestFairUseOutboxAmbiguousCommitRestartIsExactlyOnce(t *testing.T) {
	backend := miniredis.RunT(t)
	now := time.Unix(2_000_100_000, 0)
	backend.SetTime(now)
	store := newTestRedisFairUseStore(t, backend, 24)
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	record := testFairUseOutboxRecord("ambiguous-raw-id", 901, 3)
	record.CreatedAt = now.Unix()
	record.ExpiresAt = now.Add(24 * time.Hour).Unix()
	if err := outbox.enqueue(record); err != nil {
		t.Fatal(err)
	}
	ambiguous := &ambiguousDigestStore{sharedFairUseStore: store, digestStore: store}
	if err := outbox.replay(context.Background(), ambiguous, now); err == nil {
		t.Fatal("ambiguous post-commit error was not surfaced")
	}
	if outbox.count() != 1 {
		t.Fatal("ambiguous record was removed without confirmation")
	}
	if err := outbox.close(); err != nil {
		t.Fatal(err)
	}
	restarted := openTestFairUseOutbox(t, path)
	if err := restarted.replay(context.Background(), store, now); err != nil {
		t.Fatal(err)
	}
	_, total, _, err := store.Reserve(context.Background(), "ambiguous-raw-id", "verify", 3, 2000, 1, fairUseLeaseTTL)
	if err != nil || total != 901 {
		t.Fatalf("total after ambiguous restart replay = %d, err=%v, want 901", total, err)
	}
}

func TestFairUseOutboxReplayKeepsOriginalHourAndDoesNotResurrectExpiredUsage(t *testing.T) {
	backend := miniredis.RunT(t)
	createdAt := time.Unix(2_000_300_000, 0).Truncate(time.Hour)
	replayAt := createdAt.Add(23 * time.Hour)
	backend.SetTime(replayAt)
	store := newTestRedisFairUseStore(t, backend, 24)
	outbox := openTestFairUseOutbox(t, testFairUseOutboxPath(t))
	record := testFairUseOutboxRecord("original-hour", 444, 8)
	record.CreatedAt = createdAt.Unix()
	record.ExpiresAt = createdAt.Add(24 * time.Hour).Unix()
	if err := outbox.enqueue(record); err != nil {
		t.Fatal(err)
	}
	if err := outbox.replay(context.Background(), store, replayAt); err != nil {
		t.Fatal(err)
	}
	_, hoursKey, _, _ := store.keys("original-hour")
	hours, err := backend.ZMembers(hoursKey)
	if err != nil {
		t.Fatal(err)
	}
	wantHour := fmt.Sprintf("%d", hourOf(createdAt))
	if len(hours) != 1 || hours[0] != wantHour {
		t.Fatalf("persisted hours = %v, want original hour %s", hours, wantHour)
	}
	backend.SetTime(createdAt.Add(25 * time.Hour))
	_, total, _, err := store.Reserve(context.Background(), "original-hour", "verify-expiry", 3, 1000, 1, fairUseLeaseTTL)
	if err != nil || total != 0 {
		t.Fatalf("total after original window = %d, err=%v, want 0", total, err)
	}
}

func TestFairUseOutboxCrashBoundaries(t *testing.T) {
	t.Run("before rename preserves old authority", func(t *testing.T) {
		path := testFairUseOutboxPath(t)
		outbox := openTestFairUseOutbox(t, path)
		outbox.failpoint = func(point fairUseOutboxFailpoint) error {
			if point == fairUseOutboxBeforeRename {
				return errors.New("crash before rename")
			}
			return nil
		}
		if err := outbox.enqueue(testFairUseOutboxRecord("before", 1, 4)); err == nil {
			t.Fatal("failpoint did not fail enqueue")
		}
		_ = outbox.close()
		restarted := openTestFairUseOutbox(t, path)
		if restarted.count() != 0 {
			t.Fatal("pre-rename record became authoritative")
		}
	})

	t.Run("after rename exposes new authority for replay", func(t *testing.T) {
		path := testFairUseOutboxPath(t)
		outbox := openTestFairUseOutbox(t, path)
		outbox.failpoint = func(point fairUseOutboxFailpoint) error {
			if point == fairUseOutboxAfterRename {
				return errors.New("crash after rename")
			}
			return nil
		}
		if err := outbox.enqueue(testFairUseOutboxRecord("after", 2, 5)); err == nil {
			t.Fatal("failpoint did not fail enqueue")
		}
		_ = outbox.close()
		restarted := openTestFairUseOutbox(t, path)
		if restarted.count() != 1 {
			t.Fatal("post-rename record was not recovered")
		}
	})

	t.Run("after redis commit before delete replays idempotently", func(t *testing.T) {
		backend := miniredis.RunT(t)
		now := time.Unix(2_000_200_000, 0)
		backend.SetTime(now)
		store := newTestRedisFairUseStore(t, backend, 24)
		path := testFairUseOutboxPath(t)
		outbox := openTestFairUseOutbox(t, path)
		record := testFairUseOutboxRecord("commit-before-delete", 333, 6)
		record.CreatedAt = now.Unix()
		record.ExpiresAt = now.Add(24 * time.Hour).Unix()
		if err := outbox.enqueue(record); err != nil {
			t.Fatal(err)
		}
		outbox.failpoint = func(point fairUseOutboxFailpoint) error {
			if point == fairUseOutboxBeforeRename {
				return errors.New("crash before durable delete")
			}
			return nil
		}
		if err := outbox.replay(context.Background(), store, now); err == nil {
			t.Fatal("delete failpoint did not surface")
		}
		_ = outbox.close()
		restarted := openTestFairUseOutbox(t, path)
		if err := restarted.replay(context.Background(), store, now); err != nil {
			t.Fatal(err)
		}
		_, total, _, err := store.Reserve(context.Background(), "commit-before-delete", "verify", 3, 1000, 1, fairUseLeaseTTL)
		if err != nil || total != 333 {
			t.Fatalf("total after delete-boundary replay = %d, err=%v, want 333", total, err)
		}
		if err := restarted.close(); err != nil {
			t.Fatal(err)
		}
		final := openTestFairUseOutbox(t, path)
		if final.count() != 0 {
			t.Fatal("durable delete resurrected a confirmed record")
		}
	})
}

func TestFairUseOutboxFailsClosedOnInvalidStateAndProvenance(t *testing.T) {
	valid := `{"version":1,"records":[]}` + "\n"
	cases := []struct {
		name  string
		state string
		mode  os.FileMode
	}{
		{name: "corrupt", state: "{", mode: 0o600},
		{name: "unknown version", state: fmt.Sprintf(`{"version":%d,"records":[]}`, fairUseOutboxVersion+1), mode: 0o600},
		{name: "unknown field", state: `{"version":1,"records":[],"raw_id":"forbidden"}`, mode: 0o600},
		{name: "duplicate field", state: `{"version":1,"version":1,"records":[]}`, mode: 0o600},
		{name: "non private mode", state: valid, mode: 0o640},
		{name: "oversized", state: strings.Repeat(" ", maxFairUseOutboxStateBytes+1), mode: 0o600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := testFairUseOutboxPath(t)
			if err := os.WriteFile(path, []byte(tc.state), tc.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := newFileFairUseOutbox(path); err == nil {
				t.Fatal("invalid outbox state was accepted")
			}
		})
	}

	t.Run("state symlink", func(t *testing.T) {
		path := testFairUseOutboxPath(t)
		target := filepath.Join(filepath.Dir(path), "target")
		if err := os.WriteFile(target, []byte(valid), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := newFileFairUseOutbox(path); err == nil {
			t.Fatal("symlink state was accepted")
		}
	})

	t.Run("directory symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "real")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := newFileFairUseOutbox(filepath.Join(link, "state.json")); err == nil {
			t.Fatal("symlink directory was accepted")
		}
	})

	t.Run("exclusive process lock", func(t *testing.T) {
		path := testFairUseOutboxPath(t)
		first := openTestFairUseOutbox(t, path)
		if _, err := newFileFairUseOutbox(path); err == nil {
			t.Fatal("second outbox owner acquired the same path")
		}
		if err := first.close(); err != nil {
			t.Fatal(err)
		}
		second := openTestFairUseOutbox(t, path)
		if err := second.close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("overflow", func(t *testing.T) {
		state := fairUseOutboxState{Version: fairUseOutboxVersion, Records: make([]fairUseOutboxRecord, maxFairUseOutboxRecords+1)}
		if err := validateFairUseOutboxState(state); err == nil || !strings.Contains(err.Error(), "cardinality") {
			t.Fatalf("overflow validation error = %v", err)
		}
	})
}

func TestFairUseOutboxFailureFencesAdmissionWithoutDroppingRAM(t *testing.T) {
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	store := &countingFairUseStore{}
	store.healthy.Store(true)
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true, WindowDays: 1}, nil)
	limiter.store = store
	limiter.outbox = outbox
	usage := limiter.tunnel("disk-failure-raw")
	outbox.failpoint = func(point fairUseOutboxFailpoint) error {
		if point == fairUseOutboxBeforeRename {
			return errors.New("injected disk failure")
		}
		return nil
	}
	usage.mu.Lock()
	usage.pending = fairUseBatchBytes
	usage.mu.Unlock()
	if usage.flush() {
		t.Fatal("flush succeeded despite durable outbox failure")
	}
	usage.mu.Lock()
	pending := usage.pending
	usage.mu.Unlock()
	if pending != fairUseBatchBytes {
		t.Fatalf("pending bytes = %d, want preserved %d", pending, fairUseBatchBytes)
	}
	if limiter.ready() {
		t.Fatal("outbox failure did not fail readiness closed")
	}
	if store.addCalls.Load() != 0 {
		t.Fatal("Redis was called before durable outbox authority")
	}
	usage.mu.Lock()
	usage.pending = 0
	usage.mu.Unlock()
	limiter.close()
}

func TestFairUseBatchIDFailurePreservesAcceptedDelta(t *testing.T) {
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	store := &countingFairUseStore{}
	store.healthy.Store(true)
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true, WindowDays: 1}, nil)
	limiter.store = store
	limiter.outbox = outbox
	limiter.batchID = func() (string, error) { return "", errors.New("entropy unavailable") }
	usage := limiter.tunnel("batch-id-failure")
	usage.mu.Lock()
	usage.pending = fairUseBatchBytes
	usage.mu.Unlock()
	if usage.flush() {
		t.Fatal("flush succeeded without a batch id")
	}
	usage.mu.Lock()
	pending := usage.pending
	usage.mu.Unlock()
	if pending != fairUseBatchBytes || outbox.count() != 0 || store.addCalls.Load() != 0 {
		t.Fatalf("generation failure mutated authority: pending=%d outbox=%d adds=%d", pending, outbox.count(), store.addCalls.Load())
	}
	limiter.batchID = newLeaseID
	limiter.close()
}

func TestFairUseShutdownJoinsWorkersAndReplayerBeforeOneStoreClose(t *testing.T) {
	outboxPath := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, outboxPath)
	store := &closeOrderFairUseStore{}
	store.healthy.Store(true)
	limiter := newFairUseLimiter(FairUseConfig{Enabled: true, WindowDays: 1}, nil)
	limiter.store = store
	limiter.outbox = outbox
	limiter.startReplayer()
	usage := limiter.tunnel("close-order")
	store.workerDone = usage.workerDone
	store.replayDone = limiter.replayDone
	if !usage.add(73) {
		t.Fatal("usage add was rejected")
	}
	limiter.close()
	limiter.close()
	if got := store.closeCalls.Load(); got != 1 {
		t.Fatalf("store close calls = %d, want 1", got)
	}
	if store.closedBeforeJoin.Load() {
		t.Fatal("store closed before a limiter-owned descendant joined")
	}
	reopened := openTestFairUseOutbox(t, outboxPath)
	if reopened.count() != 0 {
		t.Fatal("confirmed final delta remained after ordered shutdown")
	}
}

func TestFairUseOutboxExpiredRecordClearsWithoutRedisAdd(t *testing.T) {
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	record := testFairUseOutboxRecord("expired", 22, 7)
	if err := outbox.enqueue(record); err != nil {
		t.Fatal(err)
	}
	store := &countingFairUseStore{}
	store.healthy.Store(true)
	if err := outbox.replay(context.Background(), store, time.Unix(record.ExpiresAt, 0)); err != nil {
		t.Fatal(err)
	}
	if store.addCalls.Load() != 0 || outbox.count() != 0 {
		t.Fatalf("expired replay adds=%d records=%d, want zero", store.addCalls.Load(), outbox.count())
	}
}

func TestFairUseOutboxStartupFailurePrecedesListenerBind(t *testing.T) {
	backend := miniredis.RunT(t)
	path := testFairUseOutboxPath(t)
	if err := os.WriteFile(path, []byte(`{"version":99,"records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	publicAddr := freeFairUseTestAddr(t)
	carrierAddr := freeFairUseTestAddr(t)
	server, err := Start(context.Background(), Config{
		PublicAddr:  publicAddr,
		CarrierAddr: carrierAddr,
		CarrierTLSConfig: &tls.Config{
			Certificates: []tls.Certificate{backoffTestCert(t)},
			MinVersion:   tls.VersionTLS13,
		},
		TokenVerifier: StaticTokenVerifier{
			Token:     []byte("a-sufficiently-long-static-test-token"),
			CarrierID: "carrier",
			Hostnames: []string{"relay.test"},
		},
		FairUse: FairUseConfig{
			Enabled:    true,
			WindowDays: 1,
			Store:      "redis",
			RedisURL:   "redis://" + backend.Addr(),
			OutboxPath: path,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		server.Close()
		t.Fatal("corrupt outbox did not fail startup")
	}
	for _, addr := range []string{publicAddr, carrierAddr} {
		listener, listenErr := net.Listen("tcp", addr)
		if listenErr != nil {
			t.Fatalf("startup failure bound %s: %v", addr, listenErr)
		}
		_ = listener.Close()
	}
}

// TestFairUseOutboxAppendCostIsIndependentOfOutboxSize is the ticket's named
// counted-write test. A per-event cost independent of outbox size means each
// enqueue is an in-place append to the existing file, never a whole-file
// rewrite; a rewrite replaces the file (a new inode swapped in by rename), so
// the file's inode number changes, while an in-place append never changes it.
// The test asserts the inode is unchanged by an enqueue with few existing
// records and by one with many, which would catch a regression to per-event
// whole-file rewrites regardless of how large or small the file happens to
// be — unlike comparing file-size deltas, which stays small either way since
// only one record's worth of size is ever added by a single event.
func TestFairUseOutboxAppendCostIsIndependentOfOutboxSize(t *testing.T) {
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	sequence := 0
	nextRecord := func(rawID string) fairUseOutboxRecord {
		sequence++
		return testFairUseOutboxRecord(rawID, 1, sequence)
	}
	inode := func() uint64 {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatal("stat_t unavailable for outbox path")
		}
		return stat.Ino
	}
	assertInPlaceAppend := func(label string) {
		t.Helper()
		before := inode()
		if err := outbox.enqueue(nextRecord(label)); err != nil {
			t.Fatal(err)
		}
		if after := inode(); after != before {
			t.Fatalf("%s: enqueue replaced the outbox file (inode %d -> %d), want an in-place append with no whole-file rewrite", label, before, after)
		}
	}

	const warmup = 10
	const many = 300
	for i := 0; i < warmup; i++ {
		if err := outbox.enqueue(nextRecord(fmt.Sprintf("warm-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	assertInPlaceAppend("cost-early")

	for i := 0; i < many; i++ {
		if err := outbox.enqueue(nextRecord(fmt.Sprintf("bulk-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	assertInPlaceAppend("cost-late")
}

// TestFairUseOutboxReadinessRecoversAfterDrainWithoutRestart confirms that a
// capacity rejection is a live, self-recovering condition: once the outbox is
// full, healthy() goes false and further enqueues are rejected, but a single
// remove() (standing in for the replayer draining a record after Redis
// recovers) brings healthy() back to true in the same process, with no
// restart and no new outbox instance. At this two-record limit the readiness
// hysteresis band rounds to zero records, so one remove() drains below it.
func TestFairUseOutboxReadinessRecoversAfterDrainWithoutRestart(t *testing.T) {
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	outbox.maxRecords = 2

	first := testFairUseOutboxRecord("cap-1", 1, 1)
	second := testFairUseOutboxRecord("cap-2", 1, 2)
	if err := outbox.enqueue(first); err != nil {
		t.Fatal(err)
	}
	if err := outbox.enqueue(second); err != nil {
		t.Fatal(err)
	}
	if outbox.healthy() {
		t.Fatal("outbox reported healthy while at the record limit")
	}
	third := testFairUseOutboxRecord("cap-3", 1, 3)
	if err := outbox.enqueue(third); !errors.Is(err, errFairUseOutboxRecordLimit) {
		t.Fatalf("enqueue at capacity error = %v, want errFairUseOutboxRecordLimit", err)
	}
	if err := outbox.remove(first.BatchID); err != nil {
		t.Fatal(err)
	}
	if !outbox.healthy() {
		t.Fatal("outbox stayed unhealthy after draining below the limit, without a restart")
	}
	if err := outbox.enqueue(third); err != nil {
		t.Fatalf("enqueue after drain = %v, want success", err)
	}
}

// TestFairUseOutboxReadinessHysteresisAtRecordLimit confirms that readiness,
// once lost at the record limit, stays unready while the count sits in the
// band just below the limit and returns only once the count drops below it.
// No health poll happens at the limit itself: the enqueue that reached the
// limit is what latches the hold.
func TestFairUseOutboxReadinessHysteresisAtRecordLimit(t *testing.T) {
	if band := (&fileFairUseOutbox{}).readinessBand(); band <= 0 {
		t.Fatalf("readiness band at the production record limit = %d, want a positive band", band)
	}
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	outbox.maxRecords = 128
	band := outbox.readinessBand()
	if band < 2 {
		t.Fatalf("readiness band at a %d-record limit = %d, want at least 2", outbox.maxRecords, band)
	}
	added := make([]fairUseOutboxRecord, 0, outbox.maxRecords)
	for i := 1; i <= outbox.maxRecords; i++ {
		record := testFairUseOutboxRecord(fmt.Sprintf("band-%d", i), 1, i)
		if err := outbox.enqueue(record); err != nil {
			t.Fatal(err)
		}
		added = append(added, record)
	}
	floor := outbox.maxRecords - band
	for _, record := range added[:band+1] {
		if err := outbox.remove(record.BatchID); err != nil {
			t.Fatal(err)
		}
		count := outbox.count()
		if healthy := outbox.healthy(); healthy != (count < floor) {
			t.Fatalf("healthy() = %v at %d records, want unready until the count drops below %d (limit %d, band %d)", healthy, count, floor, outbox.maxRecords, band)
		}
	}
	if !outbox.healthy() {
		t.Fatal("outbox stayed unready after draining below the readiness band")
	}
}

// TestFairUseOutboxLoadsSingleObjectVersionFile confirms this binary still
// starts from a version-1 file, the single-object format a pre-append binary
// wrote, and that the running file then carries the append format's version.
func TestFairUseOutboxLoadsSingleObjectVersionFile(t *testing.T) {
	records := []fairUseOutboxRecord{
		testFairUseOutboxRecord("single-object-a", 10, 1),
		testFairUseOutboxRecord("single-object-b", 20, 2),
	}
	raw, err := json.Marshal(fairUseOutboxState{Version: 1, Records: records})
	if err != nil {
		t.Fatal(err)
	}
	path := testFairUseOutboxPath(t)
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	outbox := openTestFairUseOutbox(t, path)
	loaded, err := outbox.records()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(loaded, records) {
		t.Fatalf("version-1 file loaded %v, want %v", loaded, records)
	}
	running, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	base, _, err := decodeFairUseOutboxBase(running)
	if err != nil {
		t.Fatal(err)
	}
	if base.Version != fairUseOutboxVersion {
		t.Fatalf("running outbox base version = %d, want the append format's %d", base.Version, fairUseOutboxVersion)
	}
}

// TestFairUseOutboxCleanCloseLeavesSingleObjectFile confirms that a clean
// close compacts every log entry into one version-1 base object, which the
// pre-append binary's reader accepts, and which this binary reopens to the
// same records.
func TestFairUseOutboxCleanCloseLeavesSingleObjectFile(t *testing.T) {
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	added := []fairUseOutboxRecord{
		testFairUseOutboxRecord("clean-1", 11, 1),
		testFairUseOutboxRecord("clean-2", 22, 2),
		testFairUseOutboxRecord("clean-3", 33, 3),
	}
	for _, record := range added {
		if err := outbox.enqueue(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := outbox.remove(added[0].BatchID); err != nil {
		t.Fatal(err)
	}
	remaining := added[1:]
	running, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePreAppendFairUseOutbox(running); err == nil {
		t.Fatal("running outbox decoded as a single-object file before close; the close check below would prove nothing")
	}
	if err := outbox.close(); err != nil {
		t.Fatal(err)
	}
	closed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines := bytes.Count(closed, []byte("\n")); lines != 1 {
		t.Fatalf("clean close left %d lines, want one base object and no log entries", lines)
	}
	state, err := decodePreAppendFairUseOutbox(closed)
	if err != nil {
		t.Fatalf("pre-append reader refused a cleanly closed outbox: %v", err)
	}
	if !slices.Equal(state.Records, remaining) {
		t.Fatalf("cleanly closed outbox holds %v, want %v", state.Records, remaining)
	}
	reopened := openTestFairUseOutbox(t, path)
	loaded, err := reopened.records()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(loaded, remaining) {
		t.Fatalf("reopened outbox loaded %v, want %v", loaded, remaining)
	}
}

// decodePreAppendFairUseOutbox decodes raw with the rules of the reader
// that predates the append format (commit 94e2d06, readState): one JSON
// object with no duplicate or unknown fields, nothing after it, and version
// 1.
func decodePreAppendFairUseOutbox(raw []byte) (fairUseOutboxState, error) {
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return fairUseOutboxState{}, err
	}
	var state fairUseOutboxState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return fairUseOutboxState{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fairUseOutboxState{}, errors.New("trailing state data")
	}
	if state.Version != 1 || state.Records == nil {
		return fairUseOutboxState{}, errors.New("unsupported state")
	}
	return state, nil
}

// TestFairUseOutboxPartialAppendRecoversWholeRecords models an append that
// stops part-way through an entry, as a short write on a full disk does. The
// failed append must cut the log back to its prior length, and a restart must
// recover every whole record and discard the partial entry, both from that
// rolled-back file and from a crash image captured before the rollback ran.
func TestFairUseOutboxPartialAppendRecoversWholeRecords(t *testing.T) {
	path := testFairUseOutboxPath(t)
	outbox := openTestFairUseOutbox(t, path)
	added := []fairUseOutboxRecord{
		testFairUseOutboxRecord("whole-1", 11, 1),
		testFairUseOutboxRecord("whole-2", 22, 2),
		testFairUseOutboxRecord("whole-3", 33, 3),
	}
	for _, record := range added {
		if err := outbox.enqueue(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := outbox.remove(added[0].BatchID); err != nil {
		t.Fatal(err)
	}
	whole := added[1:]
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var crashImage []byte
	outbox.logWrite = func(file *os.File, payload []byte) (int, error) {
		n, err := file.Write(payload[:len(payload)/2])
		if err != nil {
			return n, err
		}
		crashImage, err = os.ReadFile(path)
		if err != nil {
			return n, err
		}
		return n, syscall.ENOSPC
	}
	if err := outbox.enqueue(testFairUseOutboxRecord("partial", 44, 4)); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("partial append error = %v, want ENOSPC", err)
	}
	if !bytes.HasPrefix(crashImage, before) || len(crashImage) <= len(before) || bytes.HasSuffix(crashImage, []byte("\n")) {
		t.Fatal("write hook did not leave a partial entry on disk")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("failed append left the log at %d bytes, want it cut back to %d", len(after), len(before))
	}
	if err := outbox.close(); err != nil {
		t.Fatal(err)
	}

	crashPath := testFairUseOutboxPath(t)
	if err := os.WriteFile(crashPath, crashImage, 0o600); err != nil {
		t.Fatal(err)
	}
	restarts := []struct {
		name string
		path string
	}{
		{name: "rolled back", path: path},
		{name: "crash image", path: crashPath},
	}
	for _, restart := range restarts {
		restarted := openTestFairUseOutbox(t, restart.path)
		records, err := restarted.records()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(records, whole) {
			t.Fatalf("%s restart recovered %v, want the %d whole records %v", restart.name, records, len(whole), whole)
		}
	}
}

// TestFairUseOutboxMalformedFinalLineFailsClosed confirms that discarding an
// unterminated final entry does not loosen fail-closed decoding: a complete,
// newline-terminated final line that is malformed still refuses to open, and
// so do entry bytes joined to the base object with no newline at all.
func TestFairUseOutboxMalformedFinalLineFailsClosed(t *testing.T) {
	const base = `{"version":1,"records":[]}`
	first := testFairUseOutboxRecord("whole", 1, 1)
	second := testFairUseOutboxRecord("cut", 2, 2)
	whole, err := json.Marshal(fairUseOutboxLogEntry{Op: fairUseOutboxOpAdd, Record: &first})
	if err != nil {
		t.Fatal(err)
	}
	next, err := json.Marshal(fairUseOutboxLogEntry{Op: fairUseOutboxOpAdd, Record: &second})
	if err != nil {
		t.Fatal(err)
	}
	valid := base + "\n" + string(whole) + "\n"
	cut := string(next[:len(next)/2])

	validPath := testFairUseOutboxPath(t)
	if err := os.WriteFile(validPath, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if opened := openTestFairUseOutbox(t, validPath); opened.count() != 1 {
		t.Fatalf("valid fixture opened with %d records, want 1", opened.count())
	}

	cases := []struct {
		name  string
		state string
	}{
		{name: "terminated truncated entry", state: valid + cut + "\n"},
		{name: "unterminated bytes joined to base", state: base + cut},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := testFairUseOutboxPath(t)
			if err := os.WriteFile(path, []byte(tc.state), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := newFileFairUseOutbox(path); err == nil {
				t.Fatal("malformed final line was accepted")
			}
		})
	}
}

type ambiguousDigestStore struct {
	sharedFairUseStore
	digestStore fairUseDigestStore
	calls       atomic.Int64
	batchMu     sync.Mutex
	batchIDs    map[string]struct{}
}

type closeOrderFairUseStore struct {
	countingFairUseStore
	workerDone       <-chan struct{}
	replayDone       <-chan struct{}
	closedBeforeJoin atomic.Bool
}

func (s *closeOrderFairUseStore) Close() error {
	select {
	case <-s.workerDone:
	default:
		s.closedBeforeJoin.Store(true)
	}
	select {
	case <-s.replayDone:
	default:
		s.closedBeforeJoin.Store(true)
	}
	s.closeCalls.Add(1)
	return nil
}

func (s *ambiguousDigestStore) AddDigestAt(ctx context.Context, digest, batchID string, n int64, createdAt time.Time) (int64, error) {
	return s.trackAdd(batchID, func() (int64, error) {
		return s.digestStore.AddDigestAt(ctx, digest, batchID, n, createdAt)
	})
}

func (s *ambiguousDigestStore) Add(ctx context.Context, id, batchID string, n int64) (int64, error) {
	return s.trackAdd(batchID, func() (int64, error) {
		return s.sharedFairUseStore.Add(ctx, id, batchID, n)
	})
}

func (s *ambiguousDigestStore) trackAdd(batchID string, add func() (int64, error)) (int64, error) {
	s.batchMu.Lock()
	if s.batchIDs == nil {
		s.batchIDs = make(map[string]struct{})
	}
	s.batchIDs[batchID] = struct{}{}
	s.batchMu.Unlock()
	total, err := add()
	if err != nil {
		return total, err
	}
	if s.calls.Add(1) == 1 {
		return total, errors.New("ambiguous post-commit failure")
	}
	return total, nil
}

func (s *ambiguousDigestStore) uniqueBatchIDs() int {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	return len(s.batchIDs)
}

func (s *ambiguousDigestStore) Close() error {
	return nil
}

func testFairUseOutboxPath(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "fairuse-outbox.json")
}

func openTestFairUseOutbox(t *testing.T, path string) *fileFairUseOutbox {
	t.Helper()
	outbox, err := newFileFairUseOutbox(path)
	if err != nil {
		t.Fatalf("open fair-use outbox: %v", err)
	}
	t.Cleanup(func() { _ = outbox.close() })
	return outbox
}

func testFairUseOutboxRecord(rawID string, n int64, sequence int) fairUseOutboxRecord {
	now := time.Unix(2_000_000_000, 0)
	return fairUseOutboxRecord{
		TunnelDigest: fairUseTunnelDigest(rawID),
		Bytes:        n,
		BatchID:      fmt.Sprintf("%032x", sequence),
		CreatedAt:    now.Unix(),
		ExpiresAt:    now.Add(24 * time.Hour).Unix(),
	}
}

func assertPrivateMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", filepath.Base(path), got, want)
	}
}

func freeFairUseTestAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}
