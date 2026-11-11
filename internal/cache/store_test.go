package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdefghijklmnopqrstuvwxyz")

func TestStoreHashesSegmentSetIDOnDisk(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root, testKey, 1024)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	segmentSetID := "segset_private_123"
	if err := store.Put(segmentSetID, "0001.m4s", Entry{
		Bytes:       []byte("ciphertext"),
		ContentType: "video/mp4",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	foundClearID := false
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(path, segmentSetID) {
			foundClearID = true
		}
		return nil
	}); err != nil {
		t.Fatalf("walk store: %v", err)
	}
	if foundClearID {
		t.Fatal("segmentSetId appeared in durable store path")
	}
	entry, ok, err := store.Get(segmentSetID, "0001.m4s")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if string(entry.Bytes) != "ciphertext" || entry.ContentType != "video/mp4" {
		t.Fatalf("entry = %#v", entry)
	}
}

func TestStoreRejectsOverTenantCap(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey, 4)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	err = store.Put("segset", "0001.m4s", Entry{Bytes: []byte("12345"), ExpiresAt: time.Now().Add(time.Hour)})
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("put err = %v, want quota_exceeded", err)
	}
}

func TestStoreRejectsTenantDirectorySymlinkWithoutTouchingTarget(t *testing.T) {
	operations := []struct {
		name string
		run  func(*Store) error
	}{
		{"get", func(store *Store) error {
			_, _, err := store.Get("segset", "0001.m4s")
			return err
		}},
		{"put", func(store *Store) error {
			return store.Put("segset", "0001.m4s", Entry{
				Bytes: []byte("replacement"), ExpiresAt: time.Now().Add(time.Hour),
			})
		}},
		{"quota", func(store *Store) error {
			_, err := store.Quota("segset")
			return err
		}},
		{"inventory", func(store *Store) error {
			_, err := store.Inventory("segset")
			return err
		}},
		{"delete", func(store *Store) error {
			return store.Delete("segset", "0001.m4s")
		}},
		{"recovery", func(store *Store) error {
			return store.reconcileTenant(store.tenantDir("segset"))
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			store, err := NewStore(t.TempDir(), testKey, 4096)
			if err != nil {
				t.Fatalf("new store: %v", err)
			}
			outside := t.TempDir()
			blobPath := filepath.Join(outside, filepath.Base(store.blobPath("segset", "0001.m4s")))
			metaPath := filepath.Join(outside, filepath.Base(store.metaPath("segset", "0001.m4s")))
			if err := os.WriteFile(blobPath, []byte("outside-blob"), 0o600); err != nil {
				t.Fatalf("write outside blob: %v", err)
			}
			if err := os.WriteFile(metaPath, []byte("outside-meta"), 0o600); err != nil {
				t.Fatalf("write outside metadata: %v", err)
			}
			if err := os.Symlink(outside, store.tenantDir("segset")); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}

			if err := operation.run(store); err == nil {
				t.Fatal("operation accepted symlink tenant directory")
			}
			if got := string(mustReadFile(t, blobPath)); got != "outside-blob" {
				t.Fatalf("outside blob changed: %q", got)
			}
			if got := string(mustReadFile(t, metaPath)); got != "outside-meta" {
				t.Fatalf("outside metadata changed: %q", got)
			}
		})
	}
}

func TestStoreRejectsReplacedRootWithoutTouchingExternalTarget(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "cache")
	store, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Put("segset", "0001.m4s", Entry{
		Bytes: []byte("original"), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tenantName := filepath.Base(store.tenantDir("segset"))
	blobName := filepath.Base(store.blobPath("segset", "0001.m4s"))
	metaName := filepath.Base(store.metaPath("segset", "0001.m4s"))
	parkedRoot := filepath.Join(parent, "parked-cache")
	if err := os.Rename(root, parkedRoot); err != nil {
		t.Fatalf("park root: %v", err)
	}
	outside := t.TempDir()
	outsideTenant := filepath.Join(outside, tenantName)
	if err := os.Mkdir(outsideTenant, 0o700); err != nil {
		t.Fatalf("create outside tenant: %v", err)
	}
	outsideBlob := filepath.Join(outsideTenant, blobName)
	outsideMeta := filepath.Join(outsideTenant, metaName)
	if err := os.WriteFile(outsideBlob, []byte("outside-blob"), 0o600); err != nil {
		t.Fatalf("write outside blob: %v", err)
	}
	if err := os.WriteFile(outsideMeta, []byte("outside-meta"), 0o600); err != nil {
		t.Fatalf("write outside metadata: %v", err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if err := store.Delete("segset", "0001.m4s"); err == nil {
		t.Fatal("Delete accepted replaced cache root")
	}
	if got := string(mustReadFile(t, outsideBlob)); got != "outside-blob" {
		t.Fatalf("outside blob changed: %q", got)
	}
	if got := string(mustReadFile(t, outsideMeta)); got != "outside-meta" {
		t.Fatalf("outside metadata changed: %q", got)
	}
	if got := string(mustReadFile(t, filepath.Join(parkedRoot, tenantName, blobName))); got != "original" {
		t.Fatalf("pinned-root blob changed: %q", got)
	}
}

func TestStoreQuotaCountsPreservedUntrustedTransactionBytes(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey, 1000)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.Quota("segset"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	txnDir := filepath.Join(store.tenantDir("segset"), ".txn-untrusted")
	if err := os.Mkdir(txnDir, 0o700); err != nil {
		t.Fatalf("create untrusted transaction: %v", err)
	}
	stagedPath := filepath.Join(txnDir, "new.bin")
	if err := os.WriteFile(stagedPath, []byte(strings.Repeat("x", 2000)), 0o600); err != nil {
		t.Fatalf("write untrusted staging: %v", err)
	}

	err = store.Put("segset", "0001.m4s", Entry{
		Bytes: []byte("x"), ExpiresAt: time.Now().Add(time.Hour),
	})
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("put error = %v, want quota_exceeded", err)
	}
	if got := len(mustReadFile(t, stagedPath)); got != 2000 {
		t.Fatalf("preserved staging bytes = %d, want 2000", got)
	}
}

func TestStoreQuotaRejectDoesNotEvictExistingSegment(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey, 512)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	expires := time.Now().Add(time.Hour)
	if err := store.Put("segset", "0001.m4s", Entry{Bytes: []byte("keep"), ExpiresAt: expires}); err != nil {
		t.Fatalf("put existing: %v", err)
	}
	err = store.Put("segset", "0002.m4s", Entry{Bytes: []byte(strings.Repeat("x", 1024)), ExpiresAt: expires})
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("put err = %v, want quota_exceeded", err)
	}
	entry, ok, err := store.Get("segset", "0001.m4s")
	if err != nil || !ok {
		t.Fatalf("get existing: ok=%v err=%v", ok, err)
	}
	if string(entry.Bytes) != "keep" {
		t.Fatalf("existing bytes = %q", entry.Bytes)
	}
}

func TestStoreConcurrentPutsReserveQuotaAtomically(t *testing.T) {
	const capBytes = 1500
	store, err := NewStore(t.TempDir(), testKey, capBytes)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	entry := Entry{Bytes: []byte(strings.Repeat("x", 400)), ExpiresAt: time.Now().Add(time.Hour)}
	start := make(chan struct{})
	results := make(chan error, 12)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- store.Put("segset", fmt.Sprintf("%04d.m4s", i), entry)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("put error = %v, want quota rejection", err)
		}
	}
	inventory, err := store.Inventory("segset")
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	var publishedBytes int64
	for _, item := range inventory.Entries {
		publishedBytes += item.Bytes
	}
	if len(inventory.Entries) != succeeded {
		t.Fatalf("published entries = %d, successful puts = %d", len(inventory.Entries), succeeded)
	}
	if publishedBytes > capBytes {
		t.Fatalf("published payload = %d, cap = %d", publishedBytes, capBytes)
	}
	quota, err := store.Quota("segset")
	if err != nil {
		t.Fatalf("quota: %v", err)
	}
	onDisk, err := dirSize(store.tenantDir("segset"))
	if err != nil {
		t.Fatalf("committed size: %v", err)
	}
	if quota.UsedBytes != onDisk || quota.UsedBytes > quota.CapBytes {
		t.Fatalf("quota = %#v, committed bytes = %d", quota, onDisk)
	}
}

func TestStoreSharedRootPutsSerializeQuota(t *testing.T) {
	const capBytes = 1000
	root := t.TempDir()
	first, err := NewStore(root, testKey, capBytes)
	if err != nil {
		t.Fatalf("first store: %v", err)
	}
	second, err := NewStore(root, testKey, capBytes)
	if err != nil {
		t.Fatalf("second store: %v", err)
	}
	firstBlocked := make(chan struct{})
	releaseFirst := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(releaseFirst)
		}
	}()
	first.failStep = func(step string) error {
		if step == "before-sync-create-transaction" {
			close(firstBlocked)
			<-releaseFirst
		}
		return nil
	}
	entry := Entry{
		Bytes:     []byte(strings.Repeat("x", 600)),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	firstResult := make(chan error, 1)
	go func() { firstResult <- first.Put("segset", "0001.m4s", entry) }()
	select {
	case <-firstBlocked:
	case <-time.After(2 * time.Second):
		t.Fatal("first Store did not reach post-quota staging")
	}

	secondStarted := make(chan struct{})
	secondResult := make(chan error, 1)
	go func() {
		close(secondStarted)
		secondResult <- second.Put("segset", "0002.m4s", entry)
	}()
	<-secondStarted
	select {
	case err := <-secondResult:
		t.Fatalf("second Store crossed the shared-root fence early: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	released = true

	firstErr := <-firstResult
	secondErr := <-secondResult
	if firstErr != nil {
		t.Fatalf("first put: %v", firstErr)
	}
	if !errors.Is(secondErr, ErrQuotaExceeded) {
		t.Fatalf("second put = %v, want quota_exceeded", secondErr)
	}
	onDisk, err := dirSize(first.tenantDir("segset"))
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if onDisk > capBytes {
		t.Fatalf("shared-root publication used %d bytes, cap = %d", onDisk, capBytes)
	}
	inventory, err := second.Inventory("segset")
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inventory.Entries) != 1 || inventory.Entries[0].Segment != "0001.m4s" ||
		inventory.Quota.UsedBytes != onDisk {
		t.Fatalf("inventory = %#v, on-disk = %d", inventory, onDisk)
	}
}

func TestStoreSharedRootGetWaitsForPublication(t *testing.T) {
	root := t.TempDir()
	publisher, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("publisher store: %v", err)
	}
	reader, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("reader store: %v", err)
	}
	expires := time.Now().Add(time.Hour)
	if err := publisher.Put("segset", "0001.m4s", Entry{
		Bytes: []byte("old"), ContentType: "old/type", ExpiresAt: expires,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	backupBlocked := make(chan struct{})
	releaseBackup := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(releaseBackup)
		}
	}()
	publisher.failStep = func(step string) error {
		if step == "after-backup-blob" {
			close(backupBlocked)
			<-releaseBackup
		}
		return nil
	}
	publishResult := make(chan error, 1)
	go func() {
		publishResult <- publisher.Put("segset", "0001.m4s", Entry{
			Bytes: []byte("new"), ContentType: "new/type", ExpiresAt: expires,
		})
	}()
	select {
	case <-backupBlocked:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher did not reach the blob-backup window")
	}

	type readResult struct {
		entry Entry
		ok    bool
		err   error
	}
	readerStarted := make(chan struct{})
	readerResult := make(chan readResult, 1)
	go func() {
		close(readerStarted)
		entry, ok, err := reader.Get("segset", "0001.m4s")
		readerResult <- readResult{entry: entry, ok: ok, err: err}
	}()
	<-readerStarted
	select {
	case result := <-readerResult:
		t.Fatalf("second Store observed the backup window: %#v", result)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseBackup)
	released = true

	if err := <-publishResult; err != nil {
		t.Fatalf("publish after backup window: %v", err)
	}
	result := <-readerResult
	if result.err != nil || !result.ok || string(result.entry.Bytes) != "new" ||
		result.entry.ContentType != "new/type" {
		t.Fatalf("reader result = %#v", result)
	}
}

func TestStorePublishFailuresRollBackWithoutReservationLeak(t *testing.T) {
	steps := []string{
		"before-sync-stage-blob", "before-sync-stage-metadata", "after-backup-blob",
		"after-backup-metadata", "after-publish-blob", "after-publish-metadata",
	}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			store, err := NewStore(t.TempDir(), testKey, 4096)
			if err != nil {
				t.Fatalf("new store: %v", err)
			}
			expires := time.Now().Add(time.Hour)
			if err := store.Put("segset", "0001.m4s", Entry{
				Bytes: []byte("old"), ContentType: "old/type", ExpiresAt: expires,
			}); err != nil {
				t.Fatalf("seed: %v", err)
			}
			before, err := store.Quota("segset")
			if err != nil {
				t.Fatalf("quota before: %v", err)
			}
			injected := errors.New("injected failure")
			store.failStep = func(got string) error {
				if got == step {
					return injected
				}
				return nil
			}
			err = store.Put("segset", "0001.m4s", Entry{
				Bytes: []byte("new"), ContentType: "new/type", ExpiresAt: expires,
			})
			if !errors.Is(err, injected) {
				t.Fatalf("put error = %v, want injected failure", err)
			}
			store.failStep = nil
			entry, ok, err := store.Get("segset", "0001.m4s")
			if err != nil || !ok {
				t.Fatalf("get old entry: ok=%v err=%v", ok, err)
			}
			if string(entry.Bytes) != "old" || entry.ContentType != "old/type" {
				t.Fatalf("entry after rollback = %#v", entry)
			}
			after, err := store.Quota("segset")
			if err != nil {
				t.Fatalf("quota after: %v", err)
			}
			if after != before {
				t.Fatalf("quota after failure = %#v, want %#v", after, before)
			}
			assertNoValidTransactions(t, store.tenantDir("segset"))
		})
	}
}

func TestStoreEqualDigestMetadataFailurePreservesExistingPublication(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey, 4096)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	expires := time.Now().Add(time.Hour)
	if err := store.Put("segset", "0001.m4s", Entry{
		Bytes: []byte("same"), ContentType: "old/type", ExpiresAt: expires,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	blobPath := store.blobPath("segset", "0001.m4s")
	existingBlob, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("stat existing blob: %v", err)
	}
	before, err := store.Quota("segset")
	if err != nil {
		t.Fatalf("quota before: %v", err)
	}
	injected := errors.New("metadata publication failure")
	store.failStep = func(step string) error {
		if step == "before-sync-publish-metadata" {
			return injected
		}
		return nil
	}
	err = store.Put("segset", "0001.m4s", Entry{
		Bytes: []byte("same"), ContentType: "new/type", ExpiresAt: expires,
	})
	if !errors.Is(err, injected) {
		t.Fatalf("put error = %v, want metadata publication failure", err)
	}
	store.failStep = nil

	entry, ok, err := store.Get("segset", "0001.m4s")
	if err != nil || !ok || string(entry.Bytes) != "same" || entry.ContentType != "old/type" {
		t.Fatalf("publication after rollback: ok=%v entry=%#v err=%v", ok, entry, err)
	}
	rolledBackBlob, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("stat rolled-back blob: %v", err)
	}
	if !os.SameFile(existingBlob, rolledBackBlob) {
		t.Fatal("rollback replaced the pre-existing equal-digest blob")
	}
	after, err := store.Quota("segset")
	if err != nil {
		t.Fatalf("quota after: %v", err)
	}
	if after != before {
		t.Fatalf("quota after failure = %#v, want %#v", after, before)
	}
	assertNoValidTransactions(t, store.tenantDir("segset"))
}

func TestStoreRestartCompletesProvenanceMatchedCrashWindows(t *testing.T) {
	for _, step := range []string{"after-backup-metadata", "after-publish-blob", "after-publish-metadata"} {
		t.Run(step, func(t *testing.T) {
			root := t.TempDir()
			store, err := NewStore(root, testKey, 4096)
			if err != nil {
				t.Fatalf("new store: %v", err)
			}
			expires := time.Now().Add(time.Hour)
			if err := store.Put("segset", "0001.m4s", Entry{
				Bytes: []byte("old"), ContentType: "old/type", ExpiresAt: expires,
			}); err != nil {
				t.Fatalf("seed: %v", err)
			}
			crash := errors.New("simulated crash")
			store.leaveFailedTransaction = true
			store.failStep = func(got string) error {
				if got == step {
					return crash
				}
				return nil
			}
			if err := store.Put("segset", "0001.m4s", Entry{
				Bytes: []byte("new"), ContentType: "new/type", ExpiresAt: expires,
			}); !errors.Is(err, crash) {
				t.Fatalf("put error = %v, want simulated crash", err)
			}

			restarted, err := NewStore(root, testKey, 4096)
			if err != nil {
				t.Fatalf("restart store: %v", err)
			}
			entry, ok, err := restarted.Get("segset", "0001.m4s")
			if err != nil || !ok {
				t.Fatalf("get recovered entry: ok=%v err=%v", ok, err)
			}
			if string(entry.Bytes) != "new" || entry.ContentType != "new/type" {
				t.Fatalf("recovered entry = %#v", entry)
			}
			assertNoValidTransactions(t, restarted.tenantDir("segset"))
		})
	}
}

func TestStoreRestartPreservesUntrustedStagingAndRejectsStaleTransaction(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	expires := time.Now().Add(time.Hour)
	if err := store.Put("segset", "0001.m4s", Entry{
		Bytes: []byte("old"), ContentType: "old/type", ExpiresAt: expires,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tenantDir := store.tenantDir("segset")
	invalidID := strings.Repeat("a", 32)
	invalidDir := filepath.Join(tenantDir, ".txn-"+invalidID)
	if err := os.Mkdir(invalidDir, 0o700); err != nil {
		t.Fatalf("mkdir invalid transaction: %v", err)
	}
	invalidJournal, err := json.Marshal(cacheTxn{
		ID: invalidID, SegmentHash: strings.Repeat("b", 64), MAC: "not-authentic",
	})
	if err != nil {
		t.Fatalf("marshal invalid journal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(invalidDir, "transaction.json"), invalidJournal, 0o600); err != nil {
		t.Fatalf("write invalid journal: %v", err)
	}

	nextMeta, err := json.Marshal(storedMeta{
		Segment: "0001.m4s", ContentType: "next/type", ExpiresAt: expires,
		BlobSHA256: fileDigest([]byte("next")),
	})
	if err != nil {
		t.Fatalf("marshal next metadata: %v", err)
	}
	_, staleDir, err := store.stageTransaction(
		tenantDir, filepath.Base(store.blobPath("segset", "0001.m4s")),
		[]byte("next"), nextMeta, fileDigest([]byte("old")),
		mustFileDigest(t, store.metaPath("segset", "0001.m4s")),
	)
	if err != nil {
		t.Fatalf("stage stale transaction: %v", err)
	}
	later := []byte("later")
	laterMeta, err := json.Marshal(storedMeta{
		Segment: "0001.m4s", ContentType: "later/type", ExpiresAt: expires,
		BlobSHA256: fileDigest(later),
	})
	if err != nil {
		t.Fatalf("marshal later metadata: %v", err)
	}
	if err := os.WriteFile(store.blobPath("segset", "0001.m4s"), later, 0o600); err != nil {
		t.Fatalf("write later blob: %v", err)
	}
	if err := os.WriteFile(store.metaPath("segset", "0001.m4s"), laterMeta, 0o600); err != nil {
		t.Fatalf("write later metadata: %v", err)
	}

	restarted, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("restart store: %v", err)
	}
	if _, err := os.Stat(invalidDir); err != nil {
		t.Fatalf("untrusted staging was removed: %v", err)
	}
	if _, err := os.Stat(staleDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("provenance-matched stale staging remains: %v", err)
	}
	entry, ok, err := restarted.Get("segset", "0001.m4s")
	if err != nil || !ok || string(entry.Bytes) != "later" || entry.ContentType != "later/type" {
		t.Fatalf("later publication changed: ok=%v entry=%#v err=%v", ok, entry, err)
	}
}

func TestStoreNeverReturnsMetadataForDifferentBlob(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey, 4096)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Put("segset", "0001.m4s", Entry{
		Bytes: []byte("expected"), ContentType: "video/mp4", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := os.WriteFile(store.blobPath("segset", "0001.m4s"), []byte("different"), 0o600); err != nil {
		t.Fatalf("replace blob: %v", err)
	}
	if _, ok, err := store.Get("segset", "0001.m4s"); err != nil || ok {
		t.Fatalf("get mismatched pair: ok=%v err=%v", ok, err)
	}
	if _, err := os.Stat(store.blobPath("segset", "0001.m4s")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched blob not evicted: %v", err)
	}
	if _, err := os.Stat(store.metaPath("segset", "0001.m4s")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched metadata not evicted: %v", err)
	}
}

func TestStoreConcurrentReadersSeeOnlyExactPublications(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey, 1<<20)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	expires := time.Now().Add(time.Hour)
	publications := []Entry{
		{Bytes: []byte("alpha"), ContentType: "test/alpha", ExpiresAt: expires},
		{Bytes: []byte("bravo"), ContentType: "test/bravo", ExpiresAt: expires},
	}
	if err := store.Put("segset", "0001.m4s", publications[0]); err != nil {
		t.Fatalf("seed: %v", err)
	}
	start := make(chan struct{})
	errs := make(chan error, 4)
	var wg sync.WaitGroup
	for writer := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := range 50 {
				if err := store.Put("segset", "0001.m4s", publications[(i+writer)%2]); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 200 {
				entry, ok, err := store.Get("segset", "0001.m4s")
				if err != nil || !ok {
					errs <- fmt.Errorf("get exact publication: ok=%v err=%w", ok, err)
					return
				}
				if (string(entry.Bytes) == "alpha" && entry.ContentType != "test/alpha") ||
					(string(entry.Bytes) == "bravo" && entry.ContentType != "test/bravo") ||
					(string(entry.Bytes) != "alpha" && string(entry.Bytes) != "bravo") {
					errs <- fmt.Errorf("mixed publication: %#v", entry)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func assertNoValidTransactions(t *testing.T, tenantDir string) {
	t.Helper()
	entries, err := os.ReadDir(tenantDir)
	if err != nil {
		t.Fatalf("read tenant dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".txn-") {
			t.Fatalf("transaction residue remains: %s", entry.Name())
		}
	}
}

func mustFileDigest(t *testing.T, path string) string {
	t.Helper()
	_, digest, err := fileState(path)
	if err != nil {
		t.Fatalf("digest %s: %v", path, err)
	}
	return digest
}

func TestExpiredEntryIsMissAndRemoved(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	store, err := NewStore(t.TempDir(), testKey, 1024)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	store.now = func() time.Time { return now }
	if err := store.Put("segset", "0001.m4s", Entry{Bytes: []byte("x"), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("put: %v", err)
	}
	store.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, ok, err := store.Get("segset", "0001.m4s"); err != nil || ok {
		t.Fatalf("expired get: ok=%v err=%v, want miss", ok, err)
	}
}

func TestInventoryReflectsTTLExpiry(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	store, err := NewStore(t.TempDir(), testKey, 1024)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	store.now = func() time.Time { return now }
	if err := store.Put("segset", "old.m4s", Entry{Bytes: []byte("old"), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("put old: %v", err)
	}
	if err := store.Put("segset", "new.m4s", Entry{Bytes: []byte("new"), ExpiresAt: now.Add(3 * time.Hour)}); err != nil {
		t.Fatalf("put new: %v", err)
	}
	store.now = func() time.Time { return now.Add(2 * time.Hour) }
	inv, err := store.Inventory("segset")
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inv.Entries) != 1 || inv.Entries[0].Segment != "new.m4s" {
		t.Fatalf("inventory entries = %#v, want only new.m4s", inv.Entries)
	}
	if _, ok, err := store.Get("segset", "old.m4s"); err != nil || ok {
		t.Fatalf("expired get: ok=%v err=%v, want miss", ok, err)
	}
}

// TestSweepExpiredReapsWithoutAnyRead proves the amortized sweep (the same
// function maybeSweep schedules off the Put hot path) reclaims an expired
// entry with no Get/Inventory call ever touching that tenant - the case the
// push-ack O(1) fix must not regress: a cold tenant that stops being read.
func TestSweepExpiredReapsWithoutAnyRead(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	store, err := NewStore(t.TempDir(), testKey, 1024)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	store.now = func() time.Time { return now }
	if err := store.Put("cold", "0001.m4s", Entry{Bytes: []byte("x"), ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("put: %v", err)
	}
	blobPath := store.blobPath("cold", "0001.m4s")
	metaPath := store.metaPath("cold", "0001.m4s")
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatalf("blob missing before sweep: %v", err)
	}

	store.sweepExpired(now.Add(time.Hour))

	if _, err := os.Stat(blobPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired blob not reaped: err=%v", err)
	}
	if _, err := os.Stat(metaPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired meta not reaped: err=%v", err)
	}
	quota, err := store.Quota("cold")
	if err != nil {
		t.Fatalf("quota: %v", err)
	}
	if quota.UsedBytes != 0 {
		t.Fatalf("used bytes after reap = %d, want 0", quota.UsedBytes)
	}
}

func TestSweepExpiredNeverFollowsSymlinkNodesAndKeepsExactQuota(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		linkBlob   bool
		targetBody []byte
	}{
		{
			name: "metadata",
			targetBody: []byte(`{"segment":"0001.m4s","contentType":"video/mp4",` +
				`"expiresAt":"2026-07-24T12:01:00Z","blobSha256":"untrusted"}`),
		},
		{name: "blob", linkBlob: true, targetBody: []byte(strings.Repeat("outside", 256))},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			store, err := NewStore(root, testKey, 1<<20)
			if err != nil {
				t.Fatalf("new store: %v", err)
			}
			store.now = func() time.Time { return now }
			if err := store.Put("cold", "0001.m4s", Entry{
				Bytes: []byte("cached"), ExpiresAt: now.Add(time.Minute),
			}); err != nil {
				t.Fatalf("put: %v", err)
			}
			blobPath := store.blobPath("cold", "0001.m4s")
			metaPath := store.metaPath("cold", "0001.m4s")
			linkPath := metaPath
			if test.linkBlob {
				linkPath = blobPath
			}
			if err := os.Remove(linkPath); err != nil {
				t.Fatalf("remove cache node: %v", err)
			}
			targetPath := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(targetPath, test.targetBody, 0o600); err != nil {
				t.Fatalf("write external target: %v", err)
			}
			if err := os.Symlink(targetPath, linkPath); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}

			// Restart so quota is rebuilt from the actual link node. A Stat
			// mutation follows targetPath here and makes this assertion fail.
			store, err = NewStore(root, testKey, 1<<20)
			if err != nil {
				t.Fatalf("restart store: %v", err)
			}
			store.now = func() time.Time { return now }
			before, err := store.Quota("cold")
			if err != nil {
				t.Fatalf("quota before sweep: %v", err)
			}
			beforeDisk, err := dirSize(store.tenantDir("cold"))
			if err != nil {
				t.Fatalf("size before sweep: %v", err)
			}
			blobInfo, err := os.Lstat(blobPath)
			if err != nil {
				t.Fatalf("lstat blob before sweep: %v", err)
			}
			metaInfo, err := os.Lstat(metaPath)
			if err != nil {
				t.Fatalf("lstat metadata before sweep: %v", err)
			}
			wantBefore := blobInfo.Size() + metaInfo.Size()
			if before.UsedBytes != beforeDisk || before.UsedBytes != wantBefore {
				t.Fatalf("quota before sweep = %d, dir size = %d, lstat size = %d",
					before.UsedBytes, beforeDisk, wantBefore)
			}

			store.sweepExpired(now.Add(time.Hour))

			if _, err := os.Lstat(linkPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("untrusted cache link still present: %v", err)
			}
			gotTarget, err := os.ReadFile(targetPath)
			if err != nil {
				t.Fatalf("read external target: %v", err)
			}
			if string(gotTarget) != string(test.targetBody) {
				t.Fatal("external target changed")
			}
			after, err := store.Quota("cold")
			if err != nil {
				t.Fatalf("quota after sweep: %v", err)
			}
			afterDisk, err := dirSize(store.tenantDir("cold"))
			if err != nil {
				t.Fatalf("size after sweep: %v", err)
			}
			peerPath := blobPath
			if test.linkBlob {
				peerPath = metaPath
			}
			peerInfo, err := os.Lstat(peerPath)
			if err != nil {
				t.Fatalf("lstat surviving peer: %v", err)
			}
			if after.UsedBytes != afterDisk || after.UsedBytes != peerInfo.Size() ||
				after.UsedBytes >= before.UsedBytes {
				t.Fatalf("quota after sweep = %d, dir size = %d, peer size = %d, before = %d",
					after.UsedBytes, afterDisk, peerInfo.Size(), before.UsedBytes)
			}

			// The surviving regular peer remains charged; a stale subtraction
			// of target bytes would admit this intentionally over-cap put.
			store.TenantCapBytes = after.UsedBytes
			err = store.Put("cold", "0002.m4s", Entry{
				Bytes: []byte("x"), ExpiresAt: now.Add(2 * time.Hour),
			})
			if !errors.Is(err, ErrQuotaExceeded) {
				t.Fatalf("post-sweep put error = %v, want quota_exceeded", err)
			}
		})
	}
}

// TestAmortizedSweepReclaimsColdTenantNeverRead proves the full wiring: Put
// traffic on one tenant ("hot") crosses the SweepEvery threshold and triggers
// an async sweep that reclaims an expired entry on a DIFFERENT tenant
// ("cold") that received exactly one push and was never read, pushed to, or
// inventoried again. This is the cold-tenant case the ticket calls out - ack
// no longer calls Inventory, so nothing else would ever reap "cold".
func TestAmortizedSweepReclaimsColdTenantNeverRead(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	store, err := NewStore(t.TempDir(), testKey, 1<<20)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	store.now = func() time.Time { return now }
	store.SweepEvery = 3
	store.sweepDone = make(chan struct{}, 1)

	if err := store.Put("cold", "0001.m4s", Entry{Bytes: []byte("x"), ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("put cold: %v", err)
	}
	coldBlob := store.blobPath("cold", "0001.m4s")
	coldMeta := store.metaPath("cold", "0001.m4s")

	store.now = func() time.Time { return now.Add(time.Hour) }
	for i := range 3 {
		seg := fmt.Sprintf("%04d.m4s", i)
		if err := store.Put("hot", seg, Entry{Bytes: []byte("y"), ExpiresAt: now.Add(2 * time.Hour)}); err != nil {
			t.Fatalf("put hot %d: %v", i, err)
		}
	}

	select {
	case <-store.sweepDone:
	case <-time.After(2 * time.Second):
		t.Fatal("amortized sweep did not run within 2s of crossing SweepEvery")
	}

	if _, err := os.Stat(coldBlob); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cold tenant blob still present after amortized sweep: err=%v", err)
	}
	if _, err := os.Stat(coldMeta); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cold tenant meta still present after amortized sweep: err=%v", err)
	}
}
