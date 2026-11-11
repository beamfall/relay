package cache

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestStoreQuotaIncludesMetadataAndRejectsMetadataGrowth(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	expires := time.Now().Add(time.Hour)
	if err := store.Put("segset", "0001.m4s", Entry{
		Bytes: []byte("payload"), ContentType: "x/a", ExpiresAt: expires,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, err := store.Quota("segset")
	if err != nil {
		t.Fatalf("quota: %v", err)
	}
	onDisk, err := dirSize(store.tenantDir("segset"))
	if err != nil {
		t.Fatalf("committed size: %v", err)
	}
	if before.UsedBytes != onDisk {
		t.Fatalf("quota used = %d, committed bytes = %d", before.UsedBytes, onDisk)
	}
	store.TenantCapBytes = before.UsedBytes
	err = store.Put("segset", "0001.m4s", Entry{
		Bytes: []byte("payload"), ContentType: strings.Repeat("long/", 40), ExpiresAt: expires,
	})
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("metadata-growing overwrite error = %v, want quota exceeded", err)
	}
	after, err := store.Quota("segset")
	if err != nil {
		t.Fatalf("quota after reject: %v", err)
	}
	if after.UsedBytes != before.UsedBytes || after.UsedBytes > after.CapBytes {
		t.Fatalf("quota after reject = %#v, before = %#v", after, before)
	}
	entry, ok, err := store.Get("segset", "0001.m4s")
	if err != nil || !ok || entry.ContentType != "x/a" {
		t.Fatalf("publication after reject: ok=%v entry=%#v err=%v", ok, entry, err)
	}
}

func TestRestartBoundsOversizedUntrustedJournalBeforeAllocation(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.Quota("segset"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	txnDir := filepath.Join(store.tenantDir("segset"), ".txn-"+strings.Repeat("a", 32))
	if err := os.Mkdir(txnDir, 0o700); err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	journalPath := filepath.Join(txnDir, "transaction.json")
	journal, err := os.OpenFile(journalPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create journal: %v", err)
	}
	const sparseSize = int64(1 << 30)
	if err := journal.Truncate(sparseSize); err != nil {
		_ = journal.Close()
		t.Fatalf("truncate journal: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	restarted, err := newStoreWithin(t, root)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if _, err := restarted.readNode(journalPath, maxStructuredNodeBytes); err == nil {
		t.Fatal("oversized journal was accepted")
	}
	info, err := os.Stat(journalPath)
	if err != nil {
		t.Fatalf("stat preserved journal: %v", err)
	}
	if info.Size() != sparseSize {
		t.Fatalf("preserved journal size = %d, want %d", info.Size(), sparseSize)
	}
}

func TestRestartDiscardsPartialStageWithoutTouchingLivePair(t *testing.T) {
	for _, partial := range []string{"missing-metadata", "corrupt-metadata"} {
		t.Run(partial, func(t *testing.T) {
			root := t.TempDir()
			store := seededTransactionStore(t, root)
			tenantDir := store.tenantDir("segset")
			if partial == "missing-metadata" {
				crash := errors.New("crash after staged blob")
				store.leaveFailedTransaction = true
				store.failStep = func(step string) error {
					if step == "after-stage-blob" {
						return crash
					}
					return nil
				}
				err := store.Put("segset", "0001.m4s", testEntry("new", "new/type"))
				if !errors.Is(err, crash) {
					t.Fatalf("put error = %v", err)
				}
			} else {
				meta := mustStoredMeta(t, "0001.m4s", "new", "new/type")
				_, txnDir, err := store.stageTransaction(
					tenantDir, filepath.Base(store.blobPath("segset", "0001.m4s")),
					[]byte("new"), meta, fileDigest([]byte("old")),
					mustFileDigest(t, store.metaPath("segset", "0001.m4s")),
				)
				if err != nil {
					t.Fatalf("stage: %v", err)
				}
				if err := os.WriteFile(filepath.Join(txnDir, "new.json"), []byte("corrupt"), 0o600); err != nil {
					t.Fatalf("corrupt staged metadata: %v", err)
				}
			}
			oldBlob := mustReadFile(t, store.blobPath("segset", "0001.m4s"))
			restarted, err := NewStore(root, testKey, 4096)
			if err != nil {
				t.Fatalf("restart: %v", err)
			}
			if got := mustReadFile(t, restarted.blobPath("segset", "0001.m4s")); string(got) != string(oldBlob) {
				t.Fatalf("live blob changed: %q", got)
			}
			entry, ok, err := restarted.Get("segset", "0001.m4s")
			if err != nil || !ok || string(entry.Bytes) != "old" || entry.ContentType != "old/type" {
				t.Fatalf("old pair: ok=%v entry=%#v err=%v", ok, entry, err)
			}
			assertNoValidTransactions(t, tenantDir)
		})
	}
}

func TestRestartCompletesEveryDurableRenameWindow(t *testing.T) {
	steps := []string{
		"after-backup-blob", "before-sync-backup-metadata",
		"after-publish-blob", "before-sync-publish-metadata",
	}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			root := t.TempDir()
			store := seededTransactionStore(t, root)
			crash := errors.New("simulated crash")
			store.leaveFailedTransaction = true
			store.failStep = func(got string) error {
				if got == step {
					return crash
				}
				return nil
			}
			if err := store.Put("segset", "0001.m4s", testEntry("new", "new/type")); !errors.Is(err, crash) {
				t.Fatalf("put error = %v", err)
			}
			restarted, err := NewStore(root, testKey, 4096)
			if err != nil {
				t.Fatalf("restart: %v", err)
			}
			entry, ok, err := restarted.Get("segset", "0001.m4s")
			if err != nil || !ok || string(entry.Bytes) != "new" || entry.ContentType != "new/type" {
				t.Fatalf("recovered pair: ok=%v entry=%#v err=%v", ok, entry, err)
			}
		})
	}
}

func TestRestartCompletesEveryDurableRollbackWindow(t *testing.T) {
	failpoints := []struct {
		name       string
		step       string
		occurrence int
	}{
		{"journal-before-sync", "before-sync-phase-rolling_back", 1},
		{"journal-after-sync", "after-phase-rolling_back", 1},
		{"blob-restore-before-sync", "before-sync-rollback-restore-old", 1},
		{"blob-restore-after-sync", "after-rollback-restore-old", 1},
		{"metadata-restore-before-sync", "before-sync-rollback-restore-old", 2},
		{"metadata-restore-after-sync", "after-rollback-restore-old", 2},
		{"cleanup-before-remove", "before-cleanup", 1},
		{"cleanup-before-sync", "before-sync-cleanup", 1},
		{"cleanup-after-sync", "after-cleanup", 1},
	}
	for _, failpoint := range failpoints {
		t.Run(failpoint.name, func(t *testing.T) {
			root := t.TempDir()
			store := seededTransactionStore(t, root)
			initialFailure := errors.New("force rollback")
			rollbackCrash := errors.New("crash during rollback")
			rollbackStarted := false
			occurrence := 0
			store.failStep = func(step string) error {
				if !rollbackStarted && step == "after-publish-metadata" {
					rollbackStarted = true
					return initialFailure
				}
				if rollbackStarted && step == failpoint.step {
					occurrence++
					if occurrence == failpoint.occurrence {
						return rollbackCrash
					}
				}
				return nil
			}

			err := store.Put("segset", "0001.m4s", testEntry("new", "new/type"))
			if !errors.Is(err, rollbackCrash) {
				t.Fatalf("put error = %v, want interrupted rollback", err)
			}
			store.failStep = nil
			if err := store.Close(); err != nil {
				t.Fatalf("close interrupted store: %v", err)
			}

			restarted, err := NewStore(root, testKey, 4096)
			if err != nil {
				t.Fatalf("restart: %v", err)
			}
			entry, ok, err := restarted.Get("segset", "0001.m4s")
			if err != nil || !ok || string(entry.Bytes) != "old" || entry.ContentType != "old/type" {
				t.Fatalf("recovered old pair: ok=%v entry=%#v err=%v", ok, entry, err)
			}
			assertNoValidTransactions(t, restarted.tenantDir("segset"))
		})
	}
}

func TestRestartCompletesEveryCreatedArtifactRemovalWindow(t *testing.T) {
	failpoints := []struct {
		name       string
		step       string
		occurrence int
	}{
		{"blob-remove-before-sync", "before-sync-rollback-remove-new", 1},
		{"blob-remove-after-sync", "after-rollback-remove-new", 1},
		{"metadata-remove-before-sync", "before-sync-rollback-remove-new", 2},
		{"metadata-remove-after-sync", "after-rollback-remove-new", 2},
	}
	for _, failpoint := range failpoints {
		t.Run(failpoint.name, func(t *testing.T) {
			root := t.TempDir()
			store, err := NewStore(root, testKey, 4096)
			if err != nil {
				t.Fatalf("new store: %v", err)
			}
			initialFailure := errors.New("force rollback")
			rollbackCrash := errors.New("crash during rollback")
			rollbackStarted := false
			occurrence := 0
			store.failStep = func(step string) error {
				if !rollbackStarted && step == "after-publish-metadata" {
					rollbackStarted = true
					return initialFailure
				}
				if rollbackStarted && step == failpoint.step {
					occurrence++
					if occurrence == failpoint.occurrence {
						return rollbackCrash
					}
				}
				return nil
			}

			err = store.Put("segset", "0001.m4s", testEntry("new", "new/type"))
			if !errors.Is(err, rollbackCrash) {
				t.Fatalf("put error = %v, want interrupted rollback", err)
			}
			store.failStep = nil
			if err := store.Close(); err != nil {
				t.Fatalf("close interrupted store: %v", err)
			}

			restarted, err := NewStore(root, testKey, 4096)
			if err != nil {
				t.Fatalf("restart: %v", err)
			}
			if entry, ok, err := restarted.Get("segset", "0001.m4s"); err != nil || ok {
				t.Fatalf("rolled-back publication: ok=%v entry=%#v err=%v", ok, entry, err)
			}
			quota, err := restarted.Quota("segset")
			if err != nil {
				t.Fatalf("quota: %v", err)
			}
			if quota.UsedBytes != 0 {
				t.Fatalf("used bytes after rollback = %d, want 0", quota.UsedBytes)
			}
			assertNoValidTransactions(t, restarted.tenantDir("segset"))
		})
	}
}

func TestEqualDigestInterruptedRollbackPreservesExistingBlob(t *testing.T) {
	for _, recovery := range []string{"restart", "reconcile"} {
		t.Run(recovery, func(t *testing.T) {
			root := t.TempDir()
			store := seededTransactionStore(t, root)
			tenantDir := store.tenantDir("segset")
			blobPath := store.blobPath("segset", "0001.m4s")
			before, err := os.Stat(blobPath)
			if err != nil {
				t.Fatalf("stat existing blob: %v", err)
			}
			beforeQuota, err := store.Quota("segset")
			if err != nil {
				t.Fatalf("quota before: %v", err)
			}
			initialFailure := errors.New("metadata publication failure")
			rollbackCrash := errors.New("crash after restoring blob")
			rollbackStarted := false
			store.failStep = func(step string) error {
				if !rollbackStarted && step == "before-sync-publish-metadata" {
					rollbackStarted = true
					return initialFailure
				}
				if rollbackStarted && step == "after-rollback-restore-old" {
					return rollbackCrash
				}
				return nil
			}

			err = store.Put("segset", "0001.m4s", testEntry("old", "new/type"))
			if !errors.Is(err, rollbackCrash) {
				t.Fatalf("put error = %v, want interrupted rollback", err)
			}
			store.failStep = nil

			var recovered *Store
			switch recovery {
			case "restart":
				if err := store.Close(); err != nil {
					t.Fatalf("close interrupted store: %v", err)
				}
				recovered, err = NewStore(root, testKey, 4096)
			case "reconcile":
				err = store.reconcileTenant(tenantDir)
				recovered = store
			}
			if err != nil {
				t.Fatalf("%s: %v", recovery, err)
			}
			entry, ok, err := recovered.Get("segset", "0001.m4s")
			if err != nil || !ok || string(entry.Bytes) != "old" || entry.ContentType != "old/type" {
				t.Fatalf("recovered old pair: ok=%v entry=%#v err=%v", ok, entry, err)
			}
			after, err := os.Stat(blobPath)
			if err != nil {
				t.Fatalf("stat recovered blob: %v", err)
			}
			if !os.SameFile(before, after) {
				t.Fatal("recovery replaced the pre-existing equal-digest blob")
			}
			afterQuota, err := recovered.Quota("segset")
			if err != nil {
				t.Fatalf("quota after: %v", err)
			}
			if afterQuota != beforeQuota {
				t.Fatalf("quota after recovery = %#v, want %#v", afterQuota, beforeQuota)
			}
			assertNoValidTransactions(t, tenantDir)
		})
	}
}

func TestCommittedCleanupFailuresArePropagatedAndRecoverable(t *testing.T) {
	for _, step := range []string{"before-cleanup", "before-sync-cleanup"} {
		t.Run(step, func(t *testing.T) {
			root := t.TempDir()
			store := seededTransactionStore(t, root)
			injected := errors.New("cleanup failure")
			store.failStep = func(got string) error {
				if got == step {
					return injected
				}
				return nil
			}
			err := store.Put("segset", "0001.m4s", testEntry("new", "new/type"))
			if !errors.Is(err, injected) || !transactionCommitted(err) {
				t.Fatalf("put error = %v, want committed cleanup failure", err)
			}
			store.failStep = nil
			entry, ok, err := store.Get("segset", "0001.m4s")
			if err != nil || !ok || string(entry.Bytes) != "new" || entry.ContentType != "new/type" {
				t.Fatalf("committed pair: ok=%v entry=%#v err=%v", ok, entry, err)
			}
			restarted, err := NewStore(root, testKey, 4096)
			if err != nil {
				t.Fatalf("restart: %v", err)
			}
			entry, ok, err = restarted.Get("segset", "0001.m4s")
			if err != nil || !ok || string(entry.Bytes) != "new" {
				t.Fatalf("restarted pair: ok=%v entry=%#v err=%v", ok, entry, err)
			}
		})
	}
}

func TestLegacyAndMisfiledMetadataAreEvicted(t *testing.T) {
	t.Run("legacy-empty-digest", func(t *testing.T) {
		store, err := NewStore(t.TempDir(), testKey, 4096)
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		blobPath := store.blobPath("segset", "0001.m4s")
		metaPath := store.metaPath("segset", "0001.m4s")
		if err := os.MkdirAll(filepath.Dir(blobPath), 0o700); err != nil {
			t.Fatalf("tenant dir: %v", err)
		}
		if err := os.WriteFile(blobPath, []byte("legacy"), 0o600); err != nil {
			t.Fatalf("legacy blob: %v", err)
		}
		legacy, _ := json.Marshal(map[string]any{
			"segment": "0001.m4s", "contentType": "legacy/type",
			"expiresAt": time.Now().Add(time.Hour),
		})
		if err := os.WriteFile(metaPath, legacy, 0o600); err != nil {
			t.Fatalf("legacy metadata: %v", err)
		}
		if _, ok, err := store.Get("segset", "0001.m4s"); err != nil || ok {
			t.Fatalf("legacy get: ok=%v err=%v", ok, err)
		}
		assertPathsAbsent(t, blobPath, metaPath)
	})

	t.Run("metadata-at-wrong-derived-name", func(t *testing.T) {
		store, err := NewStore(t.TempDir(), testKey, 4096)
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		if err := store.Put("segset", "0001.m4s", testEntry("one", "one/type")); err != nil {
			t.Fatalf("put one: %v", err)
		}
		if err := store.Put("segset", "0002.m4s", testEntry("two", "two/type")); err != nil {
			t.Fatalf("put two: %v", err)
		}
		wrong := mustStoredMeta(t, "0002.m4s", "one", "wrong/type")
		if err := os.WriteFile(store.metaPath("segset", "0001.m4s"), wrong, 0o600); err != nil {
			t.Fatalf("misfile metadata: %v", err)
		}
		inventory, err := store.Inventory("segset")
		if err != nil {
			t.Fatalf("inventory: %v", err)
		}
		if len(inventory.Entries) != 1 || inventory.Entries[0].Segment != "0002.m4s" {
			t.Fatalf("inventory = %#v", inventory.Entries)
		}
		entry, ok, err := store.Get("segset", "0002.m4s")
		if err != nil || !ok || string(entry.Bytes) != "two" {
			t.Fatalf("unrelated pair: ok=%v entry=%#v err=%v", ok, entry, err)
		}
	})
}

func TestTransactionJournalCannotBeTransplantedAcrossTenants(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Put("tenant-a", "0001.m4s", testEntry("old", "old/type")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tenantA := store.tenantDir("tenant-a")
	tenantB := store.tenantDir("tenant-b")
	if err := os.MkdirAll(tenantB, 0o700); err != nil {
		t.Fatalf("tenant b: %v", err)
	}
	meta := mustStoredMeta(t, "0001.m4s", "new", "new/type")
	_, txnDir, err := store.stageTransaction(
		tenantA, filepath.Base(store.blobPath("tenant-a", "0001.m4s")),
		[]byte("new"), meta, fileDigest([]byte("old")),
		mustFileDigest(t, store.metaPath("tenant-a", "0001.m4s")),
	)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	transplanted := filepath.Join(tenantB, filepath.Base(txnDir))
	if err := os.Rename(txnDir, transplanted); err != nil {
		t.Fatalf("transplant: %v", err)
	}
	restarted, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if _, ok, err := restarted.Get("tenant-b", "0001.m4s"); err != nil || ok {
		t.Fatalf("tenant b publication: ok=%v err=%v", ok, err)
	}
	if _, err := os.Stat(transplanted); err != nil {
		t.Fatalf("untrusted transplanted staging removed: %v", err)
	}
}

func TestTransactionRecoveryRejectsSymlinkNodesWithoutFollowing(t *testing.T) {
	root := t.TempDir()
	store := seededTransactionStore(t, root)
	tenantDir := store.tenantDir("segset")
	meta := mustStoredMeta(t, "0001.m4s", "new", "new/type")
	_, txnDir, err := store.stageTransaction(
		tenantDir, filepath.Base(store.blobPath("segset", "0001.m4s")),
		[]byte("new"), meta, fileDigest([]byte("old")),
		mustFileDigest(t, store.metaPath("segset", "0001.m4s")),
	)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("outside: %v", err)
	}
	if err := os.Remove(filepath.Join(txnDir, "new.json")); err != nil {
		t.Fatalf("remove staged metadata: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(txnDir, "new.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := NewStore(root, testKey, 4096); err == nil {
		t.Fatal("restart accepted symlink staging node")
	}
	if got := string(mustReadFile(t, outside)); got != "outside" {
		t.Fatalf("symlink target changed: %q", got)
	}
	if got := string(mustReadFile(t, store.blobPath("segset", "0001.m4s"))); got != "old" {
		t.Fatalf("live blob changed: %q", got)
	}
}

func TestLiveCacheSpecialNodesReturnWithoutBlockingAndKeepExactQuota(t *testing.T) {
	for _, test := range []struct {
		name   string
		create func(*testing.T, string) func()
	}{
		{name: "fifo", create: makeTestFIFO},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			store := seededTransactionStore(t, root)
			blobPath := store.blobPath("segset", "0001.m4s")
			if err := os.Remove(blobPath); err != nil {
				t.Fatalf("remove live blob: %v", err)
			}
			release := test.create(t, blobPath)
			defer release()

			restarted, err := newStoreWithin(t, root)
			if err != nil {
				t.Fatalf("restart: %v", err)
			}
			before, err := restarted.Quota("segset")
			if err != nil {
				t.Fatalf("quota before: %v", err)
			}
			onDisk, err := dirSize(restarted.tenantDir("segset"))
			if err != nil {
				t.Fatalf("size before: %v", err)
			}
			if before.UsedBytes != onDisk {
				t.Fatalf("quota before = %d, no-follow size = %d", before.UsedBytes, onDisk)
			}

			entry, ok, getErr := getWithin(t, restarted, "segset", "0001.m4s")
			if getErr == nil || ok || len(entry.Bytes) != 0 {
				t.Fatalf("get special node: ok=%v entry=%#v err=%v", ok, entry, getErr)
			}
			putErr := errorWithin(t, func() error {
				return restarted.Put("segset", "0001.m4s", testEntry("replacement", "new/type"))
			})
			if putErr == nil {
				t.Fatal("put replaced a special live node")
			}
			after, err := restarted.Quota("segset")
			if err != nil {
				t.Fatalf("quota after: %v", err)
			}
			afterDisk, err := dirSize(restarted.tenantDir("segset"))
			if err != nil {
				t.Fatalf("size after: %v", err)
			}
			if after.UsedBytes != before.UsedBytes || after.UsedBytes != afterDisk {
				t.Fatalf("quota after = %d, before = %d, no-follow size = %d",
					after.UsedBytes, before.UsedBytes, afterDisk)
			}
			if _, err := os.Lstat(blobPath); err != nil {
				t.Fatalf("special node changed: %v", err)
			}
		})
	}
}

func TestReadNodeRejectsUnixSocketWithoutBlocking(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "beamfall-cache-special-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove temp dir: %v", err)
		}
	})
	socketPath := filepath.Join(root, "cache-node")
	release := makeTestUnixSocket(t, socketPath)
	defer release()

	var node nodeState
	readErr := errorWithin(t, func() error {
		var err error
		node, err = readNode(socketPath)
		return err
	})
	if readErr == nil || node.exists || len(node.body) != 0 {
		t.Fatalf("read socket node = %#v, err=%v", node, readErr)
	}
	if info, err := os.Lstat(socketPath); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket node changed: info=%v err=%v", info, err)
	}
}

func TestTransactionRecoverySpecialNodesReturnWithoutBlocking(t *testing.T) {
	t.Run("root-lock-fifo", func(t *testing.T) {
		root := t.TempDir()
		lockPath := filepath.Join(root, ".cache.lock")
		release := makeTestFIFO(t, lockPath)
		defer release()

		if _, err := newStoreWithin(t, root); err == nil {
			t.Fatal("NewStore accepted FIFO root lock")
		}
		if info, err := os.Lstat(lockPath); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("root lock FIFO changed: info=%v err=%v", info, err)
		}
	})

	t.Run("root-lock-symlink", func(t *testing.T) {
		root := t.TempDir()
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
			t.Fatalf("outside: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(root, ".cache.lock")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := newStoreWithin(t, root); err == nil {
			t.Fatal("NewStore accepted symlink root lock")
		}
		if got := string(mustReadFile(t, outside)); got != "outside" {
			t.Fatalf("root lock target changed: %q", got)
		}
	})

	t.Run("untrusted-journal-fifo", func(t *testing.T) {
		root := t.TempDir()
		store, err := NewStore(root, testKey, 4096)
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		tenantDir := store.tenantDir("segset")
		txnDir := filepath.Join(tenantDir, ".txn-"+strings.Repeat("a", 32))
		if err := os.MkdirAll(txnDir, 0o700); err != nil {
			t.Fatalf("mkdir transaction: %v", err)
		}
		journalPath := filepath.Join(txnDir, "transaction.json")
		release := makeTestFIFO(t, journalPath)
		defer release()

		restarted, err := newStoreWithin(t, root)
		if err != nil {
			t.Fatalf("restart with untrusted journal: %v", err)
		}
		quota, err := restarted.Quota("segset")
		if err != nil {
			t.Fatalf("quota: %v", err)
		}
		onDisk, err := dirSize(tenantDir)
		if err != nil {
			t.Fatalf("size: %v", err)
		}
		if quota.UsedBytes != onDisk {
			t.Fatalf("quota = %d, no-follow size = %d", quota.UsedBytes, onDisk)
		}
		if info, err := os.Lstat(journalPath); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("untrusted journal changed: info=%v err=%v", info, err)
		}
	})

	t.Run("signed-staging-fifo", func(t *testing.T) {
		root := t.TempDir()
		store := seededTransactionStore(t, root)
		tenantDir := store.tenantDir("segset")
		meta := mustStoredMeta(t, "0001.m4s", "new", "new/type")
		_, txnDir, err := store.stageTransaction(
			tenantDir, filepath.Base(store.blobPath("segset", "0001.m4s")),
			[]byte("new"), meta, fileDigest([]byte("old")),
			mustFileDigest(t, store.metaPath("segset", "0001.m4s")),
		)
		if err != nil {
			t.Fatalf("stage: %v", err)
		}
		stagedBlob := filepath.Join(txnDir, "new.bin")
		if err := os.Remove(stagedBlob); err != nil {
			t.Fatalf("remove staged blob: %v", err)
		}
		release := makeTestFIFO(t, stagedBlob)
		defer release()

		if _, err := newStoreWithin(t, root); err == nil {
			t.Fatal("restart accepted FIFO staging node")
		}
		if got := string(mustReadFile(t, store.blobPath("segset", "0001.m4s"))); got != "old" {
			t.Fatalf("live blob changed: %q", got)
		}
		if info, err := os.Lstat(stagedBlob); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("staged FIFO changed: info=%v err=%v", info, err)
		}
	})
}

type storeResult struct {
	store *Store
	err   error
}

func newStoreWithin(t *testing.T, root string) (*Store, error) {
	t.Helper()
	result := make(chan storeResult, 1)
	go func() {
		store, err := NewStore(root, testKey, 4096)
		result <- storeResult{store: store, err: err}
	}()
	select {
	case got := <-result:
		return got.store, got.err
	case <-time.After(2 * time.Second):
		t.Fatal("NewStore blocked on a special cache node")
		return nil, nil
	}
}

type getResult struct {
	entry Entry
	ok    bool
	err   error
}

func getWithin(t *testing.T, store *Store, segmentSetID, segment string) (Entry, bool, error) {
	t.Helper()
	result := make(chan getResult, 1)
	go func() {
		entry, ok, err := store.Get(segmentSetID, segment)
		result <- getResult{entry: entry, ok: ok, err: err}
	}()
	select {
	case got := <-result:
		return got.entry, got.ok, got.err
	case <-time.After(2 * time.Second):
		t.Fatal("Get blocked on a special cache node")
		return Entry{}, false, nil
	}
}

func errorWithin(t *testing.T, call func() error) error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- call() }()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("cache operation blocked on a special node")
		return nil
	}
}

func makeTestFIFO(t *testing.T, path string) func() {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}
	return func() {
		fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = syscall.Close(fd)
		}
	}
}

func makeTestUnixSocket(t *testing.T, path string) func() {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix socket unavailable: %v", err)
	}
	return func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close unix socket: %v", err)
		}
	}
}

func seededTransactionStore(t *testing.T, root string) *Store {
	t.Helper()
	store, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Put("segset", "0001.m4s", testEntry("old", "old/type")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return store
}

func testEntry(body, contentType string) Entry {
	return Entry{Bytes: []byte(body), ContentType: contentType, ExpiresAt: time.Now().Add(time.Hour)}
}

func mustStoredMeta(t *testing.T, segment, body, contentType string) []byte {
	t.Helper()
	meta, err := json.Marshal(storedMeta{
		Segment: segment, ContentType: contentType, ExpiresAt: time.Now().Add(time.Hour),
		BlobSHA256: fileDigest([]byte(body)),
	})
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	return meta
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return body
}

func assertPathsAbsent(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("path still exists %s: %v", path, err)
		}
	}
}
