package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const DefaultTenantCapBytes int64 = 25 * 1024 * 1024 * 1024

// defaultSweepEvery is how many Store.Put calls (across all tenants) elapse
// between amortized expiry sweeps when SweepEvery is unset.
const defaultSweepEvery = 64

var ErrQuotaExceeded = errors.New("quota_exceeded")
var ErrStoreClosed = errors.New("cache store is closed")

type Store struct {
	Root           string
	Key            []byte
	TenantCapBytes int64
	now            func() time.Time
	rootDir        *os.File
	rootInfo       os.FileInfo

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex
	usage   *sharedUsageCache

	lifecycleMu sync.Mutex
	operations  sync.WaitGroup
	closing     bool
	closeOnce   sync.Once
	closeErr    error

	// SweepEvery overrides how many Put calls between amortized expiry
	// sweeps (see maybeSweep); <= 0 uses defaultSweepEvery. Exposed so tests
	// can force sweeps to trigger quickly without waiting on real traffic
	// volume.
	SweepEvery int64
	putCount   atomic.Int64
	sweeping   atomic.Bool
	// sweepDone, if non-nil, receives a signal after each amortized sweep
	// finishes. Only ever set by tests in this package to await the async
	// sweep deterministically.
	sweepDone chan struct{}

	// failStep and leaveFailedTransaction are test-only fault injection.
	failStep               func(string) error
	leaveFailedTransaction bool
}

type Entry struct {
	Bytes       []byte
	ContentType string
	ExpiresAt   time.Time
}

type QuotaState struct {
	UsedBytes int64
	CapBytes  int64
}

type InventoryEntry struct {
	Segment     string
	Bytes       int64
	ContentType string
	ExpiresAt   time.Time
}

type Inventory struct {
	Entries []InventoryEntry
	Quota   QuotaState
}

func NewStore(root string, key []byte, tenantCapBytes int64) (*Store, error) {
	if root == "" {
		return nil, errors.New("cache store dir is required")
	}
	if err := ValidateTokenKey(key); err != nil {
		return nil, err
	}
	if tenantCapBytes <= 0 {
		capBytes, err := DefaultTenantCap(root)
		if err != nil {
			return nil, err
		}
		tenantCapBytes = capBytes
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create cache store: %w", err)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve cache store: %w", err)
	}
	physicalRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve cache store: %w", err)
	}
	rootDir, err := openVerifiedDirectory(physicalRoot)
	if err != nil {
		return nil, fmt.Errorf("pin cache store: %w", err)
	}
	usage, _ := usageCaches.LoadOrStore(physicalRoot, &sharedUsageCache{})
	store := &Store{
		Root: physicalRoot, Key: key, TenantCapBytes: tenantCapBytes,
		usage: usage.(*sharedUsageCache), rootDir: rootDir.file, rootInfo: rootDir.info,
	}
	rootDir.file = nil
	runtime.SetFinalizer(store, func(store *Store) {
		_ = store.Close()
	})
	rootLock, err := store.lockRoot()
	if err != nil {
		runtime.SetFinalizer(store, nil)
		_ = store.rootDir.Close()
		return nil, err
	}
	defer unlockRoot(rootLock)
	store.resetUsage()
	if err := store.reconcileTransactions(); err != nil {
		runtime.SetFinalizer(store, nil)
		_ = store.rootDir.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) beginOperation() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.closing {
		return ErrStoreClosed
	}
	s.operations.Add(1)
	return nil
}

func (s *Store) endOperation() {
	s.operations.Done()
}

// Close prevents new work, waits for in-flight operations and asynchronous
// sweeps, then releases the lifetime-pinned root descriptor.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.lifecycleMu.Lock()
		s.closing = true
		s.lifecycleMu.Unlock()
		s.operations.Wait()
		runtime.SetFinalizer(s, nil)
		s.closeErr = s.rootDir.Close()
	})
	return s.closeErr
}

func DefaultTenantCap(root string) (int64, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return 0, fmt.Errorf("create cache store: %w", err)
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(root, &stat); err != nil {
		return 0, fmt.Errorf("stat cache store filesystem: %w", err)
	}
	free := int64(stat.Bavail) * int64(stat.Bsize) / 10
	if free < DefaultTenantCapBytes {
		return free, nil
	}
	return DefaultTenantCapBytes, nil
}

func (s *Store) Get(segmentSetID, segment string) (Entry, bool, error) {
	if err := s.beginOperation(); err != nil {
		return Entry{}, false, err
	}
	defer s.endOperation()
	if err := validateSegmentSetID(segmentSetID); err != nil {
		return Entry{}, false, err
	}
	if err := validateSegmentName(segment); err != nil {
		return Entry{}, false, err
	}
	tenantDir := s.tenantDir(segmentSetID)
	lock := s.tenantLock(tenantDir)
	lock.Lock()
	defer lock.Unlock()
	rootLock, err := s.lockRoot()
	if err != nil {
		return Entry{}, false, err
	}
	defer unlockRoot(rootLock)
	tenant, err := s.openTenantDir(tenantDir, true)
	if err != nil {
		return Entry{}, false, err
	}
	defer tenant.close()
	if err := s.reconcileTenant(tenantDir); err != nil {
		return Entry{}, false, err
	}
	if err := tenant.verify(); err != nil {
		return Entry{}, false, err
	}
	meta, err := s.readStoredMeta(s.metaPath(segmentSetID, segment))
	if errors.Is(err, os.ErrNotExist) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, err
	}
	if meta.Segment != segment || meta.BlobSHA256 == "" {
		if err := s.deleteLocked(segmentSetID, segment); err != nil {
			return Entry{}, false, err
		}
		return Entry{}, false, nil
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	if !meta.ExpiresAt.After(now()) {
		if err := s.deleteLocked(segmentSetID, segment); err != nil {
			return Entry{}, false, err
		}
		return Entry{}, false, nil
	}
	blob, err := s.readNode(s.blobPath(segmentSetID, segment), s.TenantCapBytes)
	if err != nil {
		return Entry{}, false, fmt.Errorf("read cache segment: %w", err)
	}
	if !blob.exists {
		if err := s.deleteLocked(segmentSetID, segment); err != nil {
			return Entry{}, false, err
		}
		return Entry{}, false, nil
	}
	if blob.digest != meta.BlobSHA256 {
		if err := s.deleteLocked(segmentSetID, segment); err != nil {
			return Entry{}, false, err
		}
		return Entry{}, false, nil
	}
	return Entry{Bytes: blob.body, ContentType: meta.ContentType, ExpiresAt: meta.ExpiresAt}, true, nil
}

func (s *Store) Put(segmentSetID, segment string, entry Entry) error {
	if err := s.beginOperation(); err != nil {
		return err
	}
	defer s.endOperation()
	if err := validateSegmentSetID(segmentSetID); err != nil {
		return err
	}
	if err := validateSegmentName(segment); err != nil {
		return err
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	if !entry.ExpiresAt.After(now()) {
		return errors.New("cache entry expiry must be in the future")
	}
	if int64(len(entry.Bytes)) > s.TenantCapBytes {
		return ErrQuotaExceeded
	}
	tenantDir := s.tenantDir(segmentSetID)
	lock := s.tenantLock(tenantDir)
	lock.Lock()
	defer lock.Unlock()
	rootLock, err := s.lockRoot()
	if err != nil {
		return err
	}
	defer unlockRoot(rootLock)
	tenant, err := s.openTenantDir(tenantDir, true)
	if err != nil {
		return err
	}
	defer tenant.close()
	blobPath := s.blobPath(segmentSetID, segment)
	metaPath := s.metaPath(segmentSetID, segment)
	if err := s.reconcileTenant(tenantDir); err != nil {
		return err
	}
	if err := tenant.verify(); err != nil {
		return err
	}
	current, err := s.dirSize(tenantDir)
	if err != nil {
		return err
	}
	s.setUsed(tenantDir, current)
	if entry.ContentType == "" {
		entry.ContentType = "application/octet-stream"
	}
	metaBody, err := json.Marshal(storedMeta{
		Segment: segment, ContentType: entry.ContentType, ExpiresAt: entry.ExpiresAt,
		BlobSHA256: fileDigest(entry.Bytes),
	})
	if err != nil {
		return fmt.Errorf("marshal cache metadata: %w", err)
	}
	if int64(len(metaBody)) > maxStructuredNodeBytes {
		return errors.New("cache metadata exceeds size limit")
	}
	oldBlob, oldMeta, valid, err := s.inspectPublication(blobPath, metaPath, segment)
	if err != nil {
		return fmt.Errorf("inspect existing cache publication: %w", err)
	}
	if !valid && (oldBlob.exists || oldMeta.exists) {
		if _, err := s.removePairPaths(blobPath, metaPath); err != nil {
			return fmt.Errorf("evict unverifiable cache publication: %w", err)
		}
		current, err = s.dirSize(tenantDir)
		if err != nil {
			return err
		}
		s.setUsed(tenantDir, current)
		oldBlob, oldMeta = nodeState{}, nodeState{}
	}
	projected := current - oldBlob.size - oldMeta.size + int64(len(entry.Bytes)+len(metaBody))
	if projected > s.TenantCapBytes {
		return ErrQuotaExceeded
	}
	txn, txnDir, err := s.stageTransaction(
		tenantDir, filepath.Base(blobPath), entry.Bytes, metaBody, oldBlob.digest, oldMeta.digest,
	)
	if err != nil {
		s.invalidateUsed(tenantDir)
		return err
	}
	if err := s.publishTransaction(tenantDir, txnDir, txn); err != nil {
		s.invalidateUsed(tenantDir)
		if transactionCommitted(err) {
			s.setUsed(tenantDir, projected)
			return err
		}
		if s.leaveFailedTransaction {
			return err
		}
		if rollbackErr := rollbackTransaction(s, tenantDir, txnDir, txn); rollbackErr != nil {
			return fmt.Errorf("%v; rollback cache transaction: %w", err, rollbackErr)
		}
		return err
	}
	if err := tenant.verify(); err != nil {
		s.invalidateUsed(tenantDir)
		return err
	}
	s.setUsed(tenantDir, projected)
	s.maybeSweep()
	return nil
}

// Quota returns the process-coherent usage snapshot maintained by Store
// mutations. A cold snapshot is rebuilt under the cross-process root fence;
// warm reads stay O(1). A separately running process can make a warm report
// stale, but every Put independently recounts disk under the same fence before
// quota admission, so stale reporting can never authorize an over-cap publish.
func (s *Store) Quota(segmentSetID string) (QuotaState, error) {
	if err := s.beginOperation(); err != nil {
		return QuotaState{}, err
	}
	defer s.endOperation()
	if err := validateSegmentSetID(segmentSetID); err != nil {
		return QuotaState{}, err
	}
	tenantDir := s.tenantDir(segmentSetID)
	lock := s.tenantLock(tenantDir)
	lock.Lock()
	defer lock.Unlock()
	rootLock, err := s.lockRoot()
	if err != nil {
		return QuotaState{}, err
	}
	defer unlockRoot(rootLock)
	tenant, err := s.openTenantDir(tenantDir, true)
	if err != nil {
		return QuotaState{}, err
	}
	defer tenant.close()
	if err := s.reconcileTenant(tenantDir); err != nil {
		return QuotaState{}, err
	}
	if err := tenant.verify(); err != nil {
		return QuotaState{}, err
	}
	used, ok := s.cachedUsed(tenantDir)
	if !ok {
		used, err = s.dirSize(tenantDir)
		if err != nil {
			return QuotaState{}, err
		}
		s.setUsed(tenantDir, used)
	}
	return QuotaState{UsedBytes: used, CapBytes: s.TenantCapBytes}, nil
}

// maybeSweep triggers an amortized, asynchronous expiry sweep of the whole
// store every SweepEvery calls to Put (across every tenant, not just the one
// just written). This is what keeps expiry reaping alive now that the
// push-ack path no longer calls Inventory: as long as ANY tenant keeps
// pushing, every tenant - including one that has gone cold and stopped
// pushing or reading entirely - still gets its expired blobs reclaimed.
// A single-flight guard (sweeping) skips scheduling a new sweep while one is
// already in flight; the next threshold hit tries again.
func (s *Store) maybeSweep() {
	every := s.SweepEvery
	if every <= 0 {
		every = defaultSweepEvery
	}
	if s.putCount.Add(1)%every != 0 {
		return
	}
	if !s.sweeping.CompareAndSwap(false, true) {
		return
	}
	if err := s.beginOperation(); err != nil {
		s.sweeping.Store(false)
		return
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	at := now()
	go func() {
		defer s.endOperation()
		defer s.sweeping.Store(false)
		s.sweepExpired(at)
		if s.sweepDone != nil {
			select {
			case s.sweepDone <- struct{}{}:
			default:
			}
		}
	}()
}

// sweepExpired reaps expired entries across every tenant directory under
// Root, independent of any Get/Inventory call for that tenant.
func (s *Store) sweepExpired(now time.Time) {
	tenants, err := s.readDirectory(s.Root)
	if err != nil {
		return
	}
	for _, tenant := range tenants {
		if !tenant.IsDir() {
			continue
		}
		s.reapTenantDir(filepath.Join(s.Root, tenant.Name()), now)
	}
}

// reapTenantDir deletes every expired, provenance-matched blob+metadata pair
// under tenantDir. Symlinks are never followed: an untrusted link is removed
// by itself, while its peer remains charged until a later verified cleanup.
// The final no-follow recount makes partial removals fail closed for quota.
func (s *Store) reapTenantDir(tenantDir string, now time.Time) {
	lock := s.tenantLock(tenantDir)
	lock.Lock()
	defer lock.Unlock()
	rootLock, err := s.lockRoot()
	if err != nil {
		return
	}
	defer unlockRoot(rootLock)
	tenant, err := s.openTenantDir(tenantDir, false)
	if err != nil {
		return
	}
	defer tenant.close()
	if err := s.reconcileTenant(tenantDir); err != nil {
		return
	}
	if err := tenant.verify(); err != nil {
		return
	}

	entries, err := s.readDirectory(tenantDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" ||
			strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		metaPath := filepath.Join(tenantDir, entry.Name())
		metaInfo, err := s.nodeStat(metaPath)
		if err != nil {
			continue
		}
		if metaInfo.Mode&unix.S_IFMT == unix.S_IFLNK {
			_ = s.removePath(metaPath)
			continue
		}
		if metaInfo.Mode&unix.S_IFMT != unix.S_IFREG {
			continue
		}
		metaNode, err := s.readNode(metaPath, maxStructuredNodeBytes)
		if err != nil {
			continue
		}
		var meta storedMeta
		if err := json.Unmarshal(metaNode.body, &meta); err != nil || meta.Segment == "" ||
			meta.BlobSHA256 == "" {
			continue
		}
		if meta.ExpiresAt.After(now) {
			continue
		}
		blobPath := strings.TrimSuffix(metaPath, ".json") + ".bin"
		blobInfo, err := s.nodeStat(blobPath)
		if err != nil {
			continue
		}
		if blobInfo.Mode&unix.S_IFMT == unix.S_IFLNK {
			_ = s.removePath(blobPath)
			continue
		}
		if blobInfo.Mode&unix.S_IFMT != unix.S_IFREG {
			continue
		}
		blobNode, err := s.readNode(blobPath, s.TenantCapBytes)
		if err != nil || blobNode.digest != meta.BlobSHA256 {
			continue
		}
		_, _ = s.removePairPaths(blobPath, metaPath)
	}
	total, err := s.dirSize(tenantDir)
	if err != nil {
		s.invalidateUsed(tenantDir)
		return
	}
	s.setUsed(tenantDir, total)
}

func (s *Store) Inventory(segmentSetID string) (Inventory, error) {
	if err := s.beginOperation(); err != nil {
		return Inventory{}, err
	}
	defer s.endOperation()
	if err := validateSegmentSetID(segmentSetID); err != nil {
		return Inventory{}, err
	}
	tenantDir := s.tenantDir(segmentSetID)
	lock := s.tenantLock(tenantDir)
	lock.Lock()
	defer lock.Unlock()
	rootLock, err := s.lockRoot()
	if err != nil {
		return Inventory{}, err
	}
	defer unlockRoot(rootLock)
	tenant, err := s.openTenantDir(tenantDir, true)
	if err != nil {
		return Inventory{}, err
	}
	defer tenant.close()
	if err := s.reconcileTenant(tenantDir); err != nil {
		return Inventory{}, err
	}
	if err := tenant.verify(); err != nil {
		return Inventory{}, err
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	var entries []InventoryEntry
	diskEntries, err := s.readDirectory(tenantDir)
	if err != nil {
		return Inventory{}, fmt.Errorf("inventory cache tenant dir: %w", err)
	}
	for _, d := range diskEntries {
		path := filepath.Join(tenantDir, d.Name())
		if d.IsDir() || filepath.Ext(path) != ".json" || strings.HasPrefix(d.Name(), ".") {
			continue
		}
		metaNode, err := s.readNode(path, maxStructuredNodeBytes)
		if err != nil {
			return Inventory{}, fmt.Errorf("inventory cache tenant dir: %w", err)
		}
		var meta storedMeta
		if err := json.Unmarshal(metaNode.body, &meta); err != nil {
			if _, removeErr := s.removePairPaths(strings.TrimSuffix(path, ".json")+".bin", path); removeErr != nil {
				return Inventory{}, fmt.Errorf("inventory cache tenant dir: %w", removeErr)
			}
			continue
		}
		expectedMeta := ""
		if meta.Segment != "" {
			expectedMeta = s.metaPath(segmentSetID, meta.Segment)
		}
		if meta.Segment == "" || meta.BlobSHA256 == "" || expectedMeta != path {
			if _, removeErr := s.removePairPaths(strings.TrimSuffix(path, ".json")+".bin", path); removeErr != nil {
				return Inventory{}, fmt.Errorf("inventory cache tenant dir: %w", removeErr)
			}
			continue
		}
		blobPath := s.blobPath(segmentSetID, meta.Segment)
		blob, err := s.readNode(blobPath, s.TenantCapBytes)
		if err != nil {
			return Inventory{}, fmt.Errorf("inventory cache tenant dir: %w", err)
		}
		if !blob.exists || blob.digest != meta.BlobSHA256 {
			if _, removeErr := s.removePairPaths(blobPath, path); removeErr != nil {
				return Inventory{}, fmt.Errorf("inventory cache tenant dir: %w", removeErr)
			}
			continue
		}
		if !meta.ExpiresAt.After(now()) {
			if err := s.deleteLocked(segmentSetID, meta.Segment); err != nil {
				return Inventory{}, fmt.Errorf("inventory cache tenant dir: %w", err)
			}
			continue
		}
		entries = append(entries, InventoryEntry{
			Segment:     meta.Segment,
			Bytes:       blob.size,
			ContentType: meta.ContentType,
			ExpiresAt:   meta.ExpiresAt,
		})
	}
	used, err := s.dirSize(tenantDir)
	if err != nil {
		return Inventory{}, err
	}
	s.setUsed(tenantDir, used)
	return Inventory{Entries: entries, Quota: QuotaState{UsedBytes: used, CapBytes: s.TenantCapBytes}}, nil
}

func (s *Store) Delete(segmentSetID, segment string) error {
	if err := s.beginOperation(); err != nil {
		return err
	}
	defer s.endOperation()
	if err := validateSegmentSetID(segmentSetID); err != nil {
		return err
	}
	if err := validateSegmentName(segment); err != nil {
		return err
	}
	tenantDir := s.tenantDir(segmentSetID)
	lock := s.tenantLock(tenantDir)
	lock.Lock()
	defer lock.Unlock()
	rootLock, err := s.lockRoot()
	if err != nil {
		return err
	}
	defer unlockRoot(rootLock)
	tenant, err := s.openTenantDir(tenantDir, true)
	if err != nil {
		return err
	}
	defer tenant.close()
	if err := s.reconcileTenant(tenantDir); err != nil {
		return err
	}
	if err := tenant.verify(); err != nil {
		return err
	}
	return s.deleteLocked(segmentSetID, segment)
}

func (s *Store) deleteLocked(segmentSetID, segment string) error {
	blobPath := s.blobPath(segmentSetID, segment)
	metaPath := s.metaPath(segmentSetID, segment)
	removed, err := s.removePairPaths(blobPath, metaPath)
	if err != nil {
		s.invalidateUsed(s.tenantDir(segmentSetID))
		return err
	}
	s.adjustUsed(s.tenantDir(segmentSetID), -removed)
	return nil
}

func (s *Store) inspectPublication(blobPath, metaPath, segment string) (nodeState, nodeState, bool, error) {
	blob, err := s.readNode(blobPath, s.TenantCapBytes)
	if err != nil {
		return nodeState{}, nodeState{}, false, err
	}
	meta, err := s.readNode(metaPath, maxStructuredNodeBytes)
	if err != nil {
		return nodeState{}, nodeState{}, false, err
	}
	if !blob.exists && !meta.exists {
		return blob, meta, true, nil
	}
	if !blob.exists || !meta.exists {
		return blob, meta, false, nil
	}
	var decoded storedMeta
	if json.Unmarshal(meta.body, &decoded) != nil || decoded.Segment != segment ||
		decoded.BlobSHA256 == "" || decoded.BlobSHA256 != blob.digest {
		return blob, meta, false, nil
	}
	return blob, meta, true, nil
}

func (s *Store) removePairPaths(blobPath, metaPath string) (int64, error) {
	parent := filepath.Dir(blobPath)
	if parent != filepath.Dir(metaPath) {
		return 0, errors.New("cache publication pair has different directories")
	}
	if err := validateDirectory(parent); err != nil {
		return 0, err
	}
	blob, err := s.readNode(blobPath, s.TenantCapBytes)
	if err != nil {
		return 0, err
	}
	meta, err := s.readNode(metaPath, maxStructuredNodeBytes)
	if err != nil {
		return 0, err
	}
	for _, item := range []struct {
		path string
		node nodeState
	}{{blobPath, blob}, {metaPath, meta}} {
		if item.node.exists {
			if err := validateDirectory(parent); err != nil {
				return 0, err
			}
			if err := s.removePath(item.path); err != nil {
				return 0, err
			}
		}
	}
	return blob.size + meta.size, nil
}
