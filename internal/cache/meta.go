package cache

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type sharedUsageCache struct {
	mu   sync.Mutex
	used map[string]int64
}

type verifiedDirectory struct {
	path string
	file *os.File
	info os.FileInfo
}

// usageCaches makes warm quota reads coherent across Store values in this
// process. Put still recounts under the cross-process root lock before every
// admission decision, so this optimization is never quota authority.
var usageCaches sync.Map

// lockRoot serializes every cache publication, read, sweep, and recovery for a
// shared Root. flock is released by the kernel on process exit, so a crash
// cannot strand the fence. The guarantee covers cooperating Store processes on
// filesystems that implement advisory flock; external writers and filesystems
// without reliable flock semantics are outside the cache contract.
func (s *Store) lockRoot() (*os.File, error) {
	path := filepath.Join(s.Root, ".cache.lock")
	parent, name, err := s.openParent(path)
	if err != nil {
		return nil, fmt.Errorf("open cache root lock parent: %w", err)
	}
	defer func() { _ = parent.Close() }()
	fd, err := unix.Openat(
		int(parent.Fd()), name,
		unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return nil, fmt.Errorf("open cache root lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("inspect cache root lock: %w", err)
		}
		return nil, errors.New("cache root lock is not a private regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock cache root: %w", err)
	}
	var current unix.Stat_t
	err = unix.Fstatat(int(parent.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil || !sameFileStat(info, &current) {
		unlockRoot(file)
		if err != nil {
			return nil, fmt.Errorf("verify cache root lock: %w", err)
		}
		return nil, errors.New("cache root lock changed during acquisition")
	}
	if err := s.verifyRoot(); err != nil {
		unlockRoot(file)
		return nil, err
	}
	return file, nil
}

func sameFileStat(info os.FileInfo, current *unix.Stat_t) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Dev == current.Dev && stat.Ino == current.Ino
}

func unlockRoot(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func openVerifiedDirectory(path string) (*verifiedDirectory, error) {
	file, err := os.OpenFile(
		path,
		os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("cache path is not a regular directory: %s", path)
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, current) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("cache directory changed during inspection: %s", path)
	}
	return &verifiedDirectory{path: path, file: file, info: info}, nil
}

func (s *Store) verifyRoot() error {
	current, err := os.Lstat(s.Root)
	if err != nil {
		return fmt.Errorf("verify cache root: %w", err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(s.rootInfo, current) {
		return errors.New("cache root changed during Store lifetime")
	}
	return nil
}

func (s *Store) relativePath(path string) (string, error) {
	relative, err := filepath.Rel(s.Root, filepath.Clean(path))
	if err != nil || relative == "." || filepath.IsAbs(relative) ||
		relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("cache path is outside pinned root: %s", path)
	}
	return relative, nil
}

func openDirectoryAt(parentFD int, name, displayPath string) (*os.File, error) {
	fd, err := unix.Openat(
		parentFD, name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), displayPath), nil
}

func (s *Store) openParent(path string) (*os.File, string, error) {
	relative, err := s.relativePath(path)
	if err != nil {
		return nil, "", err
	}
	parts := strings.Split(relative, string(filepath.Separator))
	parent, err := openDirectoryAt(int(s.rootDir.Fd()), ".", s.Root)
	if err != nil {
		return nil, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := openDirectoryAt(int(parent.Fd()), part, filepath.Join(parent.Name(), part))
		_ = parent.Close()
		if openErr != nil {
			return nil, "", openErr
		}
		parent = next
	}
	return parent, parts[len(parts)-1], nil
}

func (s *Store) openDirectory(path string) (*os.File, error) {
	if filepath.Clean(path) == s.Root {
		return openDirectoryAt(int(s.rootDir.Fd()), ".", s.Root)
	}
	parent, name, err := s.openParent(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = parent.Close() }()
	return openDirectoryAt(int(parent.Fd()), name, filepath.Clean(path))
}

func (s *Store) readDirectory(path string) ([]os.DirEntry, error) {
	dir, err := s.openDirectory(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	return dir.ReadDir(-1)
}

func (s *Store) writeDurable(path string, body []byte) error {
	parent, name, err := s.openParent(path)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	fd, err := unix.Openat(
		int(parent.Fd()), name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if _, err = file.Write(body); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (s *Store) syncDir(path string) error {
	dir, err := s.openDirectory(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync cache directory: %w", err)
	}
	return nil
}

func (s *Store) removeTree(path string) error {
	dir, err := s.openDirectory(path)
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		if entry.IsDir() {
			if err := s.removeTree(child); err != nil {
				return err
			}
			continue
		}
		if err := s.removePath(child); err != nil {
			return err
		}
	}
	parent, name, err := s.openParent(path)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	return unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
}

func (s *Store) readNode(path string, maxBytes int64) (nodeState, error) {
	parent, name, err := s.openParent(path)
	if err != nil {
		return nodeState{}, err
	}
	defer func() { _ = parent.Close() }()
	var before unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, syscall.ENOENT) {
		return nodeState{}, nil
	} else if err != nil {
		return nodeState{}, fmt.Errorf("inspect cache node: %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nodeState{}, fmt.Errorf("cache node is not regular: %s", path)
	}
	if before.Size > maxBytes {
		return nodeState{}, fmt.Errorf("cache node exceeds %d-byte limit: %s", maxBytes, path)
	}
	fd, err := unix.Openat(
		int(parent.Fd()), name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC,
		0,
	)
	if errors.Is(err, syscall.ENOENT) {
		return nodeState{}, nil
	}
	if err != nil {
		return nodeState{}, fmt.Errorf("open cache node: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || !sameFileStat(info, &before) ||
		info.Size() > maxBytes {
		_ = file.Close()
		if statErr != nil {
			return nodeState{}, statErr
		}
		return nodeState{}, fmt.Errorf("cache node changed during inspection: %s", path)
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nodeState{}, readErr
	}
	if closeErr != nil {
		return nodeState{}, closeErr
	}
	if int64(len(body)) > maxBytes {
		return nodeState{}, fmt.Errorf("cache node exceeds %d-byte limit: %s", maxBytes, path)
	}
	return nodeState{exists: true, size: info.Size(), digest: fileDigest(body), body: body}, nil
}

func (s *Store) nodeStat(path string) (unix.Stat_t, error) {
	parent, name, err := s.openParent(path)
	if err != nil {
		return unix.Stat_t{}, err
	}
	defer func() { _ = parent.Close() }()
	var stat unix.Stat_t
	err = unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	return stat, err
}

func (s *Store) removePath(path string) error {
	parent, name, err := s.openParent(path)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	return unix.Unlinkat(int(parent.Fd()), name, 0)
}

func (s *Store) renamePath(from, to string) error {
	fromParent, fromName, err := s.openParent(from)
	if err != nil {
		return err
	}
	defer func() { _ = fromParent.Close() }()
	toParent, toName, err := s.openParent(to)
	if err != nil {
		return err
	}
	defer func() { _ = toParent.Close() }()
	return unix.Renameat(int(fromParent.Fd()), fromName, int(toParent.Fd()), toName)
}

func (s *Store) mkdirPath(path string) error {
	parent, name, err := s.openParent(path)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	return unix.Mkdirat(int(parent.Fd()), name, 0o700)
}

func dirSize(root string) (int64, error) {
	if err := validateDirectory(root); err != nil {
		return 0, fmt.Errorf("size cache tenant dir: %w", err)
	}
	return dirContentsSize(root)
}

func (s *Store) dirSize(root string) (int64, error) {
	entries, err := s.readDirectory(root)
	if err != nil {
		return 0, fmt.Errorf("size cache tenant dir: %w", err)
	}
	var total int64
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		info, err := s.nodeStat(path)
		if err != nil {
			return 0, fmt.Errorf("size cache tenant dir: %w", err)
		}
		if info.Mode&unix.S_IFMT == unix.S_IFDIR {
			nested, err := s.dirSize(path)
			if err != nil {
				return 0, err
			}
			total += nested
			continue
		}
		total += info.Size
	}
	return total, nil
}

func dirContentsSize(root string) (int64, error) {
	var total int64
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, fmt.Errorf("size cache tenant dir: %w", err)
	}
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return 0, fmt.Errorf("size cache tenant dir: %w", err)
		}
		if info.IsDir() {
			nested, err := dirSize(path)
			if err != nil {
				return 0, err
			}
			total += nested
			continue
		}
		total += info.Size()
	}
	return total, nil
}

func validateDirectory(path string) error {
	dir, err := openVerifiedDirectory(path)
	if err != nil {
		return err
	}
	defer dir.close()
	return dir.verify()
}

func readNode(path string) (nodeState, error) {
	return readNodeLimited(path, DefaultTenantCapBytes)
}

func readNodeLimited(path string, maxBytes int64) (nodeState, error) {
	if err := validateDirectory(filepath.Dir(path)); err != nil {
		return nodeState{}, err
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nodeState{}, nil
	}
	if err != nil {
		return nodeState{}, fmt.Errorf("inspect cache node: %w", err)
	}
	if !before.Mode().IsRegular() {
		return nodeState{}, fmt.Errorf("cache node is not regular: %s", path)
	}
	if before.Size() > maxBytes {
		return nodeState{}, fmt.Errorf("cache node exceeds %d-byte limit: %s", maxBytes, path)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nodeState{}, nil
	}
	if err != nil {
		return nodeState{}, fmt.Errorf("open cache node: %w", err)
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) ||
		info.Size() > maxBytes {
		_ = file.Close()
		if statErr != nil {
			return nodeState{}, statErr
		}
		return nodeState{}, fmt.Errorf("cache node changed during inspection: %s", path)
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nodeState{}, readErr
	}
	if closeErr != nil {
		return nodeState{}, closeErr
	}
	if int64(len(body)) > maxBytes {
		return nodeState{}, fmt.Errorf("cache node exceeds %d-byte limit: %s", maxBytes, path)
	}
	return nodeState{exists: true, size: info.Size(), digest: fileDigest(body), body: body}, nil
}

func fileState(path string) (int64, string, error) {
	node, err := readNode(path)
	return node.size, node.digest, err
}

func rollbackOldPreserved(live, backup nodeState, oldDigest, newDigest string, createdByTxn bool) bool {
	if oldDigest == "" {
		return createdByTxn && !backup.exists && (!live.exists || matches(live, newDigest))
	}
	return !createdByTxn && (matches(live, oldDigest) || matches(backup, oldDigest))
}

func (s *Store) tenantLock(tenantDir string) *sync.Mutex {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	if s.locks == nil {
		s.locks = make(map[string]*sync.Mutex)
	}
	if s.locks[tenantDir] == nil {
		s.locks[tenantDir] = &sync.Mutex{}
	}
	return s.locks[tenantDir]
}

func (s *Store) tenantDir(segmentSetID string) string {
	return filepath.Join(s.Root, hmacHex(s.Key, "tenant:"+segmentSetID))
}

func (s *Store) blobPath(segmentSetID, segment string) string {
	return filepath.Join(s.tenantDir(segmentSetID), hmacHex(s.Key, "segment:"+segmentSetID+"\x00"+segment)+".bin")
}

func (s *Store) metaPath(segmentSetID, segment string) string {
	return filepath.Join(s.tenantDir(segmentSetID), hmacHex(s.Key, "segment:"+segmentSetID+"\x00"+segment)+".json")
}

func hmacHex(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func validateSegmentName(segment string) error {
	if segment == "" || len(segment) > 256 {
		return errors.New("invalid segment name")
	}
	for _, r := range segment {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return errors.New("invalid segment name")
	}
	return nil
}

func (dir *verifiedDirectory) verify() error {
	current, err := os.Lstat(dir.path)
	if err != nil {
		return err
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(dir.info, current) {
		return fmt.Errorf("cache directory changed during operation: %s", dir.path)
	}
	return nil
}

func (dir *verifiedDirectory) close() {
	_ = dir.file.Close()
}

func (s *Store) openTenantDir(path string, create bool) (*verifiedDirectory, error) {
	clean := filepath.Clean(path)
	if filepath.Dir(clean) != s.Root || filepath.Base(clean) == "." ||
		strings.HasPrefix(filepath.Base(clean), ".") {
		return nil, fmt.Errorf("cache tenant directory is outside root: %s", path)
	}
	parent, name, err := s.openParent(clean)
	if err != nil {
		return nil, fmt.Errorf("open tenant cache parent: %w", err)
	}
	defer func() { _ = parent.Close() }()
	if create {
		if err := unix.Mkdirat(int(parent.Fd()), name, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
			return nil, fmt.Errorf("create tenant cache dir: %w", err)
		}
	}
	file, err := openDirectoryAt(int(parent.Fd()), name, clean)
	if err != nil {
		return nil, fmt.Errorf("verify tenant cache dir: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect tenant cache dir: %w", err)
	}
	dir := &verifiedDirectory{path: clean, file: file, info: info}
	if dir.info.Mode().Perm()&0o077 != 0 {
		dir.close()
		return nil, errors.New("tenant cache directory is not private")
	}
	return dir, nil
}

func (s *Store) verifyTenantDir(path string) error {
	dir, err := s.openTenantDir(path, false)
	if err != nil {
		return err
	}
	defer dir.close()
	return dir.verify()
}

func (s *Store) cachedUsed(tenantDir string) (int64, bool) {
	s.usage.mu.Lock()
	defer s.usage.mu.Unlock()
	used, ok := s.usage.used[tenantDir]
	return used, ok
}

func (s *Store) setUsed(tenantDir string, used int64) {
	s.usage.mu.Lock()
	if s.usage.used == nil {
		s.usage.used = make(map[string]int64)
	}
	s.usage.used[tenantDir] = used
	s.usage.mu.Unlock()
}

func (s *Store) adjustUsed(tenantDir string, delta int64) {
	s.usage.mu.Lock()
	if _, ok := s.usage.used[tenantDir]; ok {
		s.usage.used[tenantDir] += delta
	}
	s.usage.mu.Unlock()
}

func (s *Store) invalidateUsed(tenantDir string) {
	s.usage.mu.Lock()
	delete(s.usage.used, tenantDir)
	s.usage.mu.Unlock()
}

func (s *Store) resetUsage() {
	s.usage.mu.Lock()
	s.usage.used = nil
	s.usage.mu.Unlock()
}
