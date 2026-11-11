package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	hmacNonceLockRetry = 10 * time.Millisecond

	// maxPersistedNonceEntryBytes is the widest encoding of one persisted
	// entry: a quoted 32-hex-digit key, a colon, a signed 19-digit int64, and
	// a comma.
	maxPersistedNonceEntryBytes = 56
	maxHMACNonceStateBytes      = MaxNonceStoreCapacity*maxPersistedNonceEntryBytes + 64
)

// FileHMACNonceStore persists replay state in one atomically replaced file and
// serializes admissions with a separate advisory lock file. Independent store
// values and processes using the same path therefore share one nonce set.
//
// The path may be placed on a filesystem shared by relay hosts only when that
// filesystem preserves POSIX advisory-lock and atomic-rename semantics. Hosted
// deployments without those guarantees should implement HMACNonceStore on their
// transactional database instead.
type FileHMACNonceStore struct {
	path     string
	lockPath string
	capacity int

	// observed holds the expiries of the live nonces this instance last read
	// under the lock. It feeds the fill gauge only, so a scrape never touches
	// the state file.
	mu       sync.Mutex
	observed []int64
}

// NewFileHMACNonceStore prepares a persistent nonce store at path with
// DefaultNonceStoreCapacity. The containing directory is created private to the
// current user when absent.
func NewFileHMACNonceStore(path string) (*FileHMACNonceStore, error) {
	return NewFileHMACNonceStoreWithCapacity(path, DefaultNonceStoreCapacity)
}

// NewFileHMACNonceStoreWithCapacity prepares a persistent nonce store at path
// that admits at most capacity live nonces; once full, Admit refuses with
// ErrNonceStoreFull until entries expire. Every instance sharing path should use
// the same capacity. capacity must be in [1, MaxNonceStoreCapacity].
func NewFileHMACNonceStoreWithCapacity(path string, capacity int) (*FileHMACNonceStore, error) {
	if path == "" {
		return nil, errors.New("hmac nonce store path is required")
	}
	if capacity < 1 || capacity > MaxNonceStoreCapacity {
		return nil, fmt.Errorf("hmac nonce store capacity %d is outside [1, %d]", capacity, MaxNonceStoreCapacity)
	}
	path = filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create hmac nonce store directory: %w", err)
	}
	store := &FileHMACNonceStore{path: path, lockPath: path + ".lock", capacity: capacity}
	if err := store.initialize(); err != nil {
		return nil, err
	}
	return store, nil
}

// initialize validates and durably rewrites the state under the same lock used
// by Admit. Callers therefore learn about corrupt state or unwritable storage at
// startup, before a relay listener can accept a carrier.
func (s *FileHMACNonceStore) initialize() error {
	lock, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open hmac nonce store lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := lockFileContext(context.Background(), lock); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	state, err := s.readState()
	if err != nil {
		return err
	}
	s.observe(state.Nonces)
	return s.writeState(state)
}

// Admit implements HMACNonceStore. The lock covers the read, expiry sweep, and
// atomic replacement, so concurrent processes cannot both admit the same nonce.
func (s *FileHMACNonceStore) Admit(ctx context.Context, nonce string, expiresAt, now time.Time) (bool, error) {
	if s == nil || s.path == "" || s.lockPath == "" {
		return false, errors.New("hmac nonce store is not initialized")
	}
	if !now.Before(expiresAt) {
		return false, nil
	}
	if !validHMACNonce(nonce) {
		return false, errors.New("hmac nonce must be exactly 16 bytes of hexadecimal")
	}

	lock, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false, fmt.Errorf("open hmac nonce store lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := lockFileContext(ctx, lock); err != nil {
		return false, err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	state, err := s.readState()
	if err != nil {
		return false, err
	}
	defer s.observe(state.Nonces)
	nowUnixNano := now.UnixNano()
	for key, expiryUnixNano := range state.Nonces {
		if expiryUnixNano <= nowUnixNano {
			delete(state.Nonces, key)
		}
	}
	if _, exists := state.Nonces[nonce]; exists {
		return false, nil
	}
	if len(state.Nonces) >= s.capacity {
		return false, fmt.Errorf("hmac %w", ErrNonceStoreFull)
	}
	state.Nonces[nonce] = expiresAt.UnixNano()
	if err := s.writeState(state); err != nil {
		return false, err
	}
	return true, nil
}

// observe records the expiries of nonces for fill. The caller holds the file lock.
func (s *FileHMACNonceStore) observe(nonces map[string]int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observed = s.observed[:0]
	for _, expiryUnixNano := range nonces {
		s.observed = append(s.observed, expiryUnixNano)
	}
}

// fill reports the nonces still live at now among those this instance last
// observed. Entries other instances admitted since this instance's last
// admission are not counted until its next one.
func (s *FileHMACNonceStore) fill(now time.Time) nonceStoreFill {
	s.mu.Lock()
	defer s.mu.Unlock()
	nowUnixNano := now.UnixNano()
	live := 0
	for _, expiryUnixNano := range s.observed {
		if expiryUnixNano > nowUnixNano {
			live++
		}
	}
	return nonceStoreFill{Entries: live, Capacity: s.capacity}
}

type fileHMACNonceState struct {
	Version int              `json:"version"`
	Nonces  map[string]int64 `json:"nonces"`
}

func (s *FileHMACNonceStore) readState() (fileHMACNonceState, error) {
	state := fileHMACNonceState{Version: 1, Nonces: map[string]int64{}}
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return fileHMACNonceState{}, fmt.Errorf("read hmac nonce store: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxHMACNonceStateBytes+1))
	if err != nil {
		return fileHMACNonceState{}, fmt.Errorf("read hmac nonce store: %w", err)
	}
	if len(raw) > maxHMACNonceStateBytes {
		return fileHMACNonceState{}, errors.New("read hmac nonce store: state exceeds byte limit")
	}
	state = fileHMACNonceState{Nonces: map[string]int64{}}
	if err := decodeFileHMACNonceState(raw, &state); err != nil {
		return fileHMACNonceState{}, fmt.Errorf("decode hmac nonce store: %w", err)
	}
	if state.Version != 1 || state.Nonces == nil {
		return fileHMACNonceState{}, errors.New("decode hmac nonce store: unsupported state")
	}
	return state, nil
}

func decodeFileHMACNonceState(raw []byte, state *fileHMACNonceState) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("invalid state object")
	}
	seenVersion, seenNonces := false, false
	for decoder.More() {
		field, err := decoder.Token()
		if err != nil {
			return err
		}
		switch field {
		case "version":
			if seenVersion {
				return errors.New("duplicate version field")
			}
			seenVersion = true
			if err := decoder.Decode(&state.Version); err != nil {
				return err
			}
		case "nonces":
			if seenNonces {
				return errors.New("duplicate nonces field")
			}
			seenNonces = true
			open, err := decoder.Token()
			if err != nil || open != json.Delim('{') {
				return errors.New("nonces must be an object")
			}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || !validHMACNonce(key) {
					return errors.New("invalid persisted nonce")
				}
				if len(state.Nonces) >= MaxNonceStoreCapacity {
					return errors.New("nonce cardinality exceeds limit")
				}
				if _, duplicate := state.Nonces[key]; duplicate {
					return errors.New("duplicate persisted nonce")
				}
				var expiry int64
				if err := decoder.Decode(&expiry); err != nil {
					return err
				}
				state.Nonces[key] = expiry
			}
			if closeToken, err := decoder.Token(); err != nil || closeToken != json.Delim('}') {
				return errors.New("invalid nonces object")
			}
		default:
			return fmt.Errorf("unknown field %q", field)
		}
	}
	if closeToken, err := decoder.Token(); err != nil || closeToken != json.Delim('}') {
		return errors.New("invalid state object")
	}
	if !seenVersion || !seenNonces {
		return errors.New("state fields are required")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing state data")
	}
	return nil
}

func (s *FileHMACNonceStore) writeState(state fileHMACNonceState) error {
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".hmac-nonces-*")
	if err != nil {
		return fmt.Errorf("create hmac nonce store temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	encodeErr := json.NewEncoder(tmp).Encode(state)
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if encodeErr != nil {
		return fmt.Errorf("encode hmac nonce store: %w", encodeErr)
	}
	if syncErr != nil {
		return fmt.Errorf("sync hmac nonce store: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close hmac nonce store: %w", closeErr)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace hmac nonce store: %w", err)
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open hmac nonce store directory: %w", err)
	}
	defer func() { _ = dirHandle.Close() }()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("sync hmac nonce store directory: %w", err)
	}
	return nil
}

func lockFileContext(ctx context.Context, lock *os.File) error {
	for {
		err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("lock hmac nonce store: %w", err)
		}
		timer := time.NewTimer(hmacNonceLockRetry)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
