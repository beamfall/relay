package relay

import (
	"bytes"
	"context"
	"encoding/hex"
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
	// fairUseOutboxVersion marks the append format: a base state object
	// followed by zero or more newline-terminated add/remove log entries.
	// Every base a running outbox writes carries this version, so a binary
	// that predates the append format refuses the file instead of misreading
	// it.
	fairUseOutboxVersion = 2
	// fairUseOutboxSingleObjectVersion marks the previous format: one base
	// state object and nothing after it, the only shape a pre-append binary
	// reads. A clean close compacts to it (compactForRollbackLocked). Files
	// at this version still load, including ones that carry log entries
	// because an append-format binary wrote them before the version bump.
	fairUseOutboxSingleObjectVersion = 1

	maxFairUseOutboxStateBytes = 8 << 20
	maxFairUseOutboxRecords    = 8192
	maxFairUseOutboxBytes      = int64(maxFairUseOutboxRecords) * fairUseBatchBytes
	maxFairUseOutboxRetention  = 366 * 24 * time.Hour

	// fairUseOutboxCompactionSlack bounds how many appended add/remove log
	// entries may accumulate beyond the live record count before the log is
	// compacted back down to a single base object. Pure appends already give
	// per-event cost independent of outbox size; this bound exists so
	// sustained add+remove churn during healthy operation doesn't grow the
	// log file forever.
	fairUseOutboxCompactionSlack = 256

	// fairUseOutboxReadinessBandDivisor sizes the readiness hysteresis band as
	// a fraction of the record limit (128 records at the production limit).
	// Once the outbox reaches capacity, readiness stays unready until the
	// record count drains below limit minus band, so it does not flip with
	// each record enqueued and replayed while the outbox sits at its limit.
	fairUseOutboxReadinessBandDivisor = 64
)

var (
	errFairUseOutboxRecordLimit = errors.New("fair-use outbox record limit reached")
	errFairUseOutboxByteLimit   = errors.New("fair-use outbox byte limit reached")
)

type fairUseOutboxRecord struct {
	TunnelDigest string `json:"tunnel_digest"`
	Bytes        int64  `json:"bytes"`
	BatchID      string `json:"batch_id"`
	CreatedAt    int64  `json:"created_at"`
	ExpiresAt    int64  `json:"expires_at"`
}

type fairUseOutboxState struct {
	Version int                   `json:"version"`
	Records []fairUseOutboxRecord `json:"records"`
}

type fairUseOutboxFailpoint string

const (
	// fairUseOutboxBeforeRename and fairUseOutboxAfterRename mark the
	// durable-commit boundary of a write: the point right before the bytes
	// that make a change authoritative are made durable, and right after.
	// The names predate the append-only log (they described a temp-file
	// rename) and are kept because existing tests inject failures by name;
	// the whole-file compaction path still renames at that boundary, and the
	// per-event append path fires the same two hooks around its write+sync.
	fairUseOutboxBeforeRename fairUseOutboxFailpoint = "before_rename"
	fairUseOutboxAfterRename  fairUseOutboxFailpoint = "after_rename"
)

// fairUseOutboxOp names an append-only log entry kind.
type fairUseOutboxOp string

const (
	fairUseOutboxOpAdd    fairUseOutboxOp = "add"
	fairUseOutboxOpRemove fairUseOutboxOp = "remove"
)

// fairUseOutboxLogEntry is one line of the append-only log that follows the
// base state object on disk. Replaying every entry in order against the base
// state reconstructs the current record set without rewriting the file.
type fairUseOutboxLogEntry struct {
	Op      fairUseOutboxOp      `json:"op"`
	Record  *fairUseOutboxRecord `json:"record,omitempty"`
	BatchID string               `json:"batch_id,omitempty"`
}

// fileFairUseOutbox is a single-process write-ahead authority for accepted
// Redis fair-use batches. The lifetime advisory lock prevents a second relay
// from replacing state through the same path.
//
// On disk, the path holds one base state object (written only at bootstrap
// and by compaction) followed by zero or more single-line append-only log
// entries recording each add/remove since. This keeps steady-state writes to
// one O(1) append instead of rewriting and fsyncing the whole state per
// event, which is quadratic over a long Redis outage.
type fileFairUseOutbox struct {
	mu         sync.Mutex
	path       string
	lockPath   string
	lock       *os.File
	log        *os.File
	state      fairUseOutboxState
	pendingOps int
	closed     bool
	fatalErr   error
	failpoint  func(fairUseOutboxFailpoint) error

	// readinessHeld latches when the outbox reaches capacity and clears only
	// once the record count drains below the readiness band
	// (updateReadinessHoldLocked).
	readinessHeld bool

	// logWrite, when set, replaces the log file write so tests can stop an
	// append part-way through an entry, as a full disk does.
	logWrite func(file *os.File, payload []byte) (int, error)

	// maxRecords and maxBytes override the package capacity limits when
	// positive. They exist only so tests can reach capacity in a handful of
	// calls instead of maxFairUseOutboxRecords; production outboxes leave
	// them zero and use the package constants.
	maxRecords int
	maxBytes   int64
}

func newFileFairUseOutbox(path string) (*fileFairUseOutbox, error) {
	if path == "" {
		return nil, errors.New("fair-use outbox path is required for redis mode")
	}
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	if err := prepareFairUseOutboxDir(dir); err != nil {
		return nil, err
	}
	lockPath := path + ".lock"
	lock, err := openPrivateFairUseFile(lockPath, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, fmt.Errorf("open fair-use outbox lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock fair-use outbox: %w", err)
	}
	outbox := &fileFairUseOutbox{path: path, lockPath: lockPath, lock: lock}
	state, err := outbox.readState()
	if err != nil {
		_ = outbox.closeLock()
		return nil, err
	}
	outbox.state = state
	outbox.updateReadinessHoldLocked()
	if err := outbox.writeState(state); err != nil {
		_ = outbox.closeLock()
		return nil, err
	}
	return outbox, nil
}

func prepareFairUseOutboxDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create fair-use outbox directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect fair-use outbox directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("fair-use outbox directory must be a real directory")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("fair-use outbox directory mode is %04o, want 0700", info.Mode().Perm())
	}
	if err := requireCurrentOwner(info, "fair-use outbox directory"); err != nil {
		return err
	}
	return nil
}

func openPrivateFairUseFile(path string, flags int) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("state path must be a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, fmt.Errorf("state mode is %04o, want 0600", info.Mode().Perm())
	}
	if err := requireCurrentOwner(info, "state file"); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func requireCurrentOwner(info os.FileInfo, label string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect %s owner", label)
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s owner does not match process user", label)
	}
	return nil
}

func (o *fileFairUseOutbox) readState() (fairUseOutboxState, error) {
	state := fairUseOutboxState{Version: fairUseOutboxVersion, Records: []fairUseOutboxRecord{}}
	file, err := openPrivateFairUseFile(o.path, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return fairUseOutboxState{}, fmt.Errorf("read fair-use outbox: %w", err)
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maxFairUseOutboxStateBytes+1))
	if err != nil {
		return fairUseOutboxState{}, fmt.Errorf("read fair-use outbox: %w", err)
	}
	if len(raw) > maxFairUseOutboxStateBytes {
		return fairUseOutboxState{}, errors.New("read fair-use outbox: state exceeds byte limit")
	}
	base, tail, err := decodeFairUseOutboxBase(raw)
	if err != nil {
		return fairUseOutboxState{}, fmt.Errorf("decode fair-use outbox: %w", err)
	}
	if err := validateFairUseOutboxState(base); err != nil {
		return fairUseOutboxState{}, fmt.Errorf("decode fair-use outbox: %w", err)
	}
	state = base
	opCount, err := applyFairUseOutboxLog(&state, completeFairUseOutboxLog(tail))
	if err != nil {
		return fairUseOutboxState{}, fmt.Errorf("decode fair-use outbox: %w", err)
	}
	if err := validateFairUseOutboxState(state); err != nil {
		return fairUseOutboxState{}, fmt.Errorf("decode fair-use outbox: %w", err)
	}
	// Whatever version was read, this outbox appends after the base it
	// writes, so that base must carry the append format's version.
	state.Version = fairUseOutboxVersion
	o.pendingOps = opCount
	return state, nil
}

// decodeFairUseOutboxBase decodes the leading base state object from raw and
// returns it along with any bytes remaining after it — the append-only log.
// It preserves the original single-object decode semantics (unknown-field
// and duplicate-field rejection scoped to that object) so a file with no
// trailing log entries decodes exactly as it always has.
func decodeFairUseOutboxBase(raw []byte) (fairUseOutboxState, []byte, error) {
	state := fairUseOutboxState{Version: fairUseOutboxVersion, Records: []fairUseOutboxRecord{}}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return fairUseOutboxState{}, nil, err
	}
	offset := decoder.InputOffset()
	if err := rejectDuplicateJSONFields(raw[:offset]); err != nil {
		return fairUseOutboxState{}, nil, err
	}
	return state, raw[offset:], nil
}

// completeFairUseOutboxLog drops a final log entry that has no terminating
// newline. An append reports success only after its entry and newline are
// written and synced, so an unterminated final entry is an append that failed
// part-way (a full disk, or a crash before the failed append was cut back) and
// no caller relied on it. json.Marshal escapes newlines inside strings, so an
// entry's only newline is its terminator. Bytes joined to the base object with
// no newline at all are not a log entry and are left to fail closed, as is a
// complete, newline-terminated entry that is malformed.
func completeFairUseOutboxLog(tail []byte) []byte {
	end := bytes.LastIndexByte(tail, '\n')
	if end < 0 {
		return tail
	}
	return tail[:end+1]
}

// applyFairUseOutboxLog decodes zero or more newline-delimited op entries
// from tail and applies each to state in order, returning how many were
// applied. A malformed or unrecognized entry fails closed, the same as a
// corrupt base object.
func applyFairUseOutboxLog(state *fairUseOutboxState, tail []byte) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(tail))
	decoder.DisallowUnknownFields()
	count := 0
	for {
		var entry fairUseOutboxLogEntry
		err := decoder.Decode(&entry)
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return 0, fmt.Errorf("decode fair-use outbox log entry: %w", err)
		}
		if err := applyFairUseOutboxOp(state, entry); err != nil {
			return 0, err
		}
		count++
	}
}

func applyFairUseOutboxOp(state *fairUseOutboxState, entry fairUseOutboxLogEntry) error {
	switch entry.Op {
	case fairUseOutboxOpAdd:
		if entry.Record == nil {
			return errors.New("fair-use outbox log add missing record")
		}
		if err := validateFairUseOutboxRecord(*entry.Record); err != nil {
			return err
		}
		for i, existing := range state.Records {
			if existing.BatchID == entry.Record.BatchID {
				state.Records[i] = *entry.Record
				return nil
			}
		}
		state.Records = append(state.Records, *entry.Record)
		return nil
	case fairUseOutboxOpRemove:
		if entry.BatchID == "" {
			return errors.New("fair-use outbox log remove missing batch id")
		}
		for i, existing := range state.Records {
			if existing.BatchID == entry.BatchID {
				state.Records = append(state.Records[:i], state.Records[i+1:]...)
				return nil
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown fair-use outbox log op %q", entry.Op)
	}
}

func validateFairUseOutboxState(state fairUseOutboxState) error {
	if (state.Version != fairUseOutboxVersion && state.Version != fairUseOutboxSingleObjectVersion) || state.Records == nil {
		return errors.New("unsupported state")
	}
	if len(state.Records) > maxFairUseOutboxRecords {
		return errors.New("record cardinality exceeds limit")
	}
	seen := make(map[string]struct{}, len(state.Records))
	var totalBytes int64
	for _, record := range state.Records {
		if err := validateFairUseOutboxRecord(record); err != nil {
			return err
		}
		if _, exists := seen[record.BatchID]; exists {
			return errors.New("duplicate batch id")
		}
		seen[record.BatchID] = struct{}{}
		if totalBytes > maxFairUseOutboxBytes-record.Bytes {
			return errors.New("aggregate bytes exceed limit")
		}
		totalBytes += record.Bytes
	}
	return nil
}

func validateFairUseOutboxRecord(record fairUseOutboxRecord) error {
	if !validLowerHex(record.TunnelDigest, sha256HexLength) {
		return errors.New("invalid tunnel digest")
	}
	if !validLowerHex(record.BatchID, fairUseBatchIDHexLength) {
		return errors.New("invalid batch id")
	}
	if record.Bytes <= 0 || record.Bytes > fairUseBatchBytes {
		return errors.New("invalid batch bytes")
	}
	if record.CreatedAt <= 0 || record.ExpiresAt <= record.CreatedAt {
		return errors.New("invalid record lifetime")
	}
	if record.ExpiresAt-record.CreatedAt > int64(maxFairUseOutboxRetention/time.Second) {
		return errors.New("record lifetime exceeds limit")
	}
	return nil
}

const (
	sha256HexLength         = 64
	fairUseBatchIDHexLength = 32
)

func validLowerHex(value string, want int) bool {
	if len(value) != want {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded)*2 != want {
		return false
	}
	return value == hex.EncodeToString(decoded)
}

func rejectDuplicateJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := walkUniqueJSON(decoder, token); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing state data")
	}
	return nil
}

func walkUniqueJSON(decoder *json.Decoder, token json.Token) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key must be a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate field %q", key)
			}
			seen[key] = struct{}{}
			valueToken, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkUniqueJSON(decoder, valueToken); err != nil {
				return err
			}
		}
		closeToken, err := decoder.Token()
		if err != nil || closeToken != json.Delim('}') {
			return errors.New("invalid object")
		}
	case '[':
		for decoder.More() {
			valueToken, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkUniqueJSON(decoder, valueToken); err != nil {
				return err
			}
		}
		closeToken, err := decoder.Token()
		if err != nil || closeToken != json.Delim(']') {
			return errors.New("invalid array")
		}
	default:
		return errors.New("unexpected closing delimiter")
	}
	return nil
}

func (o *fileFairUseOutbox) enqueue(record fairUseOutboxRecord) error {
	if err := validateFairUseOutboxRecord(record); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.usableLocked(); err != nil {
		return err
	}
	for _, existing := range o.state.Records {
		if existing.BatchID != record.BatchID {
			continue
		}
		if existing == record {
			return nil
		}
		return o.failLocked(errors.New("fair-use outbox batch id collision"))
	}
	if len(o.state.Records) >= o.recordLimit() {
		// Capacity is a live, self-recovering condition, not a fatal one:
		// it must not latch fatalErr, or draining records back below the
		// limit (which uses the same usableLocked gate) would be blocked
		// forever and readiness could only recover via process restart.
		return errFairUseOutboxRecordLimit
	}
	var totalBytes int64
	for _, existing := range o.state.Records {
		totalBytes += existing.Bytes
	}
	if totalBytes > o.byteLimit()-record.Bytes {
		return errFairUseOutboxByteLimit
	}
	if err := o.appendOp(fairUseOutboxLogEntry{Op: fairUseOutboxOpAdd, Record: &record}); err != nil {
		return o.failLocked(err)
	}
	o.state.Records = append(o.state.Records, record)
	o.pendingOps++
	o.updateReadinessHoldLocked()
	if err := o.compactIfDueLocked(); err != nil {
		return o.failLocked(err)
	}
	return nil
}

func (o *fileFairUseOutbox) remove(batchID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.usableLocked(); err != nil {
		return err
	}
	index := -1
	for i := range o.state.Records {
		if o.state.Records[i].BatchID == batchID {
			index = i
			break
		}
	}
	if index < 0 {
		return nil
	}
	if err := o.appendOp(fairUseOutboxLogEntry{Op: fairUseOutboxOpRemove, BatchID: batchID}); err != nil {
		return o.failLocked(err)
	}
	o.state.Records = append(o.state.Records[:index], o.state.Records[index+1:]...)
	o.pendingOps++
	o.updateReadinessHoldLocked()
	if err := o.compactIfDueLocked(); err != nil {
		return o.failLocked(err)
	}
	return nil
}

func (o *fileFairUseOutbox) records() ([]fairUseOutboxRecord, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.usableLocked(); err != nil {
		return nil, err
	}
	return append([]fairUseOutboxRecord(nil), o.state.Records...), nil
}

func (o *fileFairUseOutbox) replay(ctx context.Context, store sharedFairUseStore, now time.Time) error {
	records, err := o.records()
	if err != nil {
		return err
	}
	var replayErr error
	for _, record := range records {
		if now.Unix() < record.ExpiresAt {
			createdAt := time.Unix(record.CreatedAt, 0)
			if _, err := addFairUseDigest(ctx, store, record.TunnelDigest, record.BatchID, record.Bytes, createdAt); err != nil {
				if replayErr == nil {
					replayErr = err
				}
				continue
			}
		}
		if err := o.remove(record.BatchID); err != nil {
			return err
		}
	}
	return replayErr
}

func (o *fileFairUseOutbox) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.state.Records)
}

func (o *fileFairUseOutbox) pendingBytes() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	var total int64
	for _, record := range o.state.Records {
		total += record.Bytes
	}
	return total
}

func (o *fileFairUseOutbox) healthy() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.closed && o.fatalErr == nil && !o.readinessHeld
}

// updateReadinessHoldLocked re-derives readinessHeld after every change to
// the record set. Reaching capacity latches it; it clears once the record
// count drops below the limit minus the readiness band, so readiness
// recovers in-process as replay drains the outbox, without a restart, and
// does not flip back each time one record leaves a full outbox.
func (o *fileFairUseOutbox) updateReadinessHoldLocked() {
	if o.atCapacityLocked() {
		o.readinessHeld = true
		return
	}
	if len(o.state.Records) < o.recordLimit()-o.readinessBand() {
		o.readinessHeld = false
	}
}

// readinessBand is how many records below the limit the outbox must drain to
// before a capacity hold on readiness clears.
func (o *fileFairUseOutbox) readinessBand() int {
	return o.recordLimit() / fairUseOutboxReadinessBandDivisor
}

// atCapacityLocked reports whether the outbox is currently full, computed
// from the current record set. It mirrors enqueue's rejection conditions,
// using the largest possible next record (fairUseBatchBytes) in place of a
// specific candidate since a health check has none.
func (o *fileFairUseOutbox) atCapacityLocked() bool {
	if len(o.state.Records) >= o.recordLimit() {
		return true
	}
	var totalBytes int64
	for _, record := range o.state.Records {
		totalBytes += record.Bytes
	}
	return totalBytes > o.byteLimit()-fairUseBatchBytes
}

func (o *fileFairUseOutbox) recordLimit() int {
	if o.maxRecords > 0 {
		return o.maxRecords
	}
	return maxFairUseOutboxRecords
}

func (o *fileFairUseOutbox) byteLimit() int64 {
	if o.maxBytes > 0 {
		return o.maxBytes
	}
	return maxFairUseOutboxBytes
}

func (o *fileFairUseOutbox) usableLocked() error {
	if o.closed {
		return errors.New("fair-use outbox is closed")
	}
	if o.fatalErr != nil {
		return o.fatalErr
	}
	return nil
}

func (o *fileFairUseOutbox) failLocked(err error) error {
	if o.fatalErr == nil {
		o.fatalErr = err
	}
	return o.fatalErr
}

// appendOp durably writes one log entry to the end of the outbox file: O(1)
// cost independent of how many records or log entries already exist, unlike
// writeState's full rewrite. It reuses writeState's before/after-commit
// failpoint hooks around the write+sync that makes the entry authoritative.
func (o *fileFairUseOutbox) appendOp(entry fairUseOutboxLogEntry) error {
	if o.log == nil {
		log, err := openPrivateFairUseFile(o.path, os.O_WRONLY|os.O_APPEND)
		if err != nil {
			return fmt.Errorf("open fair-use outbox log: %w", err)
		}
		o.log = log
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode fair-use outbox log entry: %w", err)
	}
	payload = append(payload, '\n')
	if o.failpoint != nil {
		if err := o.failpoint(fairUseOutboxBeforeRename); err != nil {
			return err
		}
	}
	info, err := o.log.Stat()
	if err != nil {
		return fmt.Errorf("inspect fair-use outbox log: %w", err)
	}
	if err := o.writeLogEntry(payload); err != nil {
		return o.rollbackAppend(info.Size(), err)
	}
	if o.failpoint != nil {
		if err := o.failpoint(fairUseOutboxAfterRename); err != nil {
			return err
		}
	}
	return nil
}

// writeLogEntry writes and syncs one encoded log entry at the end of the log.
func (o *fileFairUseOutbox) writeLogEntry(payload []byte) error {
	write := (*os.File).Write
	if o.logWrite != nil {
		write = o.logWrite
	}
	if _, err := write(o.log, payload); err != nil {
		return fmt.Errorf("write fair-use outbox log entry: %w", err)
	}
	if err := o.log.Sync(); err != nil {
		return fmt.Errorf("sync fair-use outbox log entry: %w", err)
	}
	return nil
}

// rollbackAppend cuts the log back to size, its length before a failed
// append, so a write that stopped part-way through an entry leaves no partial
// line behind. The append error is returned either way, and the caller latches
// it as fatal; if the cut itself fails, restart still discards the
// unterminated final entry (completeFairUseOutboxLog).
func (o *fileFairUseOutbox) rollbackAppend(size int64, appendErr error) error {
	cutErr := o.log.Truncate(size)
	if cutErr == nil {
		cutErr = o.log.Sync()
	}
	if cutErr != nil {
		return errors.Join(appendErr, fmt.Errorf("truncate fair-use outbox log: %w", cutErr))
	}
	return appendErr
}

// compactIfDueLocked rewrites the outbox down to a single base object, via
// the unchanged writeState, once accumulated log entries exceed the live
// record count by fairUseOutboxCompactionSlack. Pure appends already cost
// O(1) regardless of outbox size; this bounds log file size under the
// add+remove churn of normal healthy operation.
func (o *fileFairUseOutbox) compactIfDueLocked() error {
	if o.pendingOps < len(o.state.Records)+fairUseOutboxCompactionSlack {
		return nil
	}
	return o.writeState(o.state)
}

func (o *fileFairUseOutbox) writeState(state fairUseOutboxState) error {
	dir := filepath.Dir(o.path)
	temp, err := os.CreateTemp(dir, ".fairuse-outbox-*")
	if err != nil {
		return fmt.Errorf("create fair-use outbox temp file: %w", err)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set fair-use outbox temp mode: %w", err)
	}
	encodeErr := json.NewEncoder(temp).Encode(state)
	syncErr := temp.Sync()
	closeErr := temp.Close()
	if encodeErr != nil {
		return fmt.Errorf("encode fair-use outbox: %w", encodeErr)
	}
	if syncErr != nil {
		return fmt.Errorf("sync fair-use outbox: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close fair-use outbox: %w", closeErr)
	}
	if o.failpoint != nil {
		if err := o.failpoint(fairUseOutboxBeforeRename); err != nil {
			return err
		}
	}
	if err := os.Rename(tempPath, o.path); err != nil {
		return fmt.Errorf("replace fair-use outbox: %w", err)
	}
	if o.failpoint != nil {
		if err := o.failpoint(fairUseOutboxAfterRename); err != nil {
			return err
		}
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open fair-use outbox directory: %w", err)
	}
	defer func() { _ = dirHandle.Close() }()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("sync fair-use outbox directory: %w", err)
	}
	// The file now holds state as a single base object with no trailing log
	// entries: any open append handle points at stale byte offsets and must
	// be reopened on the next append.
	if o.log != nil {
		_ = o.log.Close()
		o.log = nil
	}
	o.pendingOps = 0
	return nil
}

func (o *fileFairUseOutbox) close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	compactErr := o.compactForRollbackLocked()
	return errors.Join(compactErr, o.closeLock())
}

// compactForRollbackLocked rewrites the outbox as one single-object-version
// base with no log entries, the format a pre-append binary reads, so a clean
// shutdown leaves a file that a binary rollback can start from. It is skipped
// once a failure has latched: the file may then hold an entry that synced
// after its caller was told the write failed, which the in-memory state never
// applied, and only replaying the file on the next start reconciles the two.
func (o *fileFairUseOutbox) compactForRollbackLocked() error {
	if o.fatalErr != nil {
		return nil
	}
	state := o.state
	state.Version = fairUseOutboxSingleObjectVersion
	return o.writeState(state)
}

func (o *fileFairUseOutbox) closeLock() error {
	if o.log != nil {
		_ = o.log.Close()
		o.log = nil
	}
	var unlockErr error
	if o.lock != nil {
		unlockErr = syscall.Flock(int(o.lock.Fd()), syscall.LOCK_UN)
		closeErr := o.lock.Close()
		o.lock = nil
		if unlockErr == nil {
			unlockErr = closeErr
		}
	}
	return unlockErr
}
