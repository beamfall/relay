package cache

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxStructuredNodeBytes int64 = 64 * 1024
const cacheTxnVersion = 3

type storedMeta struct {
	Segment     string    `json:"segment,omitempty"`
	ContentType string    `json:"contentType"`
	ExpiresAt   time.Time `json:"expiresAt"`
	BlobSHA256  string    `json:"blobSha256"`
}

type txnPhase string

const (
	phaseStaging       txnPhase = "staging"
	phaseStaged        txnPhase = "staged"
	phaseBackingUp     txnPhase = "backing_up"
	phaseBackedUp      txnPhase = "backed_up"
	phaseBlobPublished txnPhase = "blob_published"
	phaseCommitted     txnPhase = "committed"
	phaseRollingBack   txnPhase = "rolling_back"
)

type cacheTxn struct {
	Version          int      `json:"version,omitempty"`
	ID               string   `json:"id"`
	TenantHash       string   `json:"tenantHash"`
	SegmentHash      string   `json:"segmentHash"`
	Phase            txnPhase `json:"phase"`
	NewBlobSHA256    string   `json:"newBlobSha256"`
	NewMetaSHA256    string   `json:"newMetaSha256"`
	OldBlobSHA256    string   `json:"oldBlobSha256,omitempty"`
	OldMetaSHA256    string   `json:"oldMetaSha256,omitempty"`
	BlobCreatedByTxn bool     `json:"blobCreatedByTxn"`
	MetaCreatedByTxn bool     `json:"metaCreatedByTxn"`
	MAC              string   `json:"mac"`
}

type nodeState struct {
	exists bool
	size   int64
	digest string
	body   []byte
}

type txnSnapshot struct {
	liveBlob, liveMeta nodeState
	newBlob, newMeta   nodeState
	oldBlob, oldMeta   nodeState
}

type committedTxnError struct{ err error }

func (e committedTxnError) Error() string { return e.err.Error() }
func (e committedTxnError) Unwrap() error { return e.err }

func transactionCommitted(err error) bool {
	var committed committedTxnError
	return errors.As(err, &committed)
}

func (s *Store) stageTransaction(tenantDir, blobName string, blob, meta []byte, oldBlobSHA, oldMetaSHA string) (cacheTxn, string, error) {
	if err := s.verifyTenantDir(tenantDir); err != nil {
		return cacheTxn{}, "", err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return cacheTxn{}, "", fmt.Errorf("create cache transaction id: %w", err)
	}
	txn := cacheTxn{
		Version: cacheTxnVersion, ID: hex.EncodeToString(nonce[:]),
		TenantHash:  filepath.Base(tenantDir),
		SegmentHash: strings.TrimSuffix(blobName, ".bin"), Phase: phaseStaging,
		NewBlobSHA256: fileDigest(blob), NewMetaSHA256: fileDigest(meta),
		OldBlobSHA256: oldBlobSHA, OldMetaSHA256: oldMetaSHA,
		BlobCreatedByTxn: oldBlobSHA == "", MetaCreatedByTxn: oldMetaSHA == "",
	}
	txnDir := filepath.Join(tenantDir, ".txn-"+txn.ID)
	if err := s.mkdirPath(txnDir); err != nil {
		return cacheTxn{}, "", fmt.Errorf("create cache transaction: %w", err)
	}
	if err := s.syncMutation("create-transaction", tenantDir, txnDir); err != nil {
		return cacheTxn{}, "", s.abortStage(tenantDir, txnDir, err)
	}
	if err := s.writeJournal(tenantDir, txnDir, &txn, phaseStaging); err != nil {
		return cacheTxn{}, "", s.abortStage(tenantDir, txnDir, err)
	}
	if err := s.writeDurable(filepath.Join(txnDir, "new.bin"), blob); err != nil {
		return cacheTxn{}, "", s.abortStage(tenantDir, txnDir, fmt.Errorf("stage cache segment: %w", err))
	}
	if err := s.syncMutation("stage-blob", tenantDir, txnDir); err != nil {
		return cacheTxn{}, "", s.abortStage(tenantDir, txnDir, err)
	}
	if err := s.writeDurable(filepath.Join(txnDir, "new.json"), meta); err != nil {
		return cacheTxn{}, "", s.abortStage(tenantDir, txnDir, fmt.Errorf("stage cache metadata: %w", err))
	}
	if err := s.syncMutation("stage-metadata", tenantDir, txnDir); err != nil {
		return cacheTxn{}, "", s.abortStage(tenantDir, txnDir, err)
	}
	if err := s.validateNewPair(txnDir, txn); err != nil {
		return cacheTxn{}, "", s.abortStage(tenantDir, txnDir, err)
	}
	if err := s.writeJournal(tenantDir, txnDir, &txn, phaseStaged); err != nil {
		return cacheTxn{}, "", s.abortStage(tenantDir, txnDir, err)
	}
	return txn, txnDir, nil
}

func (s *Store) abortStage(tenantDir, txnDir string, cause error) error {
	if s.leaveFailedTransaction {
		return cause
	}
	if err := s.removeTransaction(tenantDir, txnDir); err != nil {
		return fmt.Errorf("%v; clean cache staging: %w", cause, err)
	}
	return cause
}

func (s *Store) publishTransaction(tenantDir, txnDir string, txn cacheTxn) error {
	if err := s.verifyTenantDir(tenantDir); err != nil {
		return err
	}
	snapshot, err := s.inspectTransaction(tenantDir, txnDir, txn)
	if err != nil {
		return err
	}
	if err := validatePhase(snapshot, txn, phaseStaged); err != nil {
		return err
	}
	return s.advanceTransaction(tenantDir, txnDir, &txn, snapshot)
}

func (s *Store) advanceTransaction(tenantDir, txnDir string, txn *cacheTxn, snapshot txnSnapshot) error {
	if err := s.verifyTenantDir(tenantDir); err != nil {
		return err
	}
	if txn.Phase == phaseStaged {
		if err := s.writeJournal(tenantDir, txnDir, txn, phaseBackingUp); err != nil {
			return err
		}
		txn.Phase = phaseBackingUp
	}
	if txn.Phase == phaseBackingUp {
		for _, move := range []struct {
			name, from, to string
			live           nodeState
		}{
			{"backup-blob", filepath.Join(tenantDir, txn.SegmentHash+".bin"), filepath.Join(txnDir, "old.bin"), snapshot.liveBlob},
			{"backup-metadata", filepath.Join(tenantDir, txn.SegmentHash+".json"), filepath.Join(txnDir, "old.json"), snapshot.liveMeta},
		} {
			if move.live.exists {
				if err := s.renameRequired(move.from, move.to); err != nil {
					return fmt.Errorf("%s: %w", move.name, err)
				}
				if err := s.syncMutation(move.name, tenantDir, txnDir); err != nil {
					return err
				}
			}
		}
		if err := s.writeJournal(tenantDir, txnDir, txn, phaseBackedUp); err != nil {
			return err
		}
		txn.Phase = phaseBackedUp
	}
	if txn.Phase == phaseBackedUp {
		if snapshot.newBlob.exists {
			if err := s.renameRequired(filepath.Join(txnDir, "new.bin"), filepath.Join(tenantDir, txn.SegmentHash+".bin")); err != nil {
				return fmt.Errorf("publish blob: %w", err)
			}
			if err := s.syncMutation("publish-blob", tenantDir, txnDir); err != nil {
				return err
			}
		}
		if err := s.writeJournal(tenantDir, txnDir, txn, phaseBlobPublished); err != nil {
			return err
		}
		txn.Phase = phaseBlobPublished
	}
	if txn.Phase == phaseBlobPublished {
		if snapshot.newMeta.exists {
			if err := s.renameRequired(filepath.Join(txnDir, "new.json"), filepath.Join(tenantDir, txn.SegmentHash+".json")); err != nil {
				return fmt.Errorf("publish metadata: %w", err)
			}
			if err := s.syncMutation("publish-metadata", tenantDir, txnDir); err != nil {
				return err
			}
		}
		if err := s.writeJournal(tenantDir, txnDir, txn, phaseCommitted); err != nil {
			return committedTxnError{err}
		}
		txn.Phase = phaseCommitted
	}
	if err := s.removeTransaction(tenantDir, txnDir); err != nil {
		return committedTxnError{err}
	}
	return nil
}

func rollbackTransaction(s *Store, tenantDir, txnDir string, txn cacheTxn) error {
	if err := s.verifyTenantDir(tenantDir); err != nil {
		return err
	}
	snapshot, err := s.inspectTransaction(tenantDir, txnDir, txn)
	if err != nil {
		return err
	}
	if err := validateRollbackSnapshot(snapshot, txn); err != nil {
		return err
	}
	if txn.Phase != phaseRollingBack {
		if err := s.writeJournal(tenantDir, txnDir, &txn, phaseRollingBack); err != nil {
			return err
		}
		txn.Phase = phaseRollingBack
	}
	for _, item := range []struct {
		livePath, oldPath string
		live, old         nodeState
		newSHA            string
		createdByTxn      bool
	}{
		{
			filepath.Join(tenantDir, txn.SegmentHash+".bin"), filepath.Join(txnDir, "old.bin"),
			snapshot.liveBlob, snapshot.oldBlob, txn.NewBlobSHA256,
			createdByTransaction(txn.Version, txn.BlobCreatedByTxn, txn.OldBlobSHA256),
		},
		{
			filepath.Join(tenantDir, txn.SegmentHash+".json"), filepath.Join(txnDir, "old.json"),
			snapshot.liveMeta, snapshot.oldMeta, txn.NewMetaSHA256,
			createdByTransaction(txn.Version, txn.MetaCreatedByTxn, txn.OldMetaSHA256),
		},
	} {
		if err := s.verifyTenantDir(tenantDir); err != nil {
			return err
		}
		if item.old.exists {
			if err := s.renameRequired(item.oldPath, item.livePath); err != nil {
				return err
			}
			if err := s.syncMutation("rollback-restore-old", tenantDir, txnDir); err != nil {
				return err
			}
			continue
		}
		if item.createdByTxn && item.live.exists && item.live.digest == item.newSHA {
			if err := s.removePath(item.livePath); err != nil {
				return err
			}
			if err := s.syncMutation("rollback-remove-new", tenantDir, txnDir); err != nil {
				return err
			}
		}
	}
	return s.removeTransaction(tenantDir, txnDir)
}

func validateRollbackSnapshot(snapshot txnSnapshot, txn cacheTxn) error {
	if err := validateRecoverable(snapshot, txn); err != nil {
		return err
	}
	if (txn.OldBlobSHA256 == "") != (txn.OldMetaSHA256 == "") {
		return errors.New("cache transaction old pair is incomplete")
	}
	if !rollbackOldPreserved(
		snapshot.liveBlob, snapshot.oldBlob, txn.OldBlobSHA256, txn.NewBlobSHA256,
		createdByTransaction(txn.Version, txn.BlobCreatedByTxn, txn.OldBlobSHA256),
	) || !rollbackOldPreserved(
		snapshot.liveMeta, snapshot.oldMeta, txn.OldMetaSHA256, txn.NewMetaSHA256,
		createdByTransaction(txn.Version, txn.MetaCreatedByTxn, txn.OldMetaSHA256),
	) {
		return errors.New("cache rollback lost old publication provenance")
	}
	return nil
}

func (s *Store) writeJournal(tenantDir, txnDir string, txn *cacheTxn, phase txnPhase) error {
	if err := s.verifyTenantDir(tenantDir); err != nil {
		return err
	}
	txn.Phase = phase
	txn.MAC = s.transactionMAC(*txn)
	body, err := json.Marshal(txn)
	if err != nil {
		return fmt.Errorf("marshal cache transaction: %w", err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temp := filepath.Join(txnDir, ".journal-"+hex.EncodeToString(nonce[:]))
	if err := s.writeDurable(temp, body); err != nil {
		return fmt.Errorf("write cache transaction: %w", err)
	}
	if err := s.renameRequired(temp, filepath.Join(txnDir, "transaction.json")); err != nil {
		return fmt.Errorf("publish cache transaction journal: %w", err)
	}
	return s.syncMutation("phase-"+string(phase), tenantDir, txnDir)
}

func (s *Store) syncMutation(name, tenantDir, txnDir string) error {
	if err := s.step("before-sync-" + name); err != nil {
		return err
	}
	if err := s.verifyTenantDir(tenantDir); err != nil {
		return err
	}
	if err := s.syncDir(txnDir); err != nil {
		return err
	}
	if err := s.syncDir(tenantDir); err != nil {
		return err
	}
	if err := s.step("after-" + name); err != nil {
		return err
	}
	return s.verifyTenantDir(tenantDir)
}

func (s *Store) removeTransaction(tenantDir, txnDir string) error {
	if err := s.step("before-cleanup"); err != nil {
		return err
	}
	if err := s.verifyTenantDir(tenantDir); err != nil {
		return err
	}
	if err := s.removeTree(txnDir); err != nil {
		return fmt.Errorf("remove cache transaction: %w", err)
	}
	if err := s.step("before-sync-cleanup"); err != nil {
		return err
	}
	if err := s.syncDir(tenantDir); err != nil {
		return err
	}
	if err := s.step("after-cleanup"); err != nil {
		return err
	}
	return s.verifyTenantDir(tenantDir)
}

func (s *Store) step(name string) error {
	if s.failStep == nil {
		return nil
	}
	return s.failStep(name)
}

func (s *Store) inspectTransaction(tenantDir, txnDir string, txn cacheTxn) (txnSnapshot, error) {
	dir, err := s.openDirectory(txnDir)
	if err != nil {
		return txnSnapshot{}, err
	}
	if err := dir.Close(); err != nil {
		return txnSnapshot{}, err
	}
	paths := []string{
		filepath.Join(tenantDir, txn.SegmentHash+".bin"),
		filepath.Join(tenantDir, txn.SegmentHash+".json"),
		filepath.Join(txnDir, "new.bin"), filepath.Join(txnDir, "new.json"),
		filepath.Join(txnDir, "old.bin"), filepath.Join(txnDir, "old.json"),
	}
	nodes := make([]nodeState, len(paths))
	for i, path := range paths {
		node, err := s.readNode(path, s.nodeLimit(path))
		if err != nil {
			return txnSnapshot{}, err
		}
		nodes[i] = node
	}
	return txnSnapshot{
		liveBlob: nodes[0], liveMeta: nodes[1], newBlob: nodes[2],
		newMeta: nodes[3], oldBlob: nodes[4], oldMeta: nodes[5],
	}, nil
}

func (s *Store) validateNewPair(txnDir string, txn cacheTxn) error {
	blob, err := s.readNode(filepath.Join(txnDir, "new.bin"), s.TenantCapBytes)
	if err != nil {
		return err
	}
	meta, err := s.readNode(filepath.Join(txnDir, "new.json"), maxStructuredNodeBytes)
	if err != nil {
		return err
	}
	if !blob.exists || blob.digest != txn.NewBlobSHA256 || !meta.exists || meta.digest != txn.NewMetaSHA256 {
		return errors.New("cache transaction staged pair mismatch")
	}
	var decoded storedMeta
	if json.Unmarshal(meta.body, &decoded) != nil || decoded.Segment == "" || decoded.BlobSHA256 != blob.digest {
		return errors.New("cache transaction metadata does not bind staged blob")
	}
	return nil
}

func validatePhase(s txnSnapshot, txn cacheTxn, phase txnPhase) error {
	if err := validateRecoverable(s, txn); err != nil {
		return err
	}
	oldBlobAbsent := txn.OldBlobSHA256 == ""
	oldMetaAbsent := txn.OldMetaSHA256 == ""
	switch phase {
	case phaseStaged:
		if !matches(s.newBlob, txn.NewBlobSHA256) || !matches(s.newMeta, txn.NewMetaSHA256) ||
			s.oldBlob.exists || s.oldMeta.exists ||
			!matchesAbsentOr(s.liveBlob, txn.OldBlobSHA256) || !matchesAbsentOr(s.liveMeta, txn.OldMetaSHA256) {
			return errors.New("invalid staged cache transaction")
		}
	case phaseBackingUp:
		if !matches(s.newBlob, txn.NewBlobSHA256) || !matches(s.newMeta, txn.NewMetaSHA256) ||
			!distributedOld(s.liveBlob, s.oldBlob, txn.OldBlobSHA256) ||
			!distributedOld(s.liveMeta, s.oldMeta, txn.OldMetaSHA256) {
			return errors.New("invalid cache backup phase")
		}
	case phaseBackedUp:
		if !matches(s.newMeta, txn.NewMetaSHA256) || s.liveMeta.exists ||
			!distributedNew(s.newBlob, s.liveBlob, txn.NewBlobSHA256) ||
			!matchesAbsentOr(s.oldBlob, txn.OldBlobSHA256) ||
			!matchesAbsentOr(s.oldMeta, txn.OldMetaSHA256) {
			return errors.New("invalid backed-up cache transaction")
		}
	case phaseBlobPublished:
		if !matches(s.liveBlob, txn.NewBlobSHA256) || s.newBlob.exists ||
			!distributedNew(s.newMeta, s.liveMeta, txn.NewMetaSHA256) ||
			!matchesAbsentOr(s.oldBlob, txn.OldBlobSHA256) ||
			!matchesAbsentOr(s.oldMeta, txn.OldMetaSHA256) {
			return errors.New("invalid cache blob publication")
		}
	case phaseCommitted:
		if !matches(s.liveBlob, txn.NewBlobSHA256) || !matches(s.liveMeta, txn.NewMetaSHA256) ||
			s.newBlob.exists || s.newMeta.exists ||
			!matchesAbsentOr(s.oldBlob, txn.OldBlobSHA256) ||
			!matchesAbsentOr(s.oldMeta, txn.OldMetaSHA256) {
			return errors.New("invalid committed cache transaction")
		}
	default:
		return errors.New("unknown cache transaction phase")
	}
	if oldBlobAbsent != oldMetaAbsent {
		return errors.New("cache transaction old pair is incomplete")
	}
	return nil
}

func validateRecoverable(s txnSnapshot, txn cacheTxn) error {
	if err := validateCreationProvenance(txn); err != nil {
		return err
	}
	allowed := []struct {
		node          nodeState
		first, second string
	}{
		{s.liveBlob, txn.OldBlobSHA256, txn.NewBlobSHA256},
		{s.liveMeta, txn.OldMetaSHA256, txn.NewMetaSHA256},
		{s.newBlob, txn.NewBlobSHA256, ""}, {s.newMeta, txn.NewMetaSHA256, ""},
		{s.oldBlob, txn.OldBlobSHA256, ""}, {s.oldMeta, txn.OldMetaSHA256, ""},
	}
	for _, item := range allowed {
		if item.node.exists && item.node.digest != item.first && item.node.digest != item.second {
			return errors.New("cache transaction node provenance mismatch")
		}
	}
	return nil
}

func validateCreationProvenance(txn cacheTxn) error {
	if txn.Version == 0 {
		return nil
	}
	if txn.Version != cacheTxnVersion {
		return errors.New("unsupported cache transaction version")
	}
	if txn.BlobCreatedByTxn != (txn.OldBlobSHA256 == "") ||
		txn.MetaCreatedByTxn != (txn.OldMetaSHA256 == "") {
		return errors.New("cache transaction creation provenance mismatch")
	}
	return nil
}

func createdByTransaction(version int, declared bool, oldDigest string) bool {
	if version == 0 {
		return oldDigest == ""
	}
	return declared
}

func matches(node nodeState, digest string) bool {
	return digest != "" && node.exists && node.digest == digest
}

func matchesAbsentOr(node nodeState, digest string) bool {
	if digest == "" {
		return !node.exists
	}
	return matches(node, digest)
}

func distributedOld(live, backup nodeState, digest string) bool {
	if digest == "" {
		return !live.exists && !backup.exists
	}
	return matches(live, digest) != matches(backup, digest)
}

func distributedNew(staged, live nodeState, digest string) bool {
	return matches(staged, digest) != matches(live, digest)
}

func (s *Store) nodeLimit(path string) int64 {
	name := filepath.Base(path)
	if filepath.Ext(name) == ".json" || strings.HasPrefix(name, ".journal-") {
		return maxStructuredNodeBytes
	}
	return s.TenantCapBytes
}

func (s *Store) renameRequired(from, to string) error {
	if _, err := s.readNode(from, s.nodeLimit(from)); err != nil {
		return err
	}
	return s.renamePath(from, to)
}

func fileDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (s *Store) readStoredMeta(path string) (storedMeta, error) {
	node, err := s.readNode(path, maxStructuredNodeBytes)
	if err != nil {
		return storedMeta{}, err
	}
	if !node.exists {
		return storedMeta{}, os.ErrNotExist
	}
	var meta storedMeta
	if err := json.Unmarshal(node.body, &meta); err != nil {
		return storedMeta{}, fmt.Errorf("parse cache metadata: %w", err)
	}
	return meta, nil
}

func (s *Store) transactionMAC(txn cacheTxn) string {
	if txn.Version == 0 {
		return hmacHex(s.Key, strings.Join([]string{
			"cache-txn-v2", txn.ID, txn.TenantHash, txn.SegmentHash, string(txn.Phase),
			txn.NewBlobSHA256, txn.NewMetaSHA256, txn.OldBlobSHA256, txn.OldMetaSHA256,
		}, "\x00"))
	}
	return hmacHex(s.Key, strings.Join([]string{
		"cache-txn-v3", txn.ID, txn.TenantHash, txn.SegmentHash, string(txn.Phase),
		txn.NewBlobSHA256, txn.NewMetaSHA256, txn.OldBlobSHA256, txn.OldMetaSHA256,
		fmt.Sprint(txn.BlobCreatedByTxn), fmt.Sprint(txn.MetaCreatedByTxn),
	}, "\x00"))
}

func (s *Store) reconcileTransactions() error {
	tenants, err := s.readDirectory(s.Root)
	if err != nil {
		return fmt.Errorf("scan cache transactions: %w", err)
	}
	for _, tenant := range tenants {
		if tenant.IsDir() && !strings.HasPrefix(tenant.Name(), ".") {
			tenantDir := filepath.Join(s.Root, tenant.Name())
			pinned, err := s.openTenantDir(tenantDir, false)
			if err != nil {
				return err
			}
			err = s.reconcileTenant(tenantDir)
			if err == nil {
				err = pinned.verify()
			}
			pinned.close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) reconcileTenant(tenantDir string) error {
	pinned, err := s.openTenantDir(tenantDir, false)
	if err != nil {
		return err
	}
	defer pinned.close()
	entries, err := s.readDirectory(tenantDir)
	if err != nil {
		return fmt.Errorf("scan tenant cache transactions: %w", err)
	}
	changed := false
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".txn-") {
			continue
		}
		txnDir := filepath.Join(tenantDir, entry.Name())
		journal, err := s.readNode(filepath.Join(txnDir, "transaction.json"), maxStructuredNodeBytes)
		if err != nil || !journal.exists {
			continue
		}
		var txn cacheTxn
		if json.Unmarshal(journal.body, &txn) != nil || !validTxnName(tenantDir, entry.Name(), txn) ||
			txn.Version != 0 && txn.Version != cacheTxnVersion ||
			!hmac.Equal([]byte(txn.MAC), []byte(s.transactionMAC(txn))) {
			continue
		}
		changed = true
		if err := s.recoverTransaction(tenantDir, txnDir, txn); err != nil {
			s.invalidateUsed(tenantDir)
			return fmt.Errorf("reconcile cache transaction: %w", err)
		}
	}
	if changed {
		s.invalidateUsed(tenantDir)
	}
	return pinned.verify()
}

func validTxnName(tenantDir, name string, txn cacheTxn) bool {
	if name != ".txn-"+txn.ID || txn.TenantHash != filepath.Base(tenantDir) ||
		len(txn.ID) != 32 || len(txn.SegmentHash) != 64 {
		return false
	}
	_, idErr := hex.DecodeString(txn.ID)
	_, segmentErr := hex.DecodeString(txn.SegmentHash)
	return idErr == nil && segmentErr == nil
}

func (s *Store) recoverTransaction(tenantDir, txnDir string, txn cacheTxn) error {
	snapshot, err := s.inspectTransaction(tenantDir, txnDir, txn)
	if err != nil {
		return err
	}
	if txn.Phase == phaseStaging {
		if err := validateRecoverable(snapshot, txn); err != nil {
			return err
		}
		return s.removeTransaction(tenantDir, txnDir)
	}
	if txn.Phase == phaseRollingBack {
		return rollbackTransaction(s, tenantDir, txnDir, txn)
	}
	if err := validatePhase(snapshot, txn, txn.Phase); err != nil {
		if txn.Phase == phaseStaged &&
			matchesAbsentOr(snapshot.liveBlob, txn.OldBlobSHA256) &&
			matchesAbsentOr(snapshot.liveMeta, txn.OldMetaSHA256) &&
			!snapshot.oldBlob.exists && !snapshot.oldMeta.exists {
			return s.removeTransaction(tenantDir, txnDir)
		}
		if unrelatedLive(snapshot, txn) {
			return s.removeTransaction(tenantDir, txnDir)
		}
		return err
	}
	return s.advanceTransaction(tenantDir, txnDir, &txn, snapshot)
}

func unrelatedLive(snapshot txnSnapshot, txn cacheTxn) bool {
	return snapshot.liveBlob.exists &&
		snapshot.liveBlob.digest != txn.OldBlobSHA256 &&
		snapshot.liveBlob.digest != txn.NewBlobSHA256 ||
		snapshot.liveMeta.exists &&
			snapshot.liveMeta.digest != txn.OldMetaSHA256 &&
			snapshot.liveMeta.digest != txn.NewMetaSHA256
}
