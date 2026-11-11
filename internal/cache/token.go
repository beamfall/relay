package cache

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	TokenVersion       = "v1"
	MinTokenKeyBytes   = 32
	MaxTokenTTL        = 24 * time.Hour
	DefaultTokenTTL    = 6 * time.Hour
	tokenDistinctBytes = 16
)

var ErrUnauthorized = errors.New("unauthorized cache access token")

type VerifiedAccess struct {
	CarrierID    string
	SegmentSetID string
	ExpiresAt    time.Time
}

type TokenVerifier interface {
	VerifyCacheAccessToken(ctx context.Context, token string) (VerifiedAccess, error)
}

type HMACTokenVerifier struct {
	Key  []byte
	Keys *VerificationKeys
	Now  func() time.Time
}

func (v HMACTokenVerifier) Validate() error {
	if v.Keys != nil {
		return nil
	}
	return ValidateTokenKey(v.Key)
}

func (v HMACTokenVerifier) VerifyCacheAccessToken(ctx context.Context, token string) (VerifiedAccess, error) {
	select {
	case <-ctx.Done():
		return VerifiedAccess{}, ctx.Err()
	default:
	}
	parts := strings.Split(token, "|")
	if len(parts) != 4 || parts[0] != TokenVersion {
		return VerifiedAccess{}, ErrUnauthorized
	}
	segmentSetID := parts[1]
	if err := validateSegmentSetID(segmentSetID); err != nil {
		return VerifiedAccess{}, ErrUnauthorized
	}
	expUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return VerifiedAccess{}, ErrUnauthorized
	}
	expiresAt := time.Unix(expUnix, 0)
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if !expiresAt.After(now()) || expiresAt.Sub(now()) > MaxTokenTTL {
		return VerifiedAccess{}, ErrUnauthorized
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return VerifiedAccess{}, ErrUnauthorized
	}
	ok := false
	for _, key := range v.keys() {
		want := signToken(key, parts[0], segmentSetID, parts[2])
		if subtle.ConstantTimeCompare(got, want) == 1 {
			ok = true
		}
	}
	if !ok {
		return VerifiedAccess{}, ErrUnauthorized
	}
	return VerifiedAccess{SegmentSetID: segmentSetID, ExpiresAt: expiresAt}, nil
}

func (v HMACTokenVerifier) keys() [][]byte {
	if v.Keys != nil {
		return v.Keys.Snapshot()
	}
	return [][]byte{v.Key}
}

type VerificationKeys struct {
	mu       sync.RWMutex
	current  []byte
	previous []byte
}

func NewVerificationKeys(current []byte) (*VerificationKeys, error) {
	if err := ValidateTokenKey(current); err != nil {
		return nil, err
	}
	return &VerificationKeys{current: append([]byte(nil), current...)}, nil
}

func (k *VerificationKeys) Rotate(current []byte) error {
	if err := ValidateTokenKey(current); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.previous = append(k.previous[:0], k.current...)
	k.current = append(k.current[:0], current...)
	return nil
}

func (k *VerificationKeys) Snapshot() [][]byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	keys := [][]byte{append([]byte(nil), k.current...)}
	if len(k.previous) != 0 {
		keys = append(keys, append([]byte(nil), k.previous...))
	}
	return keys
}

func MintToken(key []byte, segmentSetID string, expiresAt time.Time) (string, error) {
	if err := ValidateTokenKey(key); err != nil {
		return "", err
	}
	if err := validateSegmentSetID(segmentSetID); err != nil {
		return "", err
	}
	exp := strconv.FormatInt(expiresAt.Unix(), 10)
	sig := base64.RawURLEncoding.EncodeToString(signToken(key, TokenVersion, segmentSetID, exp))
	return strings.Join([]string{TokenVersion, segmentSetID, exp, sig}, "|"), nil
}

func ValidateTokenKey(key []byte) error {
	if len(key) < MinTokenKeyBytes {
		return fmt.Errorf("cache token key too short: %d bytes, need at least %d", len(key), MinTokenKeyBytes)
	}
	var seen [256]bool
	distinct := 0
	for _, b := range key {
		if !seen[b] {
			seen[b] = true
			distinct++
		}
	}
	if distinct < tokenDistinctBytes {
		return fmt.Errorf("cache token key too low-entropy: %d distinct byte values, need at least %d", distinct, tokenDistinctBytes)
	}
	return nil
}

func signToken(key []byte, version, segmentSetID, exp string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(version))
	mac.Write([]byte("|"))
	mac.Write([]byte(segmentSetID))
	mac.Write([]byte("|"))
	mac.Write([]byte(exp))
	return mac.Sum(nil)
}

func validateSegmentSetID(id string) error {
	if id == "" || len(id) > 256 {
		return errors.New("invalid segment-set id")
	}
	for _, r := range id {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return errors.New("invalid segment-set id")
	}
	return nil
}
