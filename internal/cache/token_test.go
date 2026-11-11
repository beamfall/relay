package cache

import (
	"context"
	"testing"
	"time"
)

func TestHMACTokenVerifierAcceptsScopedUnexpiredToken(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	token, err := MintToken(testKey, "segset_123", now.Add(DefaultTokenTTL))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	access, err := (HMACTokenVerifier{
		Key: testKey,
		Now: func() time.Time {
			return now
		},
	}).VerifyCacheAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if access.SegmentSetID != "segset_123" {
		t.Fatalf("SegmentSetID = %q", access.SegmentSetID)
	}
}

func TestHMACTokenVerifierRejectsExpiredAndOverCeilingTokens(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	verifier := HMACTokenVerifier{
		Key: testKey,
		Now: func() time.Time {
			return now
		},
	}
	expired, err := MintToken(testKey, "segset", now.Add(-time.Second))
	if err != nil {
		t.Fatalf("mint expired: %v", err)
	}
	if _, err := verifier.VerifyCacheAccessToken(context.Background(), expired); err != ErrUnauthorized {
		t.Fatalf("expired verify err = %v, want unauthorized", err)
	}
	tooLong, err := MintToken(testKey, "segset", now.Add(MaxTokenTTL+time.Second))
	if err != nil {
		t.Fatalf("mint over ceiling: %v", err)
	}
	if _, err := verifier.VerifyCacheAccessToken(context.Background(), tooLong); err != ErrUnauthorized {
		t.Fatalf("over-ceiling verify err = %v, want unauthorized", err)
	}
}

func TestHMACTokenVerifierAcceptsCurrentAndPreviousKeysAcrossRotation(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	nextKey := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	keys, err := NewVerificationKeys(testKey)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	oldToken, err := MintToken(testKey, "segset", now.Add(DefaultTokenTTL))
	if err != nil {
		t.Fatalf("mint old: %v", err)
	}
	if err := keys.Rotate(nextKey); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	newToken, err := MintToken(nextKey, "segset", now.Add(DefaultTokenTTL))
	if err != nil {
		t.Fatalf("mint new: %v", err)
	}
	verifier := HMACTokenVerifier{
		Keys: keys,
		Now: func() time.Time {
			return now
		},
	}
	if _, err := verifier.VerifyCacheAccessToken(context.Background(), oldToken); err != nil {
		t.Fatalf("verify old token after rotation: %v", err)
	}
	if _, err := verifier.VerifyCacheAccessToken(context.Background(), newToken); err != nil {
		t.Fatalf("verify new token after rotation: %v", err)
	}
}
