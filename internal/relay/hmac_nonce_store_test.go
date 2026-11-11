package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const hmacNonceCrashHelperEnv = "BEAMFALL_HMAC_NONCE_CRASH_HELPER"

// TestFileHMACNonceStoreSurvivesSubprocessCrash proves an admitted nonce is
// durable even when the admitting process exits abruptly without running any
// deferred cleanup. A fresh process reopening the path must reject the replay.
func TestFileHMACNonceStoreSurvivesSubprocessCrash(t *testing.T) {
	if os.Getenv(hmacNonceCrashHelperEnv) == "1" {
		store, err := NewFileHMACNonceStore(os.Getenv("BEAMFALL_HMAC_NONCE_PATH"))
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(24)
		}
		nowUnixNano, err := strconv.ParseInt(os.Getenv("BEAMFALL_HMAC_NONCE_NOW"), 10, 64)
		if err != nil {
			os.Exit(25)
		}
		now := time.Unix(0, nowUnixNano)
		admitted, err := store.Admit(context.Background(), strings.Repeat("ab", hmacNonceBytes), now.Add(time.Minute), now)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(26)
		}
		if admitted {
			os.Exit(0) // Deliberately bypass all defers: model a process crash.
		}
		os.Exit(23)
	}

	path := filepath.Join(t.TempDir(), "hmac-nonces.json")
	now := time.Now()
	run := func(wantExit int) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestFileHMACNonceStoreSurvivesSubprocessCrash$")
		cmd.Env = append(os.Environ(),
			hmacNonceCrashHelperEnv+"=1",
			"BEAMFALL_HMAC_NONCE_PATH="+path,
			"BEAMFALL_HMAC_NONCE_NOW="+strconv.FormatInt(now.UnixNano(), 10),
		)
		err := cmd.Run()
		gotExit := 0
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("run crash helper: %v", err)
			}
			gotExit = exitErr.ExitCode()
		}
		if gotExit != wantExit {
			t.Fatalf("crash helper exit = %d, want %d", gotExit, wantExit)
		}
	}
	run(0)
	run(23)
}

func TestFileHMACNonceStoreRejectsReplayAcrossVerifiersAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac-nonces.json")
	firstStore, err := NewFileHMACNonceStore(path)
	if err != nil {
		t.Fatalf("new first store: %v", err)
	}
	secret := []byte("secret")
	hosts := []string{"home.relay.test"}
	token, err := MintHMACTunnelToken(secret, hosts, time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	firstVerifier := &HMACTokenVerifier{Secret: secret, Hostnames: hosts, NonceStore: firstStore}
	if _, err := firstVerifier.VerifyTunnelToken(context.Background(), token, hosts); err != nil {
		t.Fatalf("first verifier: %v", err)
	}

	// Constructing a distinct store value from the same path models another
	// process opening the persistent state after the first admission.
	reopenedStore, err := NewFileHMACNonceStore(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	reopenedVerifier := &HMACTokenVerifier{Secret: secret, Hostnames: hosts, NonceStore: reopenedStore}
	if _, err := reopenedVerifier.VerifyTunnelToken(context.Background(), token, hosts); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("reopened verifier err = %v, want ErrUnauthorized (persistent replay)", err)
	}
}

func TestFileHMACNonceStoreAdmissionIsAtomicAcrossInstances(t *testing.T) {
	const instances = 12
	path := filepath.Join(t.TempDir(), "hmac-nonces.json")
	stores := make([]*FileHMACNonceStore, instances)
	for i := range stores {
		store, err := NewFileHMACNonceStore(path)
		if err != nil {
			t.Fatalf("new store %d: %v", i, err)
		}
		stores[i] = store
	}

	now := time.Now()
	start := make(chan struct{})
	results := make(chan bool, instances)
	errs := make(chan error, instances)
	var wg sync.WaitGroup
	for _, store := range stores {
		wg.Add(1)
		go func(store *FileHMACNonceStore) {
			defer wg.Done()
			<-start
			admitted, err := store.Admit(context.Background(), strings.Repeat("bc", hmacNonceBytes), now.Add(time.Minute), now)
			if err != nil {
				errs <- err
				return
			}
			results <- admitted
		}(store)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Errorf("admit: %v", err)
	}
	admitted := 0
	for result := range results {
		if result {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("admitted = %d, want exactly 1", admitted)
	}
}

func TestFileHMACNonceStoreExpiresPersistedNonce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac-nonces.json")
	store, err := NewFileHMACNonceStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	now := time.Now()
	nonce := strings.Repeat("cd", hmacNonceBytes)
	if admitted, err := store.Admit(context.Background(), nonce, now.Add(time.Minute), now); err != nil || !admitted {
		t.Fatalf("first admit = %t, %v; want true, nil", admitted, err)
	}

	reopened, err := NewFileHMACNonceStore(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	if admitted, err := reopened.Admit(context.Background(), nonce, now.Add(3*time.Minute), now.Add(2*time.Minute)); err != nil || !admitted {
		t.Fatalf("post-expiry admit = %t, %v; want true, nil", admitted, err)
	}
}

func TestHMACV2RejectsOversizedNonceBeforePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac-nonces.json")
	store, err := NewFileHMACNonceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("secret")
	hosts := []string{"home.relay.test"}
	now := time.Now().Truncate(time.Second)
	issuedAt, expiresAt := now.Add(-time.Second), now.Add(time.Minute)
	nonce := strings.Repeat("ab", hmacNonceBytes+1)
	token := strings.Join([]string{
		hmacTokenV2Prefix,
		strconv.FormatInt(issuedAt.Unix(), 10),
		strconv.FormatInt(expiresAt.Unix(), 10),
		nonce,
		macV2(secret, hosts, issuedAt, expiresAt, nonce),
	}, ".")
	verifier := &HMACTokenVerifier{Secret: secret, Hostnames: hosts, Now: func() time.Time { return now }, NonceStore: store}
	if _, err := verifier.VerifyTunnelToken(context.Background(), []byte(token), hosts); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("oversized nonce error = %v, want ErrUnauthorized", err)
	}
	state, err := store.readState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Nonces) != 0 {
		t.Fatalf("oversized nonce mutated persistent state: %d entries", len(state.Nonces))
	}
}

func TestFileHMACNonceStoreRejectsOversizedStateBeforeDecode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac-nonces.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxHMACNonceStateBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileHMACNonceStore(path); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized state error = %v, want byte-limit error", err)
	}
}

func TestFileHMACNonceStoreFailsClosedWhenFull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac-nonces.json")
	now := time.Now()
	state := fileHMACNonceState{Version: 1, Nonces: make(map[string]int64, DefaultNonceStoreCapacity)}
	for i := 0; i < DefaultNonceStoreCapacity; i++ {
		state.Nonces[fmt.Sprintf("%032x", i)] = now.Add(time.Minute).UnixNano()
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileHMACNonceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := store.Admit(context.Background(), strings.Repeat("ff", hmacNonceBytes), now.Add(time.Minute), now)
	if admitted || err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("full-store admission = %t, %v; want false, full error", admitted, err)
	}
}
