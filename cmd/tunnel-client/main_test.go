package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/config"
	"github.com/beamfall/relay/internal/relay"
)

// writeCAPEM emits a self-signed CA certificate PEM to a temp file and returns
// its path, for exercising the --relay-ca pinning branch.
func writeCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-relay-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return path
}

func TestBuildCarrierTLSConfig(t *testing.T) {
	validCA := writeCAPEM(t)

	garbageCA := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbageCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write garbage ca: %v", err)
	}

	missingCA := filepath.Join(t.TempDir(), "does-not-exist.pem")

	t.Run("default verifies with system roots", func(t *testing.T) {
		cfg, err := buildCarrierTLSConfig(false, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.InsecureSkipVerify {
			t.Fatal("default config must NOT set InsecureSkipVerify")
		}
		if cfg.RootCAs != nil {
			t.Fatal("default config must use system roots (nil RootCAs), got a pool")
		}
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
		}
	})

	t.Run("insecure flag disables verification", func(t *testing.T) {
		cfg, err := buildCarrierTLSConfig(true, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.InsecureSkipVerify {
			t.Fatal("--insecure-skip-verify must set InsecureSkipVerify")
		}
	})

	t.Run("valid CA pins via RootCAs", func(t *testing.T) {
		cfg, err := buildCarrierTLSConfig(false, validCA)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.InsecureSkipVerify {
			t.Fatal("pinned-CA config must NOT set InsecureSkipVerify")
		}
		if cfg.RootCAs == nil {
			t.Fatal("valid --relay-ca must populate RootCAs")
		}
	})

	t.Run("garbage CA is an error", func(t *testing.T) {
		if _, err := buildCarrierTLSConfig(false, garbageCA); err == nil {
			t.Fatal("CA file with no certificates must error")
		}
	})

	t.Run("missing CA file is an error", func(t *testing.T) {
		if _, err := buildCarrierTLSConfig(false, missingCA); err == nil {
			t.Fatal("unreadable --relay-ca must error")
		}
	})

	t.Run("insecure wins over CA (documented precedence)", func(t *testing.T) {
		cfg, err := buildCarrierTLSConfig(true, validCA)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.InsecureSkipVerify {
			t.Fatal("insecure must take precedence over --relay-ca")
		}
		if cfg.RootCAs != nil {
			t.Fatal("insecure path must ignore --relay-ca (no RootCAs)")
		}
	})
}

// TestBuildTokenSourceStatic pins static mode: the loaded token bytes are
// presented verbatim and no per-dial provider is installed.
func TestBuildTokenSourceStatic(t *testing.T) {
	token, provider, err := buildTokenSource(tokenModeStatic, []byte("tok"), []string{"home.relay.test"}, time.Hour, "1")
	if err != nil {
		t.Fatalf("static mode: %v", err)
	}
	if string(token) != "tok" || provider != nil {
		t.Fatalf("static mode wiring: token=%q provider-installed=%t", token, provider != nil)
	}
}

func TestProductionConfigRejectsStaticCarrierToken(t *testing.T) {
	if defaultTokenMode != tokenModeHMAC {
		t.Fatalf("default token mode = %q, want %q", defaultTokenMode, tokenModeHMAC)
	}
	for _, devMode := range []string{"", "0", "true", "TRUE"} {
		_, _, err := buildTokenSource(tokenModeStatic, []byte("tok"), []string{"home.relay.test"}, time.Hour, devMode)
		if err == nil {
			t.Fatalf("static mode accepted with %s=%q", config.DevModeEnv, devMode)
		}
		const want = `--token-mode "static" is insecure-development-only and is refused in production because static bearer tokens never expire and are replayable if captured: set BEAMFALL_RELAY_DEV=1 to enable it`
		if err.Error() != want {
			t.Fatalf("static rejection = %q, want %q", err, want)
		}
	}
}

// TestBuildTokenSourceHMACMintsFreshVerifiableTokens pins hmac mode: each
// provider call mints a distinct (fresh-nonce) v2 token from the shared secret
// that the relay-side HMAC verifier accepts, so every reconnect presents an
// unexpired, never-before-seen token.
func TestBuildTokenSourceHMACMintsFreshVerifiableTokens(t *testing.T) {
	secret := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	hosts := []string{"home.relay.test"}
	if defaultTokenTTL != relay.MaxHMACTokenTTL {
		t.Fatalf("default token ttl = %s, verifier cap = %s", defaultTokenTTL, relay.MaxHMACTokenTTL)
	}
	token, provider, err := buildTokenSource(tokenModeHMAC, secret, hosts, defaultTokenTTL, "")
	if err != nil {
		t.Fatalf("hmac mode: %v", err)
	}
	if token != nil || provider == nil {
		t.Fatal("hmac mode must install a provider and no static token")
	}
	first, err := provider(context.Background())
	if err != nil {
		t.Fatalf("mint first token: %v", err)
	}
	second, err := provider(context.Background())
	if err != nil {
		t.Fatalf("mint second token: %v", err)
	}
	if string(first) == string(second) {
		t.Fatal("successive mints produced identical tokens (nonce not fresh)")
	}
	nonceStore, err := relay.NewFileHMACNonceStore(filepath.Join(t.TempDir(), "hmac-nonces.json"))
	if err != nil {
		t.Fatalf("new nonce store: %v", err)
	}
	verifier := &relay.HMACTokenVerifier{Secret: secret, Hostnames: hosts, NonceStore: nonceStore}
	if _, err := verifier.VerifyTunnelToken(context.Background(), first, hosts); err != nil {
		t.Fatalf("minted token rejected by relay hmac verifier: %v", err)
	}
}

// TestBuildTokenSourceRejectsBadInputs pins the fail-fast guards: an unknown
// mode and a non-positive TTL in hmac mode are startup errors.
func TestBuildTokenSourceRejectsBadInputs(t *testing.T) {
	if _, _, err := buildTokenSource("bogus", []byte("tok"), []string{"h"}, time.Hour, "1"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, _, err := buildTokenSource(tokenModeHMAC, []byte("tok"), []string{"h"}, 0, ""); err == nil {
		t.Fatal("non-positive ttl accepted in hmac mode")
	}
	if _, _, err := buildTokenSource(tokenModeHMAC, []byte("tok"), []string{"h"}, relay.MaxHMACTokenTTL+time.Second, ""); err == nil {
		t.Fatal("over-cap ttl accepted in hmac mode")
	}
}

func TestTokenExpiryRotationInterval(t *testing.T) {
	if got := tokenRotationInterval(tokenModeHMAC, time.Second); got != 500*time.Millisecond {
		t.Fatalf("hmac rotation interval = %v, want 500ms", got)
	}
	if got := tokenRotationInterval(tokenModeStatic, time.Second); got != 0 {
		t.Fatalf("static rotation interval = %v, want disabled", got)
	}
}
