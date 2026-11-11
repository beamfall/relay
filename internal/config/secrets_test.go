package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretFromEnvOrFilePrefersEnv(t *testing.T) {
	got, err := SecretFromEnvOrFile("from-env", "")
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if string(got) != "from-env" {
		t.Fatalf("secret = %q", got)
	}
}

func TestSecretFromEnvOrFileTrimsEnvLikeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("  token-value  \n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	fromFile, err := SecretFromEnvOrFile("", path)
	if err != nil {
		t.Fatalf("file secret: %v", err)
	}
	fromEnv, err := SecretFromEnvOrFile("  token-value  \n", "")
	if err != nil {
		t.Fatalf("env secret: %v", err)
	}
	if string(fromEnv) != string(fromFile) {
		t.Fatalf("env secret %q != file secret %q", fromEnv, fromFile)
	}
	if string(fromEnv) != "token-value" {
		t.Fatalf("env secret = %q, want trimmed", fromEnv)
	}
}

func TestSecretFromEnvOrFileWhitespaceEnvFallsThroughToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	got, err := SecretFromEnvOrFile("   ", path)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if string(got) != "from-file" {
		t.Fatalf("secret = %q, want file fallback", got)
	}
}

func TestSecretFromEnvOrFileRequires0600File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o644); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if _, err := SecretFromEnvOrFile("", path); err == nil {
		t.Fatal("expected world-readable secret file to fail")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod secret: %v", err)
	}
	got, err := SecretFromEnvOrFile("", path)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if string(got) != "from-file" {
		t.Fatalf("secret = %q", got)
	}
}

// TestOptionalSecretFromEnvOrFile pins the optional-secret contract: absent on
// both sources is nil/no-error (the default loopback-admin relayd deployment
// must start with no /metrics credential — regression for the TECHAUDIT-7-RELAY
// startup failure), while a set source still goes through the strict loader.
func TestOptionalSecretFromEnvOrFile(t *testing.T) {
	secret, err := OptionalSecretFromEnvOrFile("", "")
	if err != nil || secret != nil {
		t.Fatalf("absent secret: got %q, %v; want nil, nil", secret, err)
	}
	secret, err = OptionalSecretFromEnvOrFile("tok", "")
	if err != nil || string(secret) != "tok" {
		t.Fatalf("env secret: got %q, %v", secret, err)
	}
	if _, err := OptionalSecretFromEnvOrFile("", "/nonexistent/secret"); err == nil {
		t.Fatal("unreadable file accepted")
	}
}
