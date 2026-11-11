package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/config"
	"github.com/beamfall/relay/internal/relay"
)

func TestCertReloadBuildRelayConfigUsesDynamicCertificate(t *testing.T) {
	want := &tls.Certificate{}
	getCertificate := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return want, nil }
	cfg := buildRelayConfig(relaydFlags{getCertificate: getCertificate})
	if cfg.CarrierTLSConfig.GetCertificate == nil {
		t.Fatal("carrier TLS config has no GetCertificate callback")
	}
	if len(cfg.CarrierTLSConfig.Certificates) != 0 {
		t.Fatal("carrier TLS config retains a static certificate slice")
	}
	got, err := cfg.CarrierTLSConfig.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != want {
		t.Fatal("carrier TLS config did not forward the dynamic certificate callback")
	}
}

// TestBuildRelayConfigHonorsMaxPublicConns proves the operator-tunable public
// connection cap (RV-RELAY-001) actually reaches relay.Config rather than being
// silently pinned to the 1024 default.
func TestBuildRelayConfigHonorsMaxPublicConns(t *testing.T) {
	cfg := buildRelayConfig(relaydFlags{
		maxPublicConns:  2048,
		maxCarrierConns: 64,
	})
	if cfg.MaxPublicConns != 2048 {
		t.Fatalf("MaxPublicConns = %d, want 2048 (operator override must be honored)", cfg.MaxPublicConns)
	}
	if cfg.MaxCarrierConns != 64 {
		t.Fatalf("MaxCarrierConns = %d, want 64", cfg.MaxCarrierConns)
	}
}

func TestCacheSupervisorStopsAtRestartBudget(t *testing.T) {
	code, err := superviseCacheServe(context.Background(), nil, supervisorConfig{
		restartBudget:  1,
		restartWindow:  time.Minute,
		initialBackoff: time.Nanosecond,
		maxBackoff:     time.Nanosecond,
		cacheUID:       -1,
		cacheGID:       -1,
		executable:     "/usr/bin/false",
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if err == nil || !strings.Contains(err.Error(), "exceeded restart budget") {
		t.Fatalf("err = %v, want restart-budget alert", err)
	}
}

func TestCacheSupervisorBuildsPrivSeparatedChild(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "cache-serve.log")
	cmd, logFile, err := cacheServeCommand(context.Background(), "/bin/echo", []string{"--cache-addr", ":0"}, supervisorConfig{
		cacheUID:     123,
		cacheGID:     456,
		cacheLogFile: logPath,
	})
	if err != nil {
		t.Fatalf("cacheServeCommand: %v", err)
	}
	defer logFile.Close() //nolint:errcheck // test cleanup.
	if strings.Join(cmd.Args, " ") != "/bin/echo cache-serve --cache-addr :0" {
		t.Fatalf("args = %#v", cmd.Args)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatal("cache-serve child missing OS credential override")
	}
	if got := cmd.SysProcAttr.Credential.Uid; got != 123 {
		t.Fatalf("uid = %d, want 123", got)
	}
	if got := cmd.SysProcAttr.Credential.Gid; got != 456 {
		t.Fatalf("gid = %d, want 456", got)
	}
	if cmd.Stdout != logFile || cmd.Stderr != logFile {
		t.Fatal("cache-serve stdout/stderr must use the dedicated cache log stream")
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat cache log: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache log mode = %o, want 600", info.Mode().Perm())
	}
}

func TestCacheSupervisorRequiresUIDAndGIDTogether(t *testing.T) {
	code, err := superviseCacheServe(context.Background(), nil, supervisorConfig{
		cacheUID: 123,
		cacheGID: -1,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if err == nil || !strings.Contains(err.Error(), "uid and gid") {
		t.Fatalf("err = %v, want uid/gid validation", err)
	}
}

// TestBuildRelayConfigHonorsPublicPeekHardening proves the SECREV-RELAY-9
// defense-in-depth knobs (per-IP cap + peek deadline) reach relay.Config
// rather than being silently pinned to their library defaults.
func TestBuildRelayConfigHonorsPublicPeekHardening(t *testing.T) {
	cfg := buildRelayConfig(relaydFlags{
		maxPublicConnsPerIP:    8,
		maxStreamsPerCarrierIP: 2,
		publicPeekTimeout:      2 * time.Second,
	})
	if cfg.MaxPublicConnsPerIP != 8 {
		t.Fatalf("MaxPublicConnsPerIP = %d, want 8 (operator override must be honored)", cfg.MaxPublicConnsPerIP)
	}
	if cfg.MaxStreamsPerIPPerCarrier != 2 {
		t.Fatalf("MaxStreamsPerIPPerCarrier = %d, want 2 (operator override must be honored)", cfg.MaxStreamsPerIPPerCarrier)
	}
	if cfg.PublicPeekTimeout != 2*time.Second {
		t.Fatalf("PublicPeekTimeout = %v, want 2s (operator override must be honored)", cfg.PublicPeekTimeout)
	}
}

// TestMaxPublicConnsEnvDefault proves RELAYD_MAX_PUBLIC_CONNS feeds the flag
// default and that the documented 1024 fallback holds when unset/blank.
func TestMaxPublicConnsEnvDefault(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want int
	}{
		{"unset falls back to 1024", "", 1024},
		{"override honored", "4096", 4096},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := config.IntEnvOrDefault(tc.env, 1024)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("IntEnvOrDefault(%q, 1024) = %d, want %d", tc.env, got, tc.want)
			}
			// And that value must survive the flag-to-Config mapping.
			cfg := buildRelayConfig(relaydFlags{maxPublicConns: got})
			if cfg.MaxPublicConns != tc.want {
				t.Fatalf("buildRelayConfig MaxPublicConns = %d, want %d", cfg.MaxPublicConns, tc.want)
			}
		})
	}
}

// TestBuildRelayConfigRunLoopFields verifies that run-loop-critical fields
// (shutdown grace, rate limits, fair-use config) survive the flag→Config mapping
// without truncation or silent zero-out.
func TestBuildRelayConfigRunLoopFields(t *testing.T) {
	grace := 45 * time.Second
	expiredDrain := 20 * time.Second
	redactConnectionLogs := false
	cfg := buildRelayConfig(relaydFlags{
		shutdownGrace:            grace,
		expiredSessionDrain:      expiredDrain,
		redactConnectionLogs:     &redactConnectionLogs,
		rateBytes:                1_000_000,
		rateBurst:                2_000_000,
		fairUseEnabled:           true,
		fairUseWindowDays:        14,
		fairUseSoftLimitBytes:    500_000_000,
		fairUseHardLimitBytes:    1_000_000_000,
		fairUseThrottledMaxConns: 2,
		fairUseStore:             "redis",
		fairUseRedisURL:          "rediss://redis.internal:6379/0",
		fairUseOutboxPath:        "/var/lib/beamfall-relay/test-fairuse-outbox.json",
		logger:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	if cfg.ShutdownGrace != grace {
		t.Errorf("ShutdownGrace = %v, want %v", cfg.ShutdownGrace, grace)
	}
	if cfg.ExpiredSessionDrain != expiredDrain {
		t.Errorf("ExpiredSessionDrain = %v, want %v", cfg.ExpiredSessionDrain, expiredDrain)
	}
	if cfg.RedactConnectionLogs == nil || *cfg.RedactConnectionLogs {
		t.Errorf("RedactConnectionLogs = %v, want explicit false", cfg.RedactConnectionLogs)
	}
	if cfg.RateBytesPerSec != 1_000_000 {
		t.Errorf("RateBytesPerSec = %d, want 1000000", cfg.RateBytesPerSec)
	}
	if cfg.RateBurstBytes != 2_000_000 {
		t.Errorf("RateBurstBytes = %d, want 2000000", cfg.RateBurstBytes)
	}
	if !cfg.FairUse.Enabled {
		t.Error("FairUse.Enabled = false, want true")
	}
	if cfg.FairUse.WindowDays != 14 {
		t.Errorf("FairUse.WindowDays = %d, want 14", cfg.FairUse.WindowDays)
	}
	if cfg.FairUse.SoftLimitBytes != 500_000_000 {
		t.Errorf("FairUse.SoftLimitBytes = %d, want 500000000", cfg.FairUse.SoftLimitBytes)
	}
	if cfg.FairUse.HardLimitBytes != 1_000_000_000 {
		t.Errorf("FairUse.HardLimitBytes = %d, want 1000000000", cfg.FairUse.HardLimitBytes)
	}
	if cfg.FairUse.ThrottledMaxConns != 2 {
		t.Errorf("FairUse.ThrottledMaxConns = %d, want 2", cfg.FairUse.ThrottledMaxConns)
	}
	if cfg.FairUse.Store != "redis" || cfg.FairUse.RedisURL != "rediss://redis.internal:6379/0" {
		t.Errorf("shared FairUse config = store %q url %q", cfg.FairUse.Store, cfg.FairUse.RedisURL)
	}
	if cfg.FairUse.OutboxPath != "/var/lib/beamfall-relay/test-fairuse-outbox.json" {
		t.Errorf("FairUse.OutboxPath = %q", cfg.FairUse.OutboxPath)
	}
}

// TestBuildRelayConfigStreamCap verifies stream cap is forwarded (not ignored).
func TestBuildRelayConfigStreamCap(t *testing.T) {
	cfg := buildRelayConfig(relaydFlags{streamCap: 8})
	if cfg.StreamCap != 8 {
		t.Fatalf("StreamCap = %d, want 8", cfg.StreamCap)
	}
}

func TestStreamCapParsedDefaultMatchesRelayDefault(t *testing.T) {
	relayDefaults := relay.ApplyStreamCapDefault(relay.Config{})
	cases := []struct {
		name string
		env  string
		want int
	}{
		{name: "unset uses relay default", want: relayDefaults.StreamCap},
		{name: "environment overrides default", env: "96", want: 96},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("relayd-test", flag.ContinueOnError)
			streamCap, err := registerStreamCapFlag(fs, tc.env)
			if err != nil {
				t.Fatalf("registerStreamCapFlag: %v", err)
			}
			if err := fs.Parse(nil); err != nil {
				t.Fatalf("parse flags: %v", err)
			}
			if *streamCap != tc.want {
				t.Fatalf("parsed --stream-cap default = %d, want %d", *streamCap, tc.want)
			}
		})
	}
}

// TestBuildTokenVerifierSelectsMode pins the --token-mode wiring: static mode
// keeps the constant-time StaticTokenVerifier, hmac mode selects the expiring
// v2 HMACTokenVerifier with AcceptLegacyV1 OFF (the shipped binaries never had
// a legacy-v1 carrier population, so strict v2 from the start), and a token a
// tunnel client mints from the same shared secret actually verifies.
func TestBuildTokenVerifierSelectsMode(t *testing.T) {
	secret := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	hosts := []string{"home.relay.test"}
	nonceStorePath := filepath.Join(t.TempDir(), "hmac-nonces.json")

	staticVerifier, err := buildTokenVerifier(tokenModeStatic, secret, hosts, nonceStorePath, relay.DefaultNonceStoreCapacity)
	if err != nil {
		t.Fatalf("build static verifier: %v", err)
	}
	static, ok := staticVerifier.(relay.StaticTokenVerifier)
	if !ok {
		t.Fatal("static mode did not select StaticTokenVerifier")
	}
	if string(static.Token) != string(secret) || len(static.Hostnames) != 1 {
		t.Fatalf("static verifier wiring = %#v", static)
	}

	hmacTokenVerifier, err := buildTokenVerifier(tokenModeHMAC, secret, hosts, nonceStorePath, relay.DefaultNonceStoreCapacity)
	if err != nil {
		t.Fatalf("build hmac verifier: %v", err)
	}
	hmacVerifier, ok := hmacTokenVerifier.(*relay.HMACTokenVerifier)
	if !ok {
		t.Fatal("hmac mode did not select *HMACTokenVerifier")
	}
	if hmacVerifier.AcceptLegacyV1 {
		t.Fatal("hmac mode must not accept legacy v1 tokens")
	}
	if _, ok := hmacVerifier.NonceStore.(*relay.FileHMACNonceStore); !ok {
		t.Fatalf("hmac mode nonce store = %T, want *relay.FileHMACNonceStore", hmacVerifier.NonceStore)
	}
	storeInfo, err := os.Stat(nonceStorePath)
	if err != nil {
		t.Fatalf("stat initialized nonce store: %v", err)
	}
	if storeInfo.Mode().Perm() != 0o600 {
		t.Fatalf("nonce store mode = %o, want 600", storeInfo.Mode().Perm())
	}
	token, err := relay.MintHMACTunnelToken(secret, hosts, relay.MaxHMACTokenTTL)
	if err != nil {
		t.Fatalf("mint v2 token: %v", err)
	}
	if _, err := hmacVerifier.VerifyTunnelToken(context.Background(), token, hosts); err != nil {
		t.Fatalf("client-minted v2 token rejected by relayd hmac verifier: %v", err)
	}
	reopenedTokenVerifier, err := buildTokenVerifier(tokenModeHMAC, secret, hosts, nonceStorePath, relay.DefaultNonceStoreCapacity)
	if err != nil {
		t.Fatalf("reopen hmac verifier: %v", err)
	}
	if _, err := reopenedTokenVerifier.VerifyTunnelToken(context.Background(), token, hosts); !errors.Is(err, relay.ErrUnauthorized) {
		t.Fatalf("reopened relayd verifier err = %v, want ErrUnauthorized replay", err)
	}
}

func TestBuildTokenVerifierFailsClosedOnNonceStoreInitialization(t *testing.T) {
	secret := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	hosts := []string{"home.relay.test"}
	badStorePath := t.TempDir() // Renaming a state file over an existing directory must fail.

	if _, err := buildTokenVerifier(tokenModeHMAC, secret, hosts, badStorePath, relay.DefaultNonceStoreCapacity); err == nil {
		t.Fatal("hmac mode accepted an unusable nonce store")
	}
	if _, err := buildTokenVerifier(tokenModeStatic, secret, hosts, badStorePath, relay.DefaultNonceStoreCapacity); err != nil {
		t.Fatalf("static mode must not initialize hmac replay storage: %v", err)
	}
}

func TestHMACNonceStoreCapacityFlagDefault(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want int
	}{
		{name: "unset uses the sized default", want: relay.DefaultNonceStoreCapacity},
		{name: "environment overrides default", env: "4096", want: 4096},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("relayd-test", flag.ContinueOnError)
			capacity, err := registerHMACNonceStoreCapacityFlag(fs, tc.env)
			if err != nil {
				t.Fatalf("registerHMACNonceStoreCapacityFlag: %v", err)
			}
			if err := fs.Parse(nil); err != nil {
				t.Fatalf("parse flags: %v", err)
			}
			if *capacity != tc.want {
				t.Fatalf("parsed --hmac-nonce-store-capacity default = %d, want %d", *capacity, tc.want)
			}
		})
	}
	fs := flag.NewFlagSet("relayd-test", flag.ContinueOnError)
	capacity, err := registerHMACNonceStoreCapacityFlag(fs, "4096")
	if err != nil {
		t.Fatalf("registerHMACNonceStoreCapacityFlag: %v", err)
	}
	if err := fs.Parse([]string{"--hmac-nonce-store-capacity=8"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if *capacity != 8 {
		t.Fatalf("flag did not override environment: got %d, want 8", *capacity)
	}
	if _, err := registerHMACNonceStoreCapacityFlag(flag.NewFlagSet("relayd-test", flag.ContinueOnError), "many"); err == nil {
		t.Fatal("non-integer RELAYD_HMAC_NONCE_STORE_CAPACITY accepted")
	}
}

// TestBuildTokenVerifierAppliesNonceStoreCapacity pins that the configured
// capacity reaches the hmac replay store: a capacity-1 store refuses a second
// distinct valid token with ErrNonceStoreFull (not ErrUnauthorized), and an
// out-of-range capacity fails startup closed.
func TestBuildTokenVerifierAppliesNonceStoreCapacity(t *testing.T) {
	sharedKey := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	hosts := []string{"home.relay.test"}
	nonceStorePath := filepath.Join(t.TempDir(), "hmac-nonces.json")

	verifier, err := buildTokenVerifier(tokenModeHMAC, sharedKey, hosts, nonceStorePath, 1)
	if err != nil {
		t.Fatalf("build capacity-1 hmac verifier: %v", err)
	}
	for i, want := range []error{nil, relay.ErrNonceStoreFull} {
		token, err := relay.MintHMACTunnelToken(sharedKey, hosts, relay.MaxHMACTokenTTL)
		if err != nil {
			t.Fatalf("mint v2 token %d: %v", i, err)
		}
		_, err = verifier.VerifyTunnelToken(context.Background(), token, hosts)
		if want == nil && err != nil {
			t.Fatalf("token %d rejected by a store with free capacity: %v", i, err)
		}
		if want != nil && (!errors.Is(err, want) || errors.Is(err, relay.ErrUnauthorized)) {
			t.Fatalf("token %d err = %v, want %v and not ErrUnauthorized", i, err, want)
		}
	}
	for _, capacity := range []int{0, relay.MaxNonceStoreCapacity + 1} {
		if _, err := buildTokenVerifier(tokenModeHMAC, sharedKey, hosts, nonceStorePath, capacity); err == nil {
			t.Fatalf("hmac mode accepted nonce store capacity %d", capacity)
		}
	}
}

func TestProductionConfigRejectsStaticCarrierToken(t *testing.T) {
	if defaultTokenMode != tokenModeHMAC {
		t.Fatalf("default token mode = %q, want %q", defaultTokenMode, tokenModeHMAC)
	}
	if err := validateTokenMode(tokenModeHMAC, ""); err != nil {
		t.Fatalf("production hmac mode rejected: %v", err)
	}
	for _, devMode := range []string{"", "0", "true", "TRUE"} {
		err := validateTokenMode(tokenModeStatic, devMode)
		if err == nil {
			t.Fatalf("static mode accepted with %s=%q", config.DevModeEnv, devMode)
		}
		const want = `--token-mode "static" is insecure-development-only and is refused in production because static bearer tokens never expire and are replayable if captured: set BEAMFALL_RELAY_DEV=1 to enable it`
		if err.Error() != want {
			t.Fatalf("static rejection = %q, want %q", err, want)
		}
	}
	if err := validateTokenMode(tokenModeStatic, "1"); err != nil {
		t.Fatalf("explicit insecure-development static mode rejected: %v", err)
	}
	if err := validateTokenMode("unknown", "1"); err == nil {
		t.Fatal("unknown token mode accepted")
	}
}

func TestEnvExamplesAreProductionSafe(t *testing.T) {
	validators := map[string]func(string) error{
		"RELAYD_TOKEN_MODE": func(value string) error {
			return validateTokenMode(value, "")
		},
		"TUNNEL_TOKEN_MODE": func(value string) error {
			return validateTokenMode(value, "")
		},
		"TUNNEL_TOKEN_TTL": validateExampleTokenTTL,
		"RELAYD_MAX_PUBLIC_CONNS": func(value string) error {
			_, err := config.IntEnvOrDefault(value, 1024)
			return err
		},
		"RELAYD_FAIR_USE_ENABLED": func(value string) error {
			_, err := config.BoolEnvOrDefault(value, false)
			return err
		},
		"RELAYD_FAIR_USE_WINDOW_DAYS": func(value string) error {
			_, err := config.IntEnvOrDefault(value, 30)
			return err
		},
		"RELAYD_FAIR_USE_SOFT_LIMIT_BYTES": func(value string) error {
			_, err := config.Int64EnvOrDefault(value, 0)
			return err
		},
		"RELAYD_FAIR_USE_HARD_LIMIT_BYTES": func(value string) error {
			_, err := config.Int64EnvOrDefault(value, 0)
			return err
		},
		"RELAYD_FAIR_USE_THROTTLED_MAX_CONNS": func(value string) error {
			_, err := config.IntEnvOrDefault(value, 4)
			return err
		},
	}
	tests := []struct {
		path     string
		required []string
	}{
		{
			path: filepath.Join("..", "..", ".env.example"),
			required: []string{
				"RELAYD_TOKEN_MODE",
				"TUNNEL_TOKEN_MODE",
				"TUNNEL_TOKEN_TTL",
			},
		},
		{
			path:     filepath.Join("..", "..", "packaging", "systemd", "relayd.env.example"),
			required: []string{"RELAYD_TOKEN_MODE"},
		},
	}
	for _, test := range tests {
		t.Run(filepath.Base(test.path), func(t *testing.T) {
			values := parseEnvExample(t, test.path)
			for key, value := range values {
				validate, ok := validators[key]
				if !ok {
					continue
				}
				if err := validate(value); err != nil {
					t.Errorf("%s %s=%s is refused in production: %v", test.path, key, value, err)
				}
			}
			for _, key := range test.required {
				if _, ok := values[key]; !ok {
					t.Errorf("%s is missing %s", test.path, key)
				}
			}
		})
	}
}

func parseEnvExample(t *testing.T, path string) map[string]string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close() //nolint:errcheck // test cleanup.

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := values[key]; exists {
			t.Errorf("%s defines %s more than once", path, key)
		}
		values[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return values
}

func validateExampleTokenTTL(value string) error {
	ttl, err := config.DurationEnvOrDefault(value, relay.MaxHMACTokenTTL)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		return errors.New("token TTL must be positive")
	}
	if ttl > relay.MaxHMACTokenTTL {
		return fmt.Errorf("token TTL must not exceed %s", relay.MaxHMACTokenTTL)
	}
	return nil
}

func TestDefaultHMACNonceStorePathIsDeterministicAndSecure(t *testing.T) {
	if defaultHMACNonceStorePath != "/var/lib/beamfall-relay/hmac-nonces.json" {
		t.Fatalf("default hmac nonce store path = %q", defaultHMACNonceStorePath)
	}
}
