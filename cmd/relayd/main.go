package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/beamfall/relay/internal/cache"
	"github.com/beamfall/relay/internal/config"
	"github.com/beamfall/relay/internal/relay"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "cache-serve":
			runCacheServe(os.Args[2:])
			return
		case "cache-supervise":
			os.Exit(runCacheSupervisor(os.Args[2:]))
		}
	}
	fairUseEnabledDefault, err := config.BoolEnvOrDefault(os.Getenv("RELAYD_FAIR_USE_ENABLED"), false)
	if err != nil {
		log.Fatalf("load fair-use enabled default: %v", err)
	}
	fairUseWindowDaysDefault, err := config.IntEnvOrDefault(os.Getenv("RELAYD_FAIR_USE_WINDOW_DAYS"), 30)
	if err != nil {
		log.Fatalf("load fair-use window default: %v", err)
	}
	fairUseSoftLimitDefault, err := config.Int64EnvOrDefault(os.Getenv("RELAYD_FAIR_USE_SOFT_LIMIT_BYTES"), 0)
	if err != nil {
		log.Fatalf("load fair-use soft limit default: %v", err)
	}
	fairUseHardLimitDefault, err := config.Int64EnvOrDefault(os.Getenv("RELAYD_FAIR_USE_HARD_LIMIT_BYTES"), 0)
	if err != nil {
		log.Fatalf("load fair-use hard limit default: %v", err)
	}
	fairUseThrottledMaxConnsDefault, err := config.IntEnvOrDefault(os.Getenv("RELAYD_FAIR_USE_THROTTLED_MAX_CONNS"), 4)
	if err != nil {
		log.Fatalf("load fair-use throttled max conns default: %v", err)
	}
	fairUseLeaseTTLDefault, err := config.DurationEnvOrDefault(os.Getenv("RELAYD_FAIR_USE_LEASE_TTL"), relay.DefaultFairUseLeaseTTL)
	if err != nil {
		log.Fatalf("load fair-use lease TTL default: %v", err)
	}
	fairUseFenceMarginDefault, err := config.DurationEnvOrDefault(os.Getenv("RELAYD_FAIR_USE_FENCE_MARGIN"), relay.DefaultFairUseFenceMargin)
	if err != nil {
		log.Fatalf("load fair-use fence margin default: %v", err)
	}
	maxPublicConnsDefault, err := config.IntEnvOrDefault(os.Getenv("RELAYD_MAX_PUBLIC_CONNS"), 1024)
	if err != nil {
		log.Fatalf("load max public conns default: %v", err)
	}
	maxPublicConnsPerIPDefault, err := config.IntEnvOrDefault(os.Getenv("RELAYD_MAX_PUBLIC_CONNS_PER_IP"), 64)
	if err != nil {
		log.Fatalf("load max public conns per IP default: %v", err)
	}
	maxStreamsPerCarrierIPDefault, err := config.IntEnvOrDefault(os.Getenv("RELAYD_MAX_STREAMS_PER_IP_PER_CARRIER"), 0)
	if err != nil {
		log.Fatalf("load max streams per IP per carrier default: %v", err)
	}
	streamCap, err := registerStreamCapFlag(flag.CommandLine, os.Getenv("RELAYD_STREAM_CAP"))
	if err != nil {
		log.Fatalf("load stream cap default: %v", err)
	}
	hmacNonceStoreCapacity, err := registerHMACNonceStoreCapacityFlag(flag.CommandLine, os.Getenv("RELAYD_HMAC_NONCE_STORE_CAPACITY"))
	if err != nil {
		log.Fatalf("load hmac nonce store capacity default: %v", err)
	}
	redactConnectionLogsDefault, err := config.BoolEnvOrDefault(os.Getenv("RELAYD_REDACT_CONNECTION_LOGS"), true)
	if err != nil {
		log.Fatalf("load connection-log redaction default: %v", err)
	}
	adminAllowPublicDefault, err := config.BoolEnvOrDefault(os.Getenv("RELAYD_ADMIN_ALLOW_PUBLIC"), false)
	if err != nil {
		log.Fatalf("load admin-allow-public default: %v", err)
	}

	var (
		publicAddr               = flag.String("public-addr", config.EnvOrDefault(os.Getenv("RELAYD_PUBLIC_ADDR"), ":8443"), "public TLS passthrough listener address")
		carrierAddr              = flag.String("carrier-addr", config.EnvOrDefault(os.Getenv("RELAYD_CARRIER_ADDR"), ":9443"), "carrier TLS listener address")
		quicAddr                 = flag.String("quic-addr", os.Getenv("RELAYD_QUIC_ADDR"), "ADR-0018 v2 QUIC carrier listener address (UDP); empty disables it")
		adminAddr                = flag.String("admin-addr", config.EnvOrDefault(os.Getenv("RELAYD_ADMIN_ADDR"), "127.0.0.1:9080"), "localhost admin listener address")
		adminAllowPublic         = flag.Bool("admin-allow-public", adminAllowPublicDefault, "explicitly allow --admin-addr to bind a non-loopback, non-private address; without this a public admin bind refuses to start")
		adminMetricsTokenFile    = flag.String("admin-metrics-token-file", os.Getenv("RELAYD_ADMIN_METRICS_TOKEN_FILE"), "file holding the bearer credential that guards /metrics when --admin-addr is non-loopback (ADR-0146 §5); also read from RELAYD_ADMIN_METRICS_TOKEN. A non-loopback admin bind refuses to start without it")
		certFile                 = flag.String("carrier-cert", os.Getenv("RELAYD_CARRIER_CERT"), "carrier TLS certificate file")
		keyFile                  = flag.String("carrier-key", os.Getenv("RELAYD_CARRIER_KEY"), "carrier TLS key file")
		tokenFile                = flag.String("token-file", os.Getenv("RELAYD_TOKEN_FILE"), "carrier token/secret file for self-hosted/test deployments (see --token-mode)")
		tokenMode                = flag.String("token-mode", config.EnvOrDefault(os.Getenv("RELAYD_TOKEN_MODE"), defaultTokenMode), "carrier token verification mode: 'hmac' (production default; the token file/env value is a shared SECRET and carriers present expiring, replay-resistant v2 tunnel tokens) or 'static' (insecure development only; requires BEAMFALL_RELAY_DEV=1)")
		hmacNonceStorePath       = flag.String("hmac-nonce-store", config.EnvOrDefault(os.Getenv("RELAYD_HMAC_NONCE_STORE"), defaultHMACNonceStorePath), "hmac token mode only: persistent replay-state file. All relay instances must use the same path on storage with POSIX lock/atomic-rename semantics; startup fails closed if it cannot be initialized")
		hostnames                = flag.String("hostnames", os.Getenv("RELAYD_HOSTNAMES"), "comma-separated hostnames this relay accepts")
		maxPublicConns           = flag.Int("max-public-conns", maxPublicConnsDefault, "max concurrently-handled public connections; over the cap accepts are closed; 0 uses the default")
		maxPublicConnsPerIP      = flag.Int("max-public-conns-per-ip", maxPublicConnsPerIPDefault, "max concurrently-handled public connections from one IPv4 /32 or IPv6 /64 (defense-in-depth against partial-record floods); over the cap accepts are closed; 0 uses the default")
		maxStreamsPerCarrierIP   = flag.Int("max-streams-per-ip-per-carrier", maxStreamsPerCarrierIPDefault, "max concurrent streams from one IPv4 /32 or IPv6 /64 to one carrier; 0 uses one quarter of --stream-cap (minimum 1)")
		publicPeekTimeout        = flag.Duration("public-peek-timeout", 3*time.Second, "how long the public listener waits to read a client's TLS ClientHello for SNI-blind routing before closing the connection; shorter shrinks the partial-record flood window; 0 uses the default")
		maxCarrierConns          = flag.Int("max-carrier-conns", 64, "max concurrently-handled carrier connections; over the cap accepts are closed; 0 uses the default")
		rateBytes                = flag.Int64("rate-bytes-per-sec", 0, "per-carrier byte rate limit; 0 disables")
		rateBurst                = flag.Int64("rate-burst-bytes", 0, "per-carrier byte rate burst; defaults to rate")
		fairUseEnabled           = flag.Bool("fair-use-enabled", fairUseEnabledDefault, "enable rolling-window fair-use accounting and hard-limit throttling")
		fairUseWindowDays        = flag.Int("fair-use-window-days", fairUseWindowDaysDefault, "fair-use rolling window in days")
		fairUseSoftLimitBytes    = flag.Int64("fair-use-soft-limit-bytes", fairUseSoftLimitDefault, "fair-use soft limit in bytes; 0 disables soft crossings")
		fairUseHardLimitBytes    = flag.Int64("fair-use-hard-limit-bytes", fairUseHardLimitDefault, "fair-use hard limit in bytes; 0 disables throttling")
		fairUseThrottledMaxConns = flag.Int("fair-use-throttled-max-conns", fairUseThrottledMaxConnsDefault, "new-connection ceiling for tunnels over the hard fair-use limit")
		fairUseStore             = flag.String("fair-use-store", config.EnvOrDefault(os.Getenv("RELAYD_FAIR_USE_STORE"), "memory"), "fair-use backend: memory (single instance) or redis (shared hosted instances)")
		fairUseRedisURL          = flag.String("fair-use-redis-url", os.Getenv("RELAYD_FAIR_USE_REDIS_URL"), "Redis URL for shared fair-use accounting; prefer RELAYD_FAIR_USE_REDIS_URL so credentials are not exposed in process arguments")
		fairUseOutboxPath        = flag.String("fair-use-outbox", config.EnvOrDefault(os.Getenv("RELAYD_FAIR_USE_OUTBOX"), defaultFairUseOutboxPath), "redis fair-use mode only: private durable final-delta outbox; startup fails closed unless existing records replay before listeners bind")
		fairUseLeaseTTL          = flag.Duration("fair-use-lease-ttl", fairUseLeaseTTLDefault, "redis fair-use mode only: stream lease TTL; live streams survive a Redis outage shorter than lease TTL minus fence margin minus 10s (70s at the defaults)")
		fairUseFenceMargin       = flag.Duration("fair-use-fence-margin", fairUseFenceMarginDefault, "redis fair-use mode only: the relay closes a stream this long before its unconfirmed lease can expire in Redis")
		shutdownGrace            = flag.Duration("shutdown-grace", 30*time.Second, "on shutdown, stop accepting new public connections then wait this long for in-flight streams to drain before force-close; 0 = immediate")
		expiredSessionDrain      = flag.Duration("expired-session-drain", 30*time.Second, "additional grace after token expiry for streams on a superseded carrier to drain; unsuperseded carriers still close at expiry")
		redactConnectionLogs     = flag.Bool("redact-connection-logs", redactConnectionLogsDefault, "omit public remote address, SNI hostname, and carrier id from connection logs")
		yamuxStreamWindowBytes   = flag.Int("yamux-stream-window-bytes", 0, "v1 (TLS/TCP) carrier per-stream flow-control window in bytes; 0 uses the 1 MiB default. The tunnel client's --yamux-stream-window-bytes MUST match.")
	)
	flag.Parse()

	if err := validateTokenMode(*tokenMode, os.Getenv(config.DevModeEnv)); err != nil {
		log.Fatalf("configure carrier token mode: %v", err)
	}
	token, err := config.SecretFromEnvOrFile(os.Getenv("RELAYD_TOKEN"), *tokenFile)
	if err != nil {
		log.Fatalf("load token: %v", err)
	}
	// Fail fast on a weak shared carrier token before any listener binds, so a
	// brute-forceable secret can never reach the carrier-auth path.
	if err := relay.ValidateTokenStrength(token); err != nil {
		log.Fatalf("carrier token rejected: %v", err)
	}
	logger := slog.Default()
	certReloader, err := config.NewCertificateReloader(*certFile, *keyFile, logger)
	if err != nil {
		log.Fatalf("load carrier TLS certificate: %v", err)
	}
	// Resolve the /metrics bearer credential from env or file (same secret
	// handling as the carrier token — never argv/ps). Unset is fine for a
	// loopback admin bind — the default deployment — so the load is optional;
	// relay.Start fails closed on a non-loopback bind with no credential.
	adminMetricsToken, err := config.OptionalSecretFromEnvOrFile(os.Getenv("RELAYD_ADMIN_METRICS_TOKEN"), *adminMetricsTokenFile)
	if err != nil {
		log.Fatalf("load admin metrics token: %v", err)
	}
	hosts := config.SplitCSV(*hostnames)
	if len(hosts) == 0 {
		log.Fatal("at least one hostname is required")
	}
	tokenVerifier, err := buildTokenVerifier(*tokenMode, token, hosts, *hmacNonceStorePath, *hmacNonceStoreCapacity)
	if err != nil {
		log.Fatalf("configure carrier token verifier: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGHUP)
	defer signal.Stop(reloadSignals)
	go certReloader.Watch(ctx, time.Minute, reloadSignals)
	server, err := relay.Start(ctx, buildRelayConfig(relaydFlags{
		publicAddr:               *publicAddr,
		tokenMode:                *tokenMode,
		tokenVerifier:            tokenVerifier,
		carrierAddr:              *carrierAddr,
		quicAddr:                 *quicAddr,
		adminAddr:                *adminAddr,
		adminAllowPublic:         *adminAllowPublic,
		adminMetricsToken:        string(adminMetricsToken),
		getCertificate:           certReloader.GetCertificate,
		streamCap:                *streamCap,
		maxPublicConns:           *maxPublicConns,
		maxPublicConnsPerIP:      *maxPublicConnsPerIP,
		maxStreamsPerCarrierIP:   *maxStreamsPerCarrierIP,
		publicPeekTimeout:        *publicPeekTimeout,
		maxCarrierConns:          *maxCarrierConns,
		rateBytes:                *rateBytes,
		rateBurst:                *rateBurst,
		shutdownGrace:            *shutdownGrace,
		expiredSessionDrain:      *expiredSessionDrain,
		fairUseEnabled:           *fairUseEnabled,
		fairUseWindowDays:        *fairUseWindowDays,
		fairUseSoftLimitBytes:    *fairUseSoftLimitBytes,
		fairUseHardLimitBytes:    *fairUseHardLimitBytes,
		fairUseThrottledMaxConns: *fairUseThrottledMaxConns,
		fairUseStore:             *fairUseStore,
		fairUseRedisURL:          *fairUseRedisURL,
		fairUseOutboxPath:        *fairUseOutboxPath,
		fairUseLeaseTTL:          *fairUseLeaseTTL,
		fairUseFenceMargin:       *fairUseFenceMargin,
		redactConnectionLogs:     redactConnectionLogs,
		yamuxStreamWindowBytes:   *yamuxStreamWindowBytes,
		logger:                   logger,
	}))
	if err != nil {
		log.Fatalf("start relayd: %v", err)
	}
	// Hosted/multi-tenant deployments must run both abuse controls: a per-carrier
	// byte rate limit AND fair-use accounting. With neither active a single
	// tunnel can saturate a shared relay. Emit a startup notice so an operator
	// who exposes this relay to untrusted tenants cannot miss the gap. Purely
	// self-hosted single-tenant operators can ignore it (see
	// docs/operator-self-hosted-relay.md, "Hosted / multi-tenant deployments").
	if *rateBytes <= 0 && !*fairUseEnabled {
		logger.Warn("no abuse controls enabled: both --rate-bytes-per-sec and --fair-use-enabled are off; a single tunnel can saturate the relay. Enable both for any hosted/multi-tenant deployment (docs/operator-self-hosted-relay.md).")
	}
	logger.Info("relayd listening", "public", server.PublicAddr(), "carrier", server.CarrierAddr(), "quic", server.QUICAddr(), "admin", server.AdminAddr())
	<-ctx.Done()
	server.Shutdown(*shutdownGrace)
	server.Wait()
}

func registerStreamCapFlag(fs *flag.FlagSet, envValue string) (*int, error) {
	defaultValue, err := config.IntEnvOrDefault(envValue, 64)
	if err != nil {
		return nil, err
	}
	return fs.Int("stream-cap", defaultValue, "per-carrier concurrent stream cap; --stream-cap uses 64 when RELAYD_STREAM_CAP is unset"), nil
}

// registerHMACNonceStoreCapacityFlag registers --hmac-nonce-store-capacity,
// defaulting to RELAYD_HMAC_NONCE_STORE_CAPACITY or relay.DefaultNonceStoreCapacity.
func registerHMACNonceStoreCapacityFlag(fs *flag.FlagSet, envValue string) (*int, error) {
	defaultValue, err := config.IntEnvOrDefault(envValue, relay.DefaultNonceStoreCapacity)
	if err != nil {
		return nil, err
	}
	usage := fmt.Sprintf("hmac token mode only: live replay nonces the store holds before new carrier dials are refused (fail closed, log code and dial outcome nonce_store_full); the default %d is the 24h max token TTL x %d tokens/s x 150%% headroom; every instance sharing --hmac-nonce-store should use the same value", relay.DefaultNonceStoreCapacity, relay.NonceStoreSizingPeakMintRate)
	return fs.Int("hmac-nonce-store-capacity", defaultValue, usage), nil
}

func runCacheServe(args []string) {
	tenantCapDefault, err := config.Int64EnvOrDefault(os.Getenv("RELAYD_CACHE_TENANT_CAP_BYTES"), 0)
	if err != nil {
		log.Fatalf("load cache tenant cap default: %v", err)
	}
	adminAllowPublicDefault, err := config.BoolEnvOrDefault(os.Getenv("RELAYD_CACHE_ADMIN_ALLOW_PUBLIC"), false)
	if err != nil {
		log.Fatalf("load cache admin-allow-public default: %v", err)
	}
	fs := flag.NewFlagSet("cache-serve", flag.ExitOnError)
	addr := fs.String("cache-addr", config.EnvOrDefault(os.Getenv("RELAYD_CACHE_ADDR"), ":9444"), "HTTPS Media Cache segment listener address")
	adminAddr := fs.String("cache-admin-addr", config.EnvOrDefault(os.Getenv("RELAYD_CACHE_ADMIN_ADDR"), "127.0.0.1:9081"), "cache health/metrics listener address")
	adminAllowPublic := fs.Bool("cache-admin-allow-public", adminAllowPublicDefault, "explicitly allow --cache-admin-addr to bind a non-loopback, non-private address")
	adminMetricsTokenFile := fs.String("cache-admin-metrics-token-file", os.Getenv("RELAYD_CACHE_ADMIN_METRICS_TOKEN_FILE"), "file holding the bearer credential that guards cache /metrics when --cache-admin-addr is non-loopback")
	certFile := fs.String("cache-cert", os.Getenv("RELAYD_CACHE_CERT"), "cache HTTPS certificate file")
	keyFile := fs.String("cache-key", os.Getenv("RELAYD_CACHE_KEY"), "cache HTTPS key file")
	tokenKeyFile := fs.String("cache-token-key-file", os.Getenv("RELAYD_CACHE_TOKEN_KEY_FILE"), "CacheAccessToken HMAC verification key file")
	storeDir := fs.String("cache-store-dir", config.EnvOrDefault(os.Getenv("RELAYD_CACHE_STORE_DIR"), "/var/lib/beamfall-relay/cache"), "cache segment store directory")
	tenantCapBytes := fs.Int64("cache-tenant-cap-bytes", tenantCapDefault, "per-tenant cache hard cap in bytes; 0 = min(25 GiB, 10% free disk)")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("parse cache flags: %v", err)
	}
	tokenKey, err := config.SecretFromEnvOrFile(os.Getenv("RELAYD_CACHE_TOKEN_KEY"), *tokenKeyFile)
	if err != nil {
		log.Fatalf("load cache token key: %v", err)
	}
	adminMetricsToken, err := config.OptionalSecretFromEnvOrFile(os.Getenv("RELAYD_CACHE_ADMIN_METRICS_TOKEN"), *adminMetricsTokenFile)
	if err != nil {
		log.Fatalf("load cache admin metrics token: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load cache TLS certificate: %v", err)
	}
	store, err := cache.NewStore(*storeDir, tokenKey, *tenantCapBytes)
	if err != nil {
		log.Fatalf("open cache store: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	server, err := cache.Start(ctx, cache.Config{
		Addr:              *addr,
		AdminAddr:         *adminAddr,
		AdminAllowPublic:  *adminAllowPublic,
		AdminMetricsToken: string(adminMetricsToken),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		},
		TokenVerifier: cache.HMACTokenVerifier{Key: tokenKey},
		Store:         store,
		Logger:        slog.Default(),
	})
	if err != nil {
		log.Fatalf("start cache server: %v", err)
	}
	slog.Info("relayd cache-serve listening", "cache", server.Addr(), "admin", server.AdminAddr())
	<-ctx.Done()
	if err := server.Close(); err != nil {
		slog.Error("cache server shutdown", "err", err)
	}
}

func runCacheSupervisor(args []string) int {
	cacheUIDDefault, err := config.IntEnvOrDefault(os.Getenv("RELAYD_CACHE_UID"), -1)
	if err != nil {
		log.Fatalf("load cache uid default: %v", err)
	}
	cacheGIDDefault, err := config.IntEnvOrDefault(os.Getenv("RELAYD_CACHE_GID"), -1)
	if err != nil {
		log.Fatalf("load cache gid default: %v", err)
	}
	fs := flag.NewFlagSet("cache-supervise", flag.ExitOnError)
	restartBudget := fs.Int("restart-budget", 5, "cache-serve restart budget before operator alert and supervisor exit")
	restartWindow := fs.Duration("restart-window", 10*time.Minute, "window for the cache-serve restart budget")
	initialBackoff := fs.Duration("restart-backoff", time.Second, "initial cache-serve crash-loop backoff")
	maxBackoff := fs.Duration("restart-max-backoff", 30*time.Second, "max cache-serve crash-loop backoff")
	cacheUID := fs.Int("cache-uid", cacheUIDDefault, "numeric OS uid for the cache-serve child; -1 leaves the current uid")
	cacheGID := fs.Int("cache-gid", cacheGIDDefault, "numeric OS gid for the cache-serve child; -1 leaves the current gid")
	cacheLogFile := fs.String("cache-log-file", os.Getenv("RELAYD_CACHE_LOG_FILE"), "append-only log file for cache-serve stdout/stderr; empty inherits supervisor logs")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("parse cache-supervise flags: %v", err)
	}
	childArgs := fs.Args()
	if len(childArgs) > 0 && childArgs[0] == "--" {
		childArgs = childArgs[1:]
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	code, err := superviseCacheServe(ctx, childArgs, supervisorConfig{
		restartBudget:  *restartBudget,
		restartWindow:  *restartWindow,
		initialBackoff: *initialBackoff,
		maxBackoff:     *maxBackoff,
		cacheUID:       *cacheUID,
		cacheGID:       *cacheGID,
		cacheLogFile:   *cacheLogFile,
		logger:         slog.Default(),
	})
	if err != nil {
		slog.Error("cache-serve supervisor alert", "err", err)
	}
	return code
}

type supervisorConfig struct {
	restartBudget  int
	restartWindow  time.Duration
	initialBackoff time.Duration
	maxBackoff     time.Duration
	cacheUID       int
	cacheGID       int
	cacheLogFile   string
	executable     string
	logger         *slog.Logger
}

func superviseCacheServe(ctx context.Context, args []string, cfg supervisorConfig) (int, error) {
	if cfg.restartBudget <= 0 {
		cfg.restartBudget = 1
	}
	if cfg.restartWindow <= 0 {
		cfg.restartWindow = 10 * time.Minute
	}
	if cfg.initialBackoff <= 0 {
		cfg.initialBackoff = time.Second
	}
	if cfg.maxBackoff < cfg.initialBackoff {
		cfg.maxBackoff = cfg.initialBackoff
	}
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}
	if err := validateCacheChildIdentity(cfg.cacheUID, cfg.cacheGID); err != nil {
		return 1, err
	}
	exe := cfg.executable
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return 1, fmt.Errorf("locate relayd executable: %w", err)
		}
	}
	restarts := []time.Time{}
	backoff := cfg.initialBackoff
	for {
		cmd, logFile, cmdErr := cacheServeCommand(ctx, exe, args, cfg)
		if cmdErr != nil {
			return 1, cmdErr
		}
		err := cmd.Run()
		if logFile != nil {
			if closeErr := logFile.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
		}
		if ctx.Err() != nil {
			return 0, nil
		}
		if err == nil {
			return 0, nil
		}
		now := time.Now()
		cutoff := now.Add(-cfg.restartWindow)
		kept := restarts[:0]
		for _, at := range restarts {
			if at.After(cutoff) {
				kept = append(kept, at)
			}
		}
		restarts = append(kept, now)
		if len(restarts) > cfg.restartBudget {
			return 1, fmt.Errorf("cache-serve exceeded restart budget: %d crashes inside %s", len(restarts), cfg.restartWindow)
		}
		cfg.logger.Warn("cache-serve exited; restarting", "err", err, "backoff", backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return 0, nil
		case <-timer.C:
		}
		backoff = minDuration(backoff*2, cfg.maxBackoff)
	}
}

func validateCacheChildIdentity(uid, gid int) error {
	if uid < -1 || gid < -1 {
		return fmt.Errorf("cache child uid/gid must be >= -1")
	}
	if (uid == -1) != (gid == -1) {
		return fmt.Errorf("cache child uid and gid must be configured together")
	}
	return nil
}

func cacheServeCommand(ctx context.Context, exe string, args []string, cfg supervisorConfig) (*exec.Cmd, *os.File, error) {
	cmd := exec.CommandContext(ctx, exe, append([]string{"cache-serve"}, args...)...)
	cmd.Stdin = os.Stdin
	if cfg.cacheUID >= 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(cfg.cacheUID), Gid: uint32(cfg.cacheGID)},
		}
	}
	if cfg.cacheLogFile == "" {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd, nil, nil
	}
	logFile, err := os.OpenFile(cfg.cacheLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open cache child log: %w", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	return cmd, logFile, nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// relaydFlags holds the resolved relayd flag/env values. It exists so the
// flag-to-relay.Config wiring (notably the operator-tunable connection caps)
// is testable without standing up a listener.
type relaydFlags struct {
	publicAddr               string
	tokenMode                string
	tokenVerifier            relay.TokenVerifier
	carrierAddr              string
	quicAddr                 string
	adminAddr                string
	adminAllowPublic         bool
	adminMetricsToken        string
	getCertificate           func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	streamCap                int
	maxPublicConns           int
	maxPublicConnsPerIP      int
	maxStreamsPerCarrierIP   int
	publicPeekTimeout        time.Duration
	maxCarrierConns          int
	rateBytes                int64
	rateBurst                int64
	shutdownGrace            time.Duration
	expiredSessionDrain      time.Duration
	redactConnectionLogs     *bool
	yamuxStreamWindowBytes   int
	fairUseEnabled           bool
	fairUseWindowDays        int
	fairUseSoftLimitBytes    int64
	fairUseHardLimitBytes    int64
	fairUseThrottledMaxConns int
	fairUseStore             string
	fairUseRedisURL          string
	fairUseOutboxPath        string
	fairUseLeaseTTL          time.Duration
	fairUseFenceMargin       time.Duration
	logger                   *slog.Logger
}

// Carrier token verification modes (--token-mode). Static presents/compares the
// token bytes directly (replayable if captured); hmac treats the token bytes as a
// shared secret from which carriers mint expiring, replay-resistant v2 tunnel
// tokens (docs/operator-self-hosted-relay.md, "Expiring, Replay-Resistant Tunnel
// Tokens (v2)").
const (
	tokenModeStatic           = "static"
	tokenModeHMAC             = "hmac"
	defaultTokenMode          = tokenModeHMAC
	defaultHMACNonceStorePath = "/var/lib/beamfall-relay/hmac-nonces.json"
	defaultFairUseOutboxPath  = "/var/lib/beamfall-relay/fairuse-outbox.json"
)

func validateTokenMode(mode, devMode string) error {
	if mode == tokenModeHMAC {
		return nil
	}
	if mode != tokenModeStatic {
		return fmt.Errorf("unknown --token-mode %q (want %q or %q)", mode, tokenModeStatic, tokenModeHMAC)
	}
	if devMode != "1" {
		return fmt.Errorf("--token-mode %q is insecure-development-only and is refused in production because static bearer tokens never expire and are replayable if captured: set %s=1 to enable it", tokenModeStatic, config.DevModeEnv)
	}
	return nil
}

// buildTokenVerifier selects the TokenVerifier for the resolved --token-mode.
// The hmac verifier sets AcceptLegacyV1 false: the shipped binaries never minted
// legacy v1 tokens (static mode sends the raw token, not a v1 HMAC), so there is
// no v1 carrier population to upgrade in place — strict v2 from the start.
func buildTokenVerifier(mode string, token []byte, hosts []string, nonceStorePath string, nonceStoreCapacity int) (relay.TokenVerifier, error) {
	if mode == tokenModeHMAC {
		store, err := relay.NewFileHMACNonceStoreWithCapacity(nonceStorePath, nonceStoreCapacity)
		if err != nil {
			return nil, fmt.Errorf("initialize hmac nonce store %q: %w", nonceStorePath, err)
		}
		return &relay.HMACTokenVerifier{
			Secret:     token,
			Hostnames:  hosts,
			NonceStore: store,
		}, nil
	}
	if mode != tokenModeStatic {
		return nil, fmt.Errorf("unknown token mode %q", mode)
	}
	return relay.StaticTokenVerifier{
		Token:     token,
		CarrierID: "static",
		Hostnames: hosts,
	}, nil
}

// buildRelayConfig maps resolved relayd flags to relay.Config. Connection caps
// pass through verbatim; a 0/negative cap falls through to the library default.
func buildRelayConfig(f relaydFlags) relay.Config {
	cfg := relay.Config{
		PublicAddr:        f.publicAddr,
		CarrierAddr:       f.carrierAddr,
		QUICAddr:          f.quicAddr,
		AdminAddr:         f.adminAddr,
		AdminAllowPublic:  f.adminAllowPublic,
		AdminMetricsToken: f.adminMetricsToken,
		CarrierTLSConfig: &tls.Config{
			GetCertificate: f.getCertificate,
			MinVersion:     tls.VersionTLS13,
		},
		TokenVerifier:          f.tokenVerifier,
		StreamCap:              f.streamCap,
		MaxPublicConns:         f.maxPublicConns,
		MaxPublicConnsPerIP:    f.maxPublicConnsPerIP,
		PublicPeekTimeout:      f.publicPeekTimeout,
		MaxCarrierConns:        f.maxCarrierConns,
		RateBytesPerSec:        f.rateBytes,
		RateBurstBytes:         f.rateBurst,
		ShutdownGrace:          f.shutdownGrace,
		ExpiredSessionDrain:    f.expiredSessionDrain,
		RedactConnectionLogs:   f.redactConnectionLogs,
		YamuxStreamWindowBytes: f.yamuxStreamWindowBytes,
		FairUse: relay.FairUseConfig{
			Enabled:           f.fairUseEnabled,
			WindowDays:        f.fairUseWindowDays,
			SoftLimitBytes:    f.fairUseSoftLimitBytes,
			HardLimitBytes:    f.fairUseHardLimitBytes,
			ThrottledMaxConns: f.fairUseThrottledMaxConns,
			Store:             f.fairUseStore,
			RedisURL:          f.fairUseRedisURL,
			OutboxPath:        f.fairUseOutboxPath,
			LeaseTTL:          f.fairUseLeaseTTL,
			FenceMargin:       f.fairUseFenceMargin,
		},
		Logger: f.logger,
	}
	cfg.MaxStreamsPerIPPerCarrier = f.maxStreamsPerCarrierIP
	return cfg
}
