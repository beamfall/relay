package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/beamfall/relay/internal/config"
	"github.com/beamfall/relay/internal/relay"
	"github.com/beamfall/relay/internal/tunnel"
)

func main() {
	tokenTTLDefault, err := config.DurationEnvOrDefault(os.Getenv("TUNNEL_TOKEN_TTL"), defaultTokenTTL)
	if err != nil {
		log.Fatalf("load token ttl default: %v", err)
	}
	var (
		relayAddr              = flag.String("relay-addr", config.EnvOrDefault(os.Getenv("TUNNEL_RELAY_ADDR"), "127.0.0.1:9443"), "relay carrier address")
		backendAddr            = flag.String("backend-addr", os.Getenv("TUNNEL_BACKEND_ADDR"), "home server TLS address")
		hostnames              = flag.String("hostnames", os.Getenv("TUNNEL_HOSTNAMES"), "comma-separated hostnames served by this tunnel")
		tokenFile              = flag.String("token-file", os.Getenv("TUNNEL_TOKEN_FILE"), "tunnel token/secret file (see --token-mode)")
		tokenMode              = flag.String("token-mode", config.EnvOrDefault(os.Getenv("TUNNEL_TOKEN_MODE"), defaultTokenMode), "carrier token mode: 'hmac' (production default; treat the token file/env value as a shared SECRET and mint a fresh expiring, replay-resistant v2 tunnel token on every carrier dial) or 'static' (insecure development only; requires BEAMFALL_RELAY_DEV=1 — relayd --token-mode must match)")
		tokenTTL               = flag.Duration("token-ttl", tokenTTLDefault, "hmac token mode only: validity window of each minted v2 tunnel token. The client proactively establishes a fresh carrier halfway through this window while the old carrier drains")
		caFile                 = flag.String("relay-ca", os.Getenv("TUNNEL_RELAY_CA"), "relay carrier CA PEM file")
		insecureTest           = flag.Bool("insecure-skip-verify", false, "skip relay carrier TLS verification for local tests only")
		transport              = flag.String("transport", config.EnvOrDefault(os.Getenv("TUNNEL_TRANSPORT"), tunnel.TransportTCP), "carrier wire transport: tcp (v1 yamux) or quic (ADR-0018 v2); --relay-addr must point at the matching relay listener")
		yamuxStreamWindowBytes = flag.Int("yamux-stream-window-bytes", 0, "v1 (tcp transport) carrier per-stream flow-control window in bytes; 0 uses the 1 MiB default. Must match the relay's --yamux-stream-window-bytes. Ignored for quic transport.")
	)
	flag.Parse()

	// Structural guard: --insecure-skip-verify disables carrier TLS verification
	// and is for local testing only. Refuse it unless developer mode is explicitly
	// unlocked (BEAMFALL_RELAY_DEV=1), so a copied test invocation or a
	// misconfigured unit cannot silently run production carrier TLS without
	// verification (RV-RELAY-006).
	if err := config.GuardInsecureSkipVerify(*insecureTest, os.Getenv(config.DevModeEnv)); err != nil {
		log.Fatalf("%v", err)
	}

	tokenBytes, err := config.SecretFromEnvOrFile(os.Getenv("TUNNEL_TOKEN"), *tokenFile)
	if err != nil {
		log.Fatalf("load token: %v", err)
	}
	tlsConfig, err := buildCarrierTLSConfig(*insecureTest, *caFile)
	if err != nil {
		log.Fatalf("build carrier TLS config: %v", err)
	}
	logger := slog.Default()
	if *insecureTest {
		logger.Warn("carrier TLS verification disabled", "flag", "insecure-skip-verify", "scope", "local testing only")
	}
	if *backendAddr == "" {
		log.Fatal("backend address is required")
	}
	hosts := config.SplitCSV(*hostnames)
	if len(hosts) == 0 {
		log.Fatal("at least one hostname is required")
	}
	token, tokenProvider, err := buildTokenSource(*tokenMode, tokenBytes, hosts, *tokenTTL, os.Getenv(config.DevModeEnv))
	if err != nil {
		log.Fatalf("build token source: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	client, err := tunnel.Start(ctx, tunnel.Config{
		RelayAddr:              *relayAddr,
		BackendAddr:            *backendAddr,
		Token:                  token,
		TokenProvider:          tokenProvider,
		TokenRotationInterval:  tokenRotationInterval(*tokenMode, *tokenTTL),
		Hostnames:              hosts,
		TLSConfig:              tlsConfig,
		Logger:                 logger,
		Transport:              *transport,
		YamuxStreamWindowBytes: *yamuxStreamWindowBytes,
	})
	if err != nil {
		log.Fatalf("start tunnel client: %v", err)
	}
	logger.Info("tunnel client started", "relay", *relayAddr, "backend", *backendAddr, "hosts", hosts, "transport", *transport, "auto_reconnect", true)
	<-ctx.Done()
	client.Close()
	client.Wait()
}

func tokenRotationInterval(mode string, ttl time.Duration) time.Duration {
	if mode != tokenModeHMAC {
		return 0
	}
	return ttl / 2
}

// Carrier token modes (--token-mode), mirroring relayd's verifier modes. Static
// presents the loaded token bytes verbatim on every dial; hmac treats them as a
// shared secret and mints a fresh expiring, replay-resistant v2 tunnel token per
// dial (docs/operator-self-hosted-relay.md, "Expiring, Replay-Resistant Tunnel
// Tokens (v2)").
const (
	tokenModeStatic  = "static"
	tokenModeHMAC    = "hmac"
	defaultTokenMode = tokenModeHMAC

	// defaultTokenTTL matches the relay verifier's hard acceptance ceiling. The
	// The client proactively replaces the carrier halfway through this validity
	// window, while the relay lets the prior generation drain after expiry.
	defaultTokenTTL = relay.MaxHMACTokenTTL
)

// buildTokenSource maps --token-mode to the tunnel.Config token fields: static
// mode returns the token bytes for verbatim presentation; hmac mode returns a
// TokenProvider that mints a fresh v2 tunnel token from the shared secret on
// every carrier dial, so each reconnect presents an unexpired, never-before-seen
// token (the relay's replay guard rejects re-presented nonces).
func buildTokenSource(mode string, tokenBytes []byte, hosts []string, ttl time.Duration, devMode string) ([]byte, func(context.Context) ([]byte, error), error) {
	switch mode {
	case tokenModeStatic:
		if devMode != "1" {
			return nil, nil, fmt.Errorf("--token-mode %q is insecure-development-only and is refused in production because static bearer tokens never expire and are replayable if captured: set %s=1 to enable it", tokenModeStatic, config.DevModeEnv)
		}
		return tokenBytes, nil, nil
	case tokenModeHMAC:
		if ttl <= 0 {
			return nil, nil, fmt.Errorf("--token-ttl must be positive in hmac token mode, got %s", ttl)
		}
		if ttl > relay.MaxHMACTokenTTL {
			return nil, nil, fmt.Errorf("--token-ttl must not exceed %s in hmac token mode, got %s", relay.MaxHMACTokenTTL, ttl)
		}
		provider := func(context.Context) ([]byte, error) {
			return relay.MintHMACTunnelToken(tokenBytes, hosts, ttl)
		}
		return nil, provider, nil
	default:
		return nil, nil, fmt.Errorf("unknown token mode %q (want %q or %q)", mode, tokenModeStatic, tokenModeHMAC)
	}
}

// buildCarrierTLSConfig assembles the TLS config used to dial the relay carrier
// listener. The default is verify-on (system roots, or the pinned CA if caPath
// is set) at TLS 1.3. insecure takes precedence over caPath -- when insecure is
// true, verification is skipped entirely and caPath is ignored; this is for
// local testing only (see --insecure-skip-verify). A non-empty caPath that
// cannot be read or contains no certificates is a hard error.
func buildCarrierTLSConfig(insecure bool, caPath string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if insecure {
		cfg.InsecureSkipVerify = true
		return cfg, nil
	}
	if caPath != "" {
		pemBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read relay CA: %w", err)
		}
		roots := x509.NewCertPool()
		if ok := roots.AppendCertsFromPEM(pemBytes); !ok {
			return nil, fmt.Errorf("relay CA file %q contained no certificates", caPath)
		}
		cfg.RootCAs = roots
	}
	return cfg, nil
}
