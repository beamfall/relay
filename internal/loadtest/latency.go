package loadtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/beamfall/relay/internal/relay"
	"github.com/beamfall/relay/internal/tunnel"
)

// LatencyOptions configures one latency run: a small control stream measured
// while media streams saturate the same carrier.
type LatencyOptions struct {
	// Transport is tunnel.TransportTCP, tunnel.TransportQUIC or
	// tunnel.TransportAuto (the tunnel client's default: QUIC first, TLS/TCP if
	// the relay does not answer). TransportAuto needs ExternalLink and a
	// CarrierPort, because the client tries both transports at one address.
	// With ExternalCarrierDir it only names the address handed to the outside
	// client, which picks its own transport.
	Transport string
	// Link is the emulated link between the tunnel client and the relay.
	Link Link
	// Duration is how long control messages are sent, after Warmup.
	Duration time.Duration
	// Warmup is sent but not measured, so carrier start-up is excluded.
	Warmup time.Duration
	// MediaStreams is the number of bulk streams, each sending as fast as the
	// carrier accepts in both directions. Zero measures an idle carrier.
	MediaStreams int
	// ControlInterval is the gap between control messages. Zero uses 5 ms.
	ControlInterval time.Duration
	// ExternalLink leaves Link out: the tunnel client dials the relay's carrier
	// listener directly, for a run whose link is shaped outside the process
	// (script/netem-latency.sh).
	ExternalLink bool
	// CarrierPort fixes the relay's carrier port, TCP and UDP, so an outside
	// shaper can match it. Zero picks free ports.
	CarrierPort int
	// ExternalCarrierDir, when set, leaves this repository's tunnel client out:
	// the run waits for an outside tunnel client (core's) to register as the
	// home's carrier, and writes what that client needs into the directory. See
	// writeExternalCarrierFiles.
	ExternalCarrierDir string
}

// LatencyResult is the control stream's round-trip latency through the relay:
// client to home server and back.
type LatencyResult struct {
	Samples int
	// Unanswered counts measured messages whose echo had not returned
	// echoGrace after the last send. They are missing from the percentiles, so
	// a non-zero value means the tail is worse than reported.
	Unanswered     int
	P50, P99, P999 time.Duration
	Max            time.Duration
	// CarrierTransport is the transport this repository's tunnel client
	// connected over. It is empty for an outside carrier.
	CarrierTransport string
	MediaBytes       int64
	MediaMbps        float64
}

// ControlP99Budget is the latency budget for the control stream: its
// round-trip p99 over ReferenceLink while one media stream saturates the same
// carrier in both directions. docs/relay-latency-budget.md records the
// measurements behind it.
const ControlP99Budget = 250 * time.Millisecond

// ReferenceLink is the link the budget is stated for: a 20 Mbit/s home uplink
// with a 20 ms round trip and a 50 ms bottleneck queue.
func ReferenceLink() Link {
	return Link{Delay: 10 * time.Millisecond, BitsPerSecond: 20e6, Queue: defaultLinkQueue, Seed: 1}
}

const (
	latencyHost      = "home.relay.test"
	latencyToken     = "loadgen-token"
	controlMessage   = 64
	mediaChunk       = 32 * 1024
	echoGrace        = 2 * time.Second
	streamKindEcho   = 'c'
	streamKindMedia  = 'm'
	carrierReadyWait = 10 * time.Second
	// externalCarrierReadyWait is longer: the outside tunnel client is a
	// separate process that starts after the files appear.
	externalCarrierReadyWait = 60 * time.Second
)

// Files written into LatencyOptions.ExternalCarrierDir.
const (
	// ExternalCarrierSecretFile is the shared HMAC secret the outside client
	// mints its carrier tokens from, mode 0600. Its name is the one core reads
	// from its secrets directory.
	ExternalCarrierSecretFile = "relay-token"
	// ExternalCarrierCAFile is the relay's carrier certificate in PEM, valid
	// for 127.0.0.1.
	ExternalCarrierCAFile = "relay-ca.pem"
	// ExternalCarrierEnvFile holds KEY=value lines: RELAY_ENDPOINT (the carrier
	// address to dial), BACKEND_ADDR (the home server streams are spliced to)
	// and PUBLIC_HOST (the hostname to register). It is written last, by
	// rename, so its presence means the other files and the relay are ready.
	ExternalCarrierEnvFile = "carrier.env"
)

// latencyVerifier returns the relay's token verifier. An outside carrier mints
// expiring HMAC tokens from a shared secret (returned), as a self-hosted relay
// does; this repository's own tunnel client presents a fixed token.
func latencyVerifier(opts LatencyOptions) (relay.TokenVerifier, []byte, error) {
	if opts.ExternalCarrierDir == "" {
		return relay.StaticTokenVerifier{
			Token:     []byte(latencyToken),
			CarrierID: "loadgen",
			Hostnames: []string{latencyHost},
		}, nil, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, nil, err
	}
	secret := []byte(hex.EncodeToString(raw))
	store, err := relay.NewFileHMACNonceStore(filepath.Join(opts.ExternalCarrierDir, "nonces.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("nonce store: %w", err)
	}
	return &relay.HMACTokenVerifier{
		Secret:     secret,
		CarrierID:  "external",
		Hostnames:  []string{latencyHost},
		NonceStore: store,
	}, secret, nil
}

func writeExternalCarrierFiles(dir, carrierAddr, backendAddr string, secret []byte, relayCert tls.Certificate) error {
	if err := os.WriteFile(filepath.Join(dir, ExternalCarrierSecretFile), secret, 0o600); err != nil {
		return err
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: relayCert.Certificate[0]})
	if err := os.WriteFile(filepath.Join(dir, ExternalCarrierCAFile), ca, 0o600); err != nil {
		return err
	}
	env := fmt.Sprintf("RELAY_ENDPOINT=%s\nBACKEND_ADDR=%s\nPUBLIC_HOST=%s\n", carrierAddr, backendAddr, latencyHost)
	tmp := filepath.Join(dir, ExternalCarrierEnvFile+".tmp")
	if err := os.WriteFile(tmp, []byte(env), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, ExternalCarrierEnvFile))
}

// RunLatency starts a relay, a home server and a tunnel client in-process,
// joins the client to the relay through opts.Link, and measures the control
// stream. Messages carry only their send time, and the home server echoes
// them; the relay in between still sees opaque TLS.
func RunLatency(ctx context.Context, opts LatencyOptions) (LatencyResult, error) {
	if opts.ControlInterval <= 0 {
		opts.ControlInterval = 5 * time.Millisecond
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	home, roots, err := startEchoHome(ctx)
	if err != nil {
		return LatencyResult{}, fmt.Errorf("start home server: %w", err)
	}
	relayCert, err := selfSignedCert("relay-carrier.local")
	if err != nil {
		return LatencyResult{}, err
	}
	verifier, secret, err := latencyVerifier(opts)
	if err != nil {
		return LatencyResult{}, err
	}
	carrierListen := fmt.Sprintf("127.0.0.1:%d", opts.CarrierPort)
	node, err := startRelay(ctx, relay.Config{
		PublicAddr:  "127.0.0.1:0",
		CarrierAddr: carrierListen,
		QUICAddr:    carrierListen,
		AdminAddr:   "127.0.0.1:0",
		CarrierTLSConfig: &tls.Config{
			Certificates: []tls.Certificate{relayCert},
			MinVersion:   tls.VersionTLS13,
		},
		TokenVerifier: verifier,
		StreamCap:     opts.MediaStreams + 8,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		return LatencyResult{}, fmt.Errorf("start relay: %w", err)
	}
	defer node.Close()

	carrierAddr, err := startLink(ctx, node, opts)
	if err != nil {
		return LatencyResult{}, fmt.Errorf("start link: %w", err)
	}
	readyWait := carrierReadyWait
	carrierTransport := func() string { return "" }
	if opts.ExternalCarrierDir != "" {
		if err := writeExternalCarrierFiles(opts.ExternalCarrierDir, carrierAddr, home.Addr().String(), secret, relayCert); err != nil {
			return LatencyResult{}, fmt.Errorf("write external carrier files: %w", err)
		}
		readyWait = externalCarrierReadyWait
	} else {
		client, err := tunnel.Start(ctx, tunnel.Config{
			RelayAddr:   carrierAddr,
			BackendAddr: home.Addr().String(),
			Token:       []byte(latencyToken),
			Hostnames:   []string{latencyHost},
			Transport:   opts.Transport,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
			},
		})
		if err != nil {
			return LatencyResult{}, fmt.Errorf("start tunnel client: %w", err)
		}
		defer client.Close()
		carrierTransport = client.Transport
	}

	dial := func(kind byte) (net.Conn, error) {
		conn, err := (&tls.Dialer{Config: &tls.Config{
			ServerName: latencyHost,
			RootCAs:    roots,
			MinVersion: tls.VersionTLS13,
		}}).DialContext(ctx, "tcp", node.PublicAddr())
		if err != nil {
			return nil, err
		}
		if _, err := conn.Write([]byte{kind}); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}

	// The relay refuses public connections until the carrier has registered.
	var control net.Conn
	for deadline := time.Now().Add(readyWait); ; {
		if control, err = dial(streamKindEcho); err == nil {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return LatencyResult{}, fmt.Errorf("carrier never became ready: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer func() { _ = control.Close() }()

	var mediaBytes atomic.Int64
	var media sync.WaitGroup
	for range opts.MediaStreams {
		conn, err := dial(streamKindMedia)
		if err != nil {
			return LatencyResult{}, fmt.Errorf("open media stream: %w", err)
		}
		media.Add(2)
		go func() { defer media.Done(); _ = pump(conn, &mediaBytes) }()
		go func() { defer media.Done(); _ = drain(conn, &mediaBytes) }()
		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()
	}
	mediaStart := time.Now()

	latencies, unanswered, err := measureControl(ctx, control, opts)
	if err != nil {
		return LatencyResult{}, err
	}
	mediaElapsed := time.Since(mediaStart)
	total := mediaBytes.Load()
	cancel()
	media.Wait()

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	result := LatencyResult{
		Samples:    len(latencies),
		Unanswered: unanswered,
		P50:        Percentile(latencies, 0.50),
		P99:        Percentile(latencies, 0.99),
		P999:       Percentile(latencies, 0.999),
		MediaBytes: total,
		MediaMbps:  float64(total*8) / mediaElapsed.Seconds() / 1e6,

		CarrierTransport: carrierTransport(),
	}
	if len(latencies) > 0 {
		result.Max = latencies[len(latencies)-1]
	}
	return result, nil
}

// startLink returns the address the tunnel client dials: the emulated link in
// front of the relay's carrier listener, or the listener itself when the link
// is external.
func startLink(ctx context.Context, node *relay.Server, opts LatencyOptions) (string, error) {
	switch opts.Transport {
	case tunnel.TransportTCP:
		if opts.ExternalLink {
			return node.CarrierAddr(), nil
		}
		return ProxyTCP(ctx, node.CarrierAddr(), opts.Link)
	case tunnel.TransportQUIC:
		if opts.ExternalLink {
			return node.QUICAddr(), nil
		}
		return ProxyUDP(ctx, node.QUICAddr(), opts.Link)
	case tunnel.TransportAuto:
		if !opts.ExternalLink || opts.CarrierPort == 0 {
			return "", fmt.Errorf("the %q transport needs an external link and a fixed carrier port", tunnel.TransportAuto)
		}
		return node.CarrierAddr(), nil
	default:
		return "", fmt.Errorf("unknown transport %q", opts.Transport)
	}
}

// measureControl sends a timestamped message every ControlInterval and reads
// the echoes on a second goroutine, so a slow echo never delays the next send.
func measureControl(ctx context.Context, conn net.Conn, opts LatencyOptions) ([]time.Duration, int, error) {
	epoch := time.Now()
	// Sized past the number of messages the ticker can send, so the reader
	// never blocks on it.
	echoed := make(chan time.Duration, 2*int((opts.Warmup+opts.Duration)/opts.ControlInterval)+16)
	go func() {
		msg := make([]byte, controlMessage)
		for {
			if _, err := io.ReadFull(conn, msg); err != nil {
				return
			}
			sentAt := time.Duration(binary.BigEndian.Uint64(msg))
			if sentAt >= opts.Warmup {
				echoed <- time.Since(epoch) - sentAt
			}
		}
	}()

	msg := make([]byte, controlMessage)
	ticker := time.NewTicker(opts.ControlInterval)
	defer ticker.Stop()
	sent := 0
	for end := opts.Warmup + opts.Duration; ; {
		now := time.Since(epoch)
		if now >= end {
			break
		}
		binary.BigEndian.PutUint64(msg, uint64(now))
		if err := conn.SetWriteDeadline(time.Now().Add(echoGrace)); err != nil {
			return nil, 0, err
		}
		if _, err := conn.Write(msg); err != nil {
			return nil, 0, fmt.Errorf("control stream write: %w", err)
		}
		if now >= opts.Warmup {
			sent++
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-ticker.C:
		}
	}

	// Media keeps running while the last echoes come back. Anything still
	// missing after the grace period is reported, not silently dropped.
	latencies := make([]time.Duration, 0, sent)
	grace := time.NewTimer(echoGrace)
	defer grace.Stop()
	for len(latencies) < sent {
		select {
		case latency := <-echoed:
			latencies = append(latencies, latency)
		case <-grace.C:
			return latencies, sent - len(latencies), nil
		}
	}
	return latencies, 0, nil
}

// Percentile returns the nearest-rank p-quantile of a sorted slice (empty -> 0).
func Percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p * float64(len(sorted))))
	return sorted[min(max(rank, 1), len(sorted))-1]
}

// pump writes media until the connection fails.
func pump(conn net.Conn, total *atomic.Int64) error {
	chunk := make([]byte, mediaChunk)
	for {
		n, err := conn.Write(chunk)
		total.Add(int64(n))
		if err != nil {
			return err
		}
	}
}

// drain discards media until the connection fails.
func drain(conn net.Conn, total *atomic.Int64) error {
	buf := make([]byte, mediaChunk)
	for {
		n, err := conn.Read(buf)
		total.Add(int64(n))
		if err != nil {
			return err
		}
	}
}

// startEchoHome is the fake home server. The first byte of each stream picks
// its role: echo for the control stream, or a media stream that sends and
// discards as fast as it can.
func startEchoHome(ctx context.Context) (net.Listener, *x509.CertPool, error) {
	cert, err := selfSignedCert(latencyHost)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return nil, nil, err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				go func() {
					<-ctx.Done()
					_ = conn.Close()
				}()
				kind := make([]byte, 1)
				if _, err := io.ReadFull(conn, kind); err != nil {
					return
				}
				var discard atomic.Int64
				switch kind[0] {
				case streamKindEcho:
					_, _ = io.Copy(conn, conn)
				case streamKindMedia:
					go func() { _ = pump(conn, &discard) }()
					_ = drain(conn, &discard)
				}
			}()
		}
	}()
	return ln, roots, nil
}

func selfSignedCert(dnsName string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		// Everything here listens on loopback; an outside carrier verifies the
		// relay's certificate against the address it dials.
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// startRelay starts the relay, waiting briefly for a fixed carrier port still
// held by the previous run in this process: a closed QUIC listener gives its
// UDP socket back only once its connections have ended.
func startRelay(ctx context.Context, cfg relay.Config) (*relay.Server, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		node, err := relay.Start(ctx, cfg)
		if err == nil || !errors.Is(err, syscall.EADDRINUSE) || time.Now().After(deadline) {
			return node, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
