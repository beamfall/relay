package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/beamfall/relay/internal/relay"
	"github.com/beamfall/relay/internal/tunnel"
)

func main() {
	var (
		duration  = flag.Duration("duration", 30*time.Second, "soak duration")
		streams   = flag.Int("streams", 8, "concurrent tunneled streams")
		mbps      = flag.Float64("mbps", 32, "target aggregate throughput in megabits per second")
		host      = flag.String("host", "home.relay.test", "SNI hostname")
		fairUse   = flag.Bool("fair-use", false, "enable fair-use accounting with high test limits")
		transport = flag.String("transport", tunnel.TransportTCP, "carrier transport: tcp (v1 yamux) or quic (ADR-0018 v2)")
	)
	flag.Parse()
	if *streams < 1 {
		log.Fatal("streams must be at least 1")
	}
	if *duration <= 0 {
		log.Fatal("duration must be positive")
	}
	if *mbps <= 0 {
		log.Fatal("mbps must be positive")
	}
	if *transport != tunnel.TransportTCP && *transport != tunnel.TransportQUIC {
		log.Fatalf("transport must be %q or %q, got %q", tunnel.TransportTCP, tunnel.TransportQUIC, *transport)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	home, roots, err := startHome(*host)
	if err != nil {
		log.Fatalf("start fake home server: %v", err)
	}
	defer func() { _ = home.Close() }()

	relayCert, err := selfSignedCert("relay-carrier.local")
	if err != nil {
		log.Fatalf("generate relay carrier cert: %v", err)
	}
	node, err := relay.Start(ctx, relay.Config{
		PublicAddr:  "127.0.0.1:0",
		CarrierAddr: "127.0.0.1:0",
		QUICAddr:    "127.0.0.1:0",
		AdminAddr:   "127.0.0.1:0",
		CarrierTLSConfig: &tls.Config{
			Certificates: []tls.Certificate{relayCert},
			MinVersion:   tls.VersionTLS13,
		},
		TokenVerifier: relay.StaticTokenVerifier{
			Token:     []byte("loadgen-token"),
			CarrierID: "loadgen",
			Hostnames: []string{*host},
		},
		StreamCap: *streams + 8,
		FairUse: relay.FairUseConfig{
			Enabled:           *fairUse,
			WindowDays:        30,
			SoftLimitBytes:    1 << 60,
			HardLimitBytes:    1 << 61,
			ThrottledMaxConns: *streams + 8,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		log.Fatalf("start relay: %v", err)
	}
	defer node.Close()

	carrierAddr := node.CarrierAddr()
	if *transport == tunnel.TransportQUIC {
		carrierAddr = node.QUICAddr()
	}
	client, err := tunnel.Start(ctx, tunnel.Config{
		RelayAddr:   carrierAddr,
		BackendAddr: home.Addr().String(),
		Token:       []byte("loadgen-token"),
		Hostnames:   []string{*host},
		Transport:   *transport,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
	})
	if err != nil {
		log.Fatalf("start tunnel client: %v", err)
	}
	defer client.Close()

	time.Sleep(100 * time.Millisecond)

	var bytesRelayed atomic.Int64
	var streamsOpened atomic.Int64
	latencies := make([]time.Duration, *streams)
	perStreamBytes := make([]int64, *streams)
	perStreamBps := (*mbps * 1000 * 1000 / 8) / float64(*streams)

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < *streams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			latency, n, err := runStream(ctx, node.PublicAddr(), *host, roots, perStreamBps)
			if err != nil && ctx.Err() == nil {
				log.Printf("stream %d failed: %v", i, err)
				return
			}
			latencies[i] = latency
			perStreamBytes[i] = n
			if latency > 0 {
				streamsOpened.Add(1)
			}
			bytesRelayed.Add(n)
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	fmt.Printf("transport=%s\n", *transport)
	fmt.Printf("duration_seconds=%.3f\n", elapsed.Seconds())
	fmt.Printf("streams_requested=%d\n", *streams)
	fmt.Printf("streams_opened=%d\n", streamsOpened.Load())
	fmt.Printf("streams_per_second=%.3f\n", float64(streamsOpened.Load())/elapsed.Seconds())
	fmt.Printf("bytes_relayed=%d\n", bytesRelayed.Load())
	fmt.Printf("throughput_mbps=%.3f\n", float64(bytesRelayed.Load()*8)/elapsed.Seconds()/1000/1000)
	fmt.Printf("setup_latency_p50_ms=%.3f\n", percentile(latencies, 0.50).Seconds()*1000)
	fmt.Printf("setup_latency_p99_ms=%.3f\n", percentile(latencies, 0.99).Seconds()*1000)
	// Per-stream throughput isolates head-of-line blocking: on the v1 yamux
	// carrier a single stalled/lossy stream drags its siblings down (shared
	// congestion window), so the spread across per_stream_mbps_* widens under
	// netem loss; QUIC's per-stream flow control keeps the spread tight. The
	// netem-soak.sh harness tabulates these against injected RTT/loss.
	elapsedSecs := elapsed.Seconds()
	perStreamMbps := make([]float64, 0, len(perStreamBytes))
	for _, n := range perStreamBytes {
		if n > 0 {
			perStreamMbps = append(perStreamMbps, float64(n*8)/elapsedSecs/1000/1000)
		}
	}
	sort.Float64s(perStreamMbps)
	fmt.Printf("per_stream_mbps_min=%.3f\n", floatPercentile(perStreamMbps, 0.0))
	fmt.Printf("per_stream_mbps_p50=%.3f\n", floatPercentile(perStreamMbps, 0.50))
	fmt.Printf("per_stream_mbps_max=%.3f\n", floatPercentile(perStreamMbps, 1.0))
	fmt.Printf("relayd_in_process_max_rss_bytes=%d\n", maxRSSBytes())
	fmt.Printf("relay_admin_addr=%s\n", node.AdminAddr())
}

// floatPercentile returns the p-quantile of a sorted slice (empty -> 0).
func floatPercentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func runStream(ctx context.Context, addr, host string, roots *x509.CertPool, bytesPerSecond float64) (time.Duration, int64, error) {
	start := time.Now()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		ServerName: host,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = conn.Close() }()
	latency := time.Since(start)

	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	sleepFor := time.Duration(0)
	if bytesPerSecond > 0 {
		sleepFor = time.Duration(float64(len(payload)) / bytesPerSecond * float64(time.Second))
	}

	var written int64
	for ctx.Err() == nil {
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return latency, written, err
		}
		n, err := conn.Write(payload)
		written += int64(n)
		if err != nil {
			return latency, written, err
		}
		if sleepFor > 0 {
			timer := time.NewTimer(sleepFor)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}
	return latency, written, nil
}

func startHome(host string) (net.Listener, *x509.CertPool, error) {
	cert, err := selfSignedCert(host)
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	for _, der := range cert.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, err
		}
		roots.AddCert(parsed)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return nil, nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(io.Discard, conn)
			}(conn)
		}
	}()
	return ln, roots, nil
}

func selfSignedCert(dnsName string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}

func percentile(values []time.Duration, p float64) time.Duration {
	filtered := values[:0]
	for _, value := range values {
		if value > 0 {
			filtered = append(filtered, value)
		}
	}
	if len(filtered) == 0 {
		return 0
	}
	idx := int(float64(len(filtered)-1) * p)
	return filtered[idx]
}

func maxRSSBytes() int64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	if runtime.GOOS == "linux" {
		return usage.Maxrss * 1024
	}
	return usage.Maxrss
}
