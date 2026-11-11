package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beamfall/relay/internal/relay"
)

// relaydReadyLine matches relayd's startup line. Fields logged between
// carrier= and admin= (quic= today) are skipped, so a new listener field does
// not stall the harness before carrier registration.
var relaydReadyLine = regexp.MustCompile(`relayd listening public=(\S+) carrier=(\S+)(?: \S+=\S*)* admin=(\S+)`)

const carriersConnectedMetric = "beamfall_relay_carriers_connected"

func TestRelayCoreRealBinaryE2E(t *testing.T) {
	if os.Getenv("BEAMFALL_RELAY_CORE_E2E") != "1" {
		t.Skip("set BEAMFALL_RELAY_CORE_E2E=1 with BEAMFALL_RELAYD_BIN and BEAMFALL_CORE_BIN to run the real-binary E2E")
	}
	relaydBin := requireExecutableEnv(t, "BEAMFALL_RELAYD_BIN")
	coreBin := requireExecutableEnv(t, "BEAMFALL_CORE_BIN")

	// The hold leg alone runs MaxHMACTokenTTL+30s; this stays under go test's
	// default 10m timeout, which script/relay-core-e2e.sh relies on.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	root := t.TempDir()
	const publicHost = "relay-core-e2e.test"
	const token = "relay-core-e2e-token-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const payloadSentinel = "relay-core-e2e-payload-sentinel"

	caKey, caCert, caPEM := newCA(t)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append test CA")
	}

	carrierCert, carrierKey := newLeaf(t, caKey, caCert, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	carrierCertPath := writeFile(t, root, "carrier.crt", carrierCert, 0o600)
	carrierKeyPath := writeFile(t, root, "carrier.key", carrierKey, 0o600)

	coreCert, coreKey := newLeaf(t, caKey, caCert, []string{publicHost}, nil)
	coreDataDir := filepath.Join(root, "core-data")
	coreACMEDir := filepath.Join(coreDataDir, "acme")
	if err := os.MkdirAll(coreACMEDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFileAt(t, filepath.Join(coreACMEDir, publicHost), append(coreKey, coreCert...), 0o600)

	coreSecretsDir := filepath.Join(coreDataDir, "secrets")
	if err := os.MkdirAll(coreSecretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFileAt(t, filepath.Join(coreSecretsDir, "relay-token"), []byte(token+"\n"), 0o600)
	relayTokenPath := writeFile(t, root, "relay-token", []byte(token+"\n"), 0o600)
	// Replay state outlives a relayd restart, as the default path does in
	// production, so the restart leg sees nonces the first relayd admitted.
	nonceStorePath := filepath.Join(root, "hmac-nonces.json")
	relaydArgs := func(carrierAddr string) []string {
		return []string{
			"--public-addr", "127.0.0.1:0",
			"--carrier-addr", carrierAddr,
			"--admin-addr", "127.0.0.1:0",
			"--carrier-cert", carrierCertPath,
			"--carrier-key", carrierKeyPath,
			"--token-file", relayTokenPath,
			"--hmac-nonce-store", nonceStorePath,
			"--hostnames", publicHost,
			"--shutdown-grace", "0",
		}
	}

	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()
	relayLog := newProcessLog()
	relayDone, ready := startRelayd(t, relayCtx, relayLog, relaydBin, relaydArgs("127.0.0.1:0"))
	publicAddr := ready[1]
	carrierAddr := ready[2]
	adminAddr := ready[3]

	coreLog := newProcessLog()
	coreDone := startProcess(t, ctx, coreLog, coreBin,
		"serve",
		"--addr", "127.0.0.1:0",
		"--data-dir", coreDataDir,
		"--server-name", "Relay Core E2E",
		"--discovery-enabled=false",
		"--seed=conformance",
		"--allow-conformance-seed",
		"--public-domain", publicHost,
		"--acme-terms-accepted",
		"--acme-cache-dir", coreACMEDir,
		"--relay-endpoint", carrierAddr,
		"--relay-public-host", publicHost,
		"--relay-ca", writeFile(t, root, "test-ca.pem", caPEM, 0o600),
	)
	coreLog.waitFor(t, regexp.MustCompile(`relay carrier connected`), 20*time.Second)
	assertRelayMetricEquals(t, adminAddr, carriersConnectedMetric, 1)

	client := relayHTTPClient(publicAddr, publicHost, roots)
	assertDirectByteThroughRelay(t, ctx, client, publicHost, payloadSentinel)
	assertRelayMetricPositive(t, adminAddr, "beamfall_relay_bytes_relayed_total")
	assertRelayMetricEquals(t, adminAddr, carriersConnectedMetric, 1)

	eventsCtx, eventsCancel := context.WithCancel(ctx)
	defer eventsCancel()
	eventsReq, err := http.NewRequestWithContext(eventsCtx, http.MethodGet, "https://"+publicHost+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	authorizeRelayE2EDevice(eventsReq)
	eventsResp, err := client.Do(eventsReq)
	if err != nil {
		t.Fatalf("events stream through relay: %v", err)
	}
	defer eventsResp.Body.Close() //nolint:errcheck // test response cleanup.
	if eventsResp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(eventsResp.Body)
		t.Fatalf("events stream status = %d, want 200: %s", eventsResp.StatusCode, data)
	}
	assertRelayMetricEventuallyEquals(t, adminAddr, carriersConnectedMetric, 1, 2*time.Second)
	assertRelayMetricEventuallyEquals(t, adminAddr, "beamfall_relay_active_tunnels", 1, 2*time.Second)
	assertRelayMetricEventuallyEquals(t, adminAddr, "beamfall_relay_streams_active", 1, 2*time.Second)

	leakNeedles := []string{token, payloadSentinel, "/api/media/direct/"}
	assertRelayLogClean(t, relayLog, leakNeedles)

	// The legs below need core to mint a fresh single-use v2 token per dial and
	// rotate it before expiry (CORE-RELAY-HMAC-SELFMINT-1).
	t.Run("hold_past_one_token_ttl", func(t *testing.T) {
		// relayd accepts a token only if exp-iat <= MaxHMACTokenTTL and iat <= now,
		// and closes an unreplaced carrier at exp, so the carrier live now must be
		// replaced before the hold ends for the relay to keep one throughout.
		hold := relay.MaxHMACTokenTTL + 30*time.Second
		deadline := time.Now().Add(hold)
		for time.Now().Before(deadline) {
			if got := relayMetric(t, adminAddr, carriersConnectedMetric); got < 1 {
				t.Fatalf("%s = %d with %s of the %s hold left", carriersConnectedMetric, got, time.Until(deadline).Round(time.Second), hold)
			}
			time.Sleep(time.Second)
		}
		assertDirectByteThroughRelay(t, ctx, client, publicHost, payloadSentinel)
	})

	t.Run("relayd_restart_reconnect", func(t *testing.T) {
		relayCancel()
		waitProcessExit(t, "relayd", relayDone, 10*time.Second)
		assertRelayLogClean(t, relayLog, leakNeedles)

		// Same carrier port, because core keeps dialing its fixed --relay-endpoint.
		restartCtx, restartCancel := context.WithCancel(ctx)
		defer restartCancel()
		restartLog := newProcessLog()
		restartDone, restarted := startRelayd(t, restartCtx, restartLog, relaydBin, relaydArgs(carrierAddr))
		restartedAdmin := restarted[3]
		// Core's redial backoff caps at 60s.
		assertRelayMetricEventuallyEquals(t, restartedAdmin, carriersConnectedMetric, 1, 90*time.Second)

		restartedClient := relayHTTPClient(restarted[1], publicHost, roots)
		assertDirectByteThroughRelay(t, ctx, restartedClient, publicHost, payloadSentinel)
		assertRelayMetricPositive(t, restartedAdmin, "beamfall_relay_bytes_relayed_total")
		assertRelayLogClean(t, restartLog, leakNeedles)

		restartCancel()
		waitProcessExit(t, "relayd", restartDone, 10*time.Second)
	})

	cancel()
	waitProcessExit(t, "core", coreDone, 10*time.Second)
}

// TestRelaydReadyLine starts relayd alone, with the arguments the core E2E
// uses, and requires the harness to parse its listening addresses. It needs
// only BEAMFALL_RELAYD_BIN, so the ready line is checked without a core build.
func TestRelaydReadyLine(t *testing.T) {
	if os.Getenv("BEAMFALL_RELAYD_BIN") == "" {
		t.Skip("set BEAMFALL_RELAYD_BIN to check the relayd ready line")
	}
	relaydBin := requireExecutableEnv(t, "BEAMFALL_RELAYD_BIN")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	root := t.TempDir()
	caKey, caCert, _ := newCA(t)
	carrierCert, carrierKey := newLeaf(t, caKey, caCert, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	relayLog := newProcessLog()
	relayDone, ready := startRelayd(t, ctx, relayLog, relaydBin, []string{
		"--public-addr", "127.0.0.1:0",
		"--carrier-addr", "127.0.0.1:0",
		"--admin-addr", "127.0.0.1:0",
		"--carrier-cert", writeFile(t, root, "carrier.crt", carrierCert, 0o600),
		"--carrier-key", writeFile(t, root, "carrier.key", carrierKey, 0o600),
		"--token-file", writeFile(t, root, "relay-token", []byte("relayd-ready-line-key-0123456789ABCDEFGHIJ\n"), 0o600),
		"--hmac-nonce-store", filepath.Join(root, "hmac-nonces.json"),
		"--hostnames", "relay-core-e2e.test",
		"--shutdown-grace", "0",
	})
	for i, name := range []string{"public", "carrier", "admin"} {
		if _, _, err := net.SplitHostPort(ready[i+1]); err != nil {
			t.Fatalf("%s address %q from %q: %v", name, ready[i+1], ready[0], err)
		}
	}
	assertRelayMetricEquals(t, ready[3], carriersConnectedMetric, 0)

	cancel()
	waitProcessExit(t, "relayd", relayDone, 10*time.Second)
}

// startRelayd runs relayd and waits for its ready line; the returned match holds
// the public, carrier and admin addresses at indexes 1, 2 and 3.
func startRelayd(t *testing.T, ctx context.Context, log *processLog, relaydBin string, args []string) (<-chan error, []string) {
	t.Helper()
	done := startProcess(t, ctx, log, relaydBin, args...)
	return done, log.waitFor(t, relaydReadyLine, 10*time.Second)
}

// assertDirectByteThroughRelay fetches the first byte of the conformance
// media-alpha direct stream through the relay and requires it byte-exact.
func assertDirectByteThroughRelay(t *testing.T, ctx context.Context, client *http.Client, publicHost, payloadSentinel string) {
	t.Helper()
	info := playbackInfo(t, client, "https://"+publicHost)
	directURL := directStreamURL(t, info)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+publicHost+directURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=0-0")
	req.Header.Set("X-Relay-Payload-Sentinel", payloadSentinel)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("direct byte request through relay: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("direct byte status = %d, want 206: %s", resp.StatusCode, body)
	}
	if got, want := resp.Header.Get("Content-Range"), "bytes 0-0/1"; got != want {
		t.Fatalf("Content-Range = %q, want %q", got, want)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/octet-stream") {
		t.Fatalf("Content-Type = %q, want application/octet-stream", got)
	}
	if !bytes.Equal(body, []byte{0x00}) {
		t.Fatalf("body = %x, want byte-exact conformance media-alpha payload 00", body)
	}
}

func assertRelayLogClean(t *testing.T, log *processLog, needles []string) {
	t.Helper()
	relayLogs := log.String()
	for _, needle := range needles {
		if strings.Contains(relayLogs, needle) {
			t.Fatalf("relay logs leaked payload/token sentinel %q:\n%s", needle, relayLogs)
		}
	}
}

func assertRelayMetricEquals(t *testing.T, adminAddr, name string, want int64) {
	t.Helper()
	if got := relayMetric(t, adminAddr, name); got != want {
		t.Fatalf("%s = %d, want %d", name, got, want)
	}
}

func assertRelayMetricEventuallyEquals(t *testing.T, adminAddr, name string, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := relayMetric(t, adminAddr, name)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s = %d, want %d", name, got, want)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func assertRelayMetricPositive(t *testing.T, adminAddr, name string) {
	t.Helper()
	if got := relayMetric(t, adminAddr, name); got <= 0 {
		t.Fatalf("%s = %d, want > 0", name, got)
	}
}

func relayMetric(t *testing.T, adminAddr, name string) int64 {
	t.Helper()
	resp, err := http.Get("http://" + adminAddr + "/metrics")
	if err != nil {
		t.Fatalf("get relay metrics: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test response cleanup.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relay metrics status = %d: %s", resp.StatusCode, data)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == name {
			value, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				t.Fatalf("parse %s value %q: %v", name, fields[1], err)
			}
			return value
		}
	}
	t.Fatalf("relay metric %s missing:\n%s", name, data)
	return 0
}

func requireExecutableEnv(t *testing.T, name string) string {
	t.Helper()
	path := os.Getenv(name)
	if path == "" {
		t.Fatalf("%s is required", name)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s=%q: %v", name, path, err)
	}
	if info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s=%q is not executable", name, path)
	}
	return path
}

type playbackResponse struct {
	Streams []struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
		URL  string `json:"url"`
	} `json:"streams"`
}

func playbackInfo(t *testing.T, client *http.Client, base string) playbackResponse {
	t.Helper()
	body := `{"mediaID":"media-alpha","capabilityProfile":{"client":"conformance","containers":["mp4"],"directCodecs":["h264"]}}`
	req, err := http.NewRequest(http.MethodPost, base+"/api/playback-info", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	authorizeRelayE2EDevice(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("playback-info through relay: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test response cleanup.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("playback-info status = %d, want 200: %s", resp.StatusCode, data)
	}
	var out playbackResponse
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode playback-info: %v\n%s", err, data)
	}
	return out
}

func authorizeRelayE2EDevice(req *http.Request) {
	req.Header.Set("X-Beamfall-Session", "session-revealed")
	req.Header.Set("X-Beamfall-Device", "device-tv")
	req.Header.Set("X-Beamfall-Device-Secret", "dev-tv-secret")
}

func directStreamURL(t *testing.T, info playbackResponse) string {
	t.Helper()
	for _, stream := range info.Streams {
		if stream.ID == "direct-main" || stream.Kind == "direct-play" {
			if stream.URL == "" {
				t.Fatal("direct stream URL is empty")
			}
			return stream.URL
		}
	}
	t.Fatalf("direct stream absent from playback-info: %#v", info.Streams)
	return ""
}

func relayHTTPClient(publicAddr, publicHost string, roots *x509.CertPool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, publicAddr)
			},
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				ServerName: publicHost,
				RootCAs:    roots,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

type processLog struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	lines chan string
}

func newProcessLog() *processLog {
	return &processLog{lines: make(chan string, 256)}
}

func (l *processLog) append(line string) {
	l.mu.Lock()
	l.buf.WriteString(line)
	l.buf.WriteByte('\n')
	l.mu.Unlock()
	select {
	case l.lines <- line:
	default:
	}
}

func (l *processLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *processLog) waitFor(t *testing.T, re *regexp.Regexp, timeout time.Duration) []string {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case line := <-l.lines:
			if match := re.FindStringSubmatch(line); match != nil {
				return match
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for %s\nlogs:\n%s", re, l.String())
		}
	}
}

func startProcess(t *testing.T, ctx context.Context, log *processLog, name string, args ...string) <-chan error {
	t.Helper()
	return startProcessEnv(t, ctx, log, nil, name, args...)
}

func startProcessEnv(t *testing.T, ctx context.Context, log *processLog, extraEnv []string, name string, args ...string) <-chan error {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = mergedEnv(os.Environ(), extraEnv)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	scan := func(r io.Reader) {
		s := bufio.NewScanner(r)
		s.Buffer(make([]byte, 0, 4096), 1024*1024)
		for s.Scan() {
			log.append(s.Text())
		}
		if err := s.Err(); err != nil {
			log.append("log scan error: " + err.Error())
		}
	}
	go scan(stdout)
	go scan(stderr)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
		}
	})
	return done
}

func mergedEnv(base, overlay []string) []string {
	out := append([]string{}, base...)
	index := map[string]int{}
	for i, entry := range out {
		if key, _, ok := strings.Cut(entry, "="); ok {
			index[key] = i
		}
	}
	for _, entry := range overlay {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			out = append(out, entry)
			continue
		}
		if i, exists := index[key]; exists {
			out[i] = entry
		} else {
			index[key] = len(out)
			out = append(out, entry)
		}
	}
	return out
}

func waitProcessExit(t *testing.T, name string, done <-chan error, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil && !strings.Contains(err.Error(), "signal: killed") && !strings.Contains(err.Error(), "signal: interrupt") {
			t.Fatalf("%s exited with error: %v", name, err)
		}
	case <-timer.C:
		t.Fatalf("%s did not exit within %s", name, timeout)
	}
}

func newCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "Beamfall relay-core E2E CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newLeaf(t *testing.T, caKey *ecdsa.PrivateKey, ca *x509.Certificate, dns []string, ips []net.IP) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: firstName(dns, ips)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func firstName(dns []string, ips []net.IP) string {
	if len(dns) > 0 {
		return dns[0]
	}
	if len(ips) > 0 {
		return ips[0].String()
	}
	return "localhost"
}

func writeFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	writeFileAt(t, path, data, mode)
	return path
}

func writeFileAt(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
