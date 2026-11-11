package cache

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testCacheNow() time.Time {
	return time.Now().UTC().Add(time.Hour).Truncate(time.Second)
}

func TestServerServesSegmentsAndAggregateOnlyMetrics(t *testing.T) {
	now := testCacheNow()
	store, err := NewStore(t.TempDir(), testKey, 1024)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Put("segset_abc", "0001.m4s", Entry{Bytes: []byte("ciphertext"), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("put: %v", err)
	}
	cert := testCertificate(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var logs bytes.Buffer
	server, err := Start(ctx, Config{
		Addr:      "127.0.0.1:0",
		AdminAddr: "127.0.0.1:0",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		},
		TokenVerifier: HMACTokenVerifier{
			Key: testKey,
			Now: func() time.Time {
				return now
			},
		},
		Store:  store,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer server.Close() //nolint:errcheck // test cleanup.

	token, err := MintToken(testKey, "segset_abc", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local test certificate.
	req, err := http.NewRequest(http.MethodGet, "https://"+server.Addr()+"/cache/v1/segments/0001.m4s", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get segment: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	metricsResp, err := http.Get("http://" + server.AdminAddr() + "/metrics")
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	defer metricsResp.Body.Close() //nolint:errcheck // test cleanup.
	body, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	metrics := string(body)
	if !strings.Contains(metrics, "beamfall_cache_hits_total 1") {
		t.Fatalf("metrics missing hit count:\n%s", metrics)
	}
	if strings.Contains(metrics, "segset_abc") {
		t.Fatalf("metrics leaked segmentSetId:\n%s", metrics)
	}
	for _, forbidden := range []string{"segset_abc", token} {
		if strings.Contains(logs.String(), forbidden) {
			t.Fatalf("cache-serve log leaked cache privacy value %q:\n%s", forbidden, logs.String())
		}
	}
}

func TestCachePrivacyLogWritersOmitJoinKeys(t *testing.T) {
	forbidden := []string{
		"segmentSetID",
		"SegmentSetID",
		"segmentSetId",
		"SegmentSetId",
		"segment_set_id",
		"cacheVerificationKey",
		"CacheVerificationKey",
		"cache_verification_key",
	}
	fset := token.NewFileSet()
	logCalls := 0
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".cache" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isLogWriter(call) {
				return true
			}
			logCalls++
			var src bytes.Buffer
			if err := printer.Fprint(&src, fset, call); err != nil {
				t.Fatalf("print log call %s: %v", fset.Position(call.Pos()), err)
			}
			for _, s := range forbidden {
				if strings.Contains(src.String(), s) {
					t.Fatalf("ADR-0103 §5 log writer includes cache join key %q at %s:\n%s", s, fset.Position(call.Pos()), src.String())
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("sweep log writers: %v", err)
	}
	if logCalls == 0 {
		t.Fatal("log writer sweep found no log calls")
	}
}

func isLogWriter(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Debug", "Info", "Warn", "Error", "Fatal", "Fatalf", "Fatalln", "Print", "Printf", "Println":
	default:
		return false
	}
	return isLogReceiver(sel.X)
}

func isLogReceiver(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.Ident:
		name := strings.ToLower(x.Name)
		return name == "log" || name == "slog" || strings.Contains(name, "logger")
	case *ast.SelectorExpr:
		return strings.Contains(strings.ToLower(x.Sel.Name), "logger") || isLogReceiver(x.X)
	default:
		return false
	}
}

func TestServerMissReturns404AndCoalescesPrewarmSignal(t *testing.T) {
	now := testCacheNow()
	store, err := NewStore(t.TempDir(), testKey, 1024)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	token, err := MintToken(testKey, "segset_abc", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	started := make(chan Miss, 1)
	release := make(chan struct{})
	var calls atomic.Int64
	server := startCacheServer(t, store, now, func(ctx context.Context, miss Miss) {
		calls.Add(1)
		started <- miss
		<-release
	})
	defer close(release)

	const viewers = 8
	statuses := make(chan int, viewers)
	for range viewers {
		go func() {
			statuses <- getCacheSegment(t, server, token, "0001.m4s")
		}()
	}
	miss := <-started
	if miss.SegmentSetID != "segset_abc" || miss.Segment != "0001.m4s" {
		t.Fatalf("miss = %#v", miss)
	}
	for range viewers {
		if status := <-statuses; status != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", status)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("prewarm calls = %d, want 1", got)
	}
}

// ADR-0103 §5: miss/prewarm state is transient relay memory. A restarted cache
// server must not suppress a same-segment-set miss because of prior process state.
func TestServerMissCoalescingDoesNotSurviveRestart(t *testing.T) {
	now := testCacheNow()
	store, err := NewStore(t.TempDir(), testKey, 1024)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	token, err := MintToken(testKey, "segset_abc", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	first := make(chan Miss, 1)
	server := startCacheServer(t, store, now, func(ctx context.Context, miss Miss) {
		first <- miss
	})
	if status := getCacheSegment(t, server, token, "0001.m4s"); status != http.StatusNotFound {
		t.Fatalf("first status = %d, want 404", status)
	}
	<-first
	if err := server.Close(); err != nil {
		t.Fatalf("close first server: %v", err)
	}

	second := make(chan Miss, 1)
	server = startCacheServer(t, store, now, func(ctx context.Context, miss Miss) {
		second <- miss
	})
	if status := getCacheSegment(t, server, token, "0001.m4s"); status != http.StatusNotFound {
		t.Fatalf("second status = %d, want 404", status)
	}
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("new server did not emit prewarm signal; miss state may have survived restart")
	}
}

func TestServerPullThroughCoalescesWaiters(t *testing.T) {
	now := testCacheNow()
	store, err := NewStore(t.TempDir(), testKey, 1024)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	token, err := MintToken(testKey, "segset_abc", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	var startedOnce sync.Once
	server := startCacheServerWithPull(t, store, now, Config{
		PullWaitTimeout: time.Second,
		PullThrough: func(ctx context.Context, req PullRequest) (Entry, bool, error) {
			calls.Add(1)
			startedOnce.Do(func() { close(started) })
			select {
			case <-release:
			case <-ctx.Done():
				return Entry{}, false, ctx.Err()
			}
			return Entry{Bytes: []byte("ciphertext"), ContentType: "video/mp4", ExpiresAt: now.Add(time.Hour)}, true, nil
		},
	})

	const viewers = 8
	ready := make(chan struct{}, viewers)
	start := make(chan struct{})
	responses := make(chan cacheResponse, viewers)
	for range viewers {
		go func() {
			ready <- struct{}{}
			<-start
			responses <- getCacheSegmentResponse(t, server, token, "0001.m4s")
		}()
	}
	for range viewers {
		<-ready
	}
	close(start)
	<-started
	time.Sleep(25 * time.Millisecond)
	close(release)
	for range viewers {
		resp := <-responses
		if resp.status != http.StatusOK || string(resp.body) != "ciphertext" {
			t.Fatalf("response = %#v, want one pulled segment", resp)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("pull-through calls = %d, want 1", got)
	}
}

func TestServerPullThroughTimeoutFallsBackToHomeDirectMiss(t *testing.T) {
	now := testCacheNow()
	store, err := NewStore(t.TempDir(), testKey, 1024)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	token, err := MintToken(testKey, "segset_abc", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	server := startCacheServerWithPull(t, store, now, Config{
		PullWaitTimeout: 25 * time.Millisecond,
		PullThrough: func(ctx context.Context, req PullRequest) (Entry, bool, error) {
			<-ctx.Done()
			return Entry{}, false, ctx.Err()
		},
	})

	start := time.Now()
	if status := getCacheSegment(t, server, token, "0001.m4s"); status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 home-direct fallback signal", status)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("dead-home fallback took %s", elapsed)
	}
}

func TestServerPullThroughPrefetchHonorsHeadroom(t *testing.T) {
	now := testCacheNow()
	store, err := NewStore(t.TempDir(), testKey, 4096)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	token, err := MintToken(testKey, "segset_abc", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	var mu sync.Mutex
	var pulled []string
	var carriers []string
	server := startCacheServerWithPull(t, store, now, Config{
		TokenVerifier: carrierBoundVerifier{
			carrierID: "carrier-1",
			verifier: HMACTokenVerifier{
				Key: testKey,
				Now: func() time.Time {
					return now
				},
			},
		},
		PullWaitTimeout: time.Second,
		PullThrough: func(ctx context.Context, req PullRequest) (Entry, bool, error) {
			mu.Lock()
			pulled = append(pulled, req.Segment)
			carriers = append(carriers, req.CarrierID)
			mu.Unlock()
			return Entry{Bytes: []byte(req.Segment), ContentType: "video/mp4", ExpiresAt: now.Add(time.Hour)}, true, nil
		},
		PrefetchHeadroom: func(ctx context.Context, miss Miss) int {
			return 2
		},
	})

	resp := getCacheSegmentResponse(t, server, token, "0001.m4s")
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.status)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := append([]string(nil), pulled...)
		mu.Unlock()
		if len(got) == 3 {
			if strings.Join(got, ",") != "0001.m4s,0002.m4s,0003.m4s" {
				t.Fatalf("pulled = %#v", got)
			}
			gotCarriers := append([]string(nil), carriers...)
			if strings.Join(gotCarriers, ",") != "carrier-1,carrier-1,carrier-1" {
				t.Fatalf("carriers = %#v", gotCarriers)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("pulled = %#v, want current plus two headroom-prefetch segments", pulled)
}

func TestServerCloseWaitsForPrefetchAndStoreCloseReleasesRoot(t *testing.T) {
	now := testCacheNow()
	root := filepath.Join(t.TempDir(), "cache")
	store, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	blocked := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseStore := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseStore()
	var transactionStarts atomic.Int32
	store.failStep = func(step string) error {
		if step == "before-sync-create-transaction" && transactionStarts.Add(1) == 3 {
			close(blocked)
			<-release
		}
		return nil
	}
	token, err := MintToken(testKey, "segset_abc", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	server := startCacheServerWithPull(t, store, now, Config{
		PullWaitTimeout: time.Second,
		PullThrough: func(_ context.Context, req PullRequest) (Entry, bool, error) {
			return Entry{
				Bytes: []byte(req.Segment), ContentType: "video/mp4", ExpiresAt: now.Add(time.Hour),
			}, true, nil
		},
		PrefetchHeadroom: func(context.Context, Miss) int { return 2 },
	})

	if status := getCacheSegment(t, server, token, "0001.m4s"); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("third prefetch store did not reach transaction barrier")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		server.lifecycleMu.Lock()
		closing := server.closing
		server.lifecycleMu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Server.Close did not enter lifecycle fence")
		}
		runtime.Gosched()
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Server.Close returned before prefetch store completed: %v", err)
	default:
	}

	releaseStore()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Server.Close did not join prefetch store")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	if _, err := store.rootDir.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("pinned root descriptor remains open: %v", err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("remove closed cache root: %v", err)
	}
	if err := store.Put("segset_abc", "late.m4s", Entry{
		Bytes: []byte("late"), ExpiresAt: now.Add(time.Hour),
	}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("late put error = %v, want closed store", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache root reappeared after close: %v", err)
	}
}

func TestServerCloseWaitsForTimedOutPullFlightStore(t *testing.T) {
	now := testCacheNow()
	root := filepath.Join(t.TempDir(), "cache")
	store, err := NewStore(root, testKey, 4096)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	pullStarted := make(chan struct{})
	releasePull := make(chan struct{})
	putStarted := make(chan struct{})
	releasePut := make(chan struct{})
	var pullOnce, putOnce, releasePullOnce, releasePutOnce sync.Once
	releaseBlockedPull := func() { releasePullOnce.Do(func() { close(releasePull) }) }
	releaseBlockedPut := func() { releasePutOnce.Do(func() { close(releasePut) }) }
	defer releaseBlockedPull()
	defer releaseBlockedPut()
	store.failStep = func(step string) error {
		if step == "before-sync-create-transaction" {
			putOnce.Do(func() { close(putStarted) })
			<-releasePut
		}
		return nil
	}
	server := &Server{
		store:       store,
		pullTimeout: 20 * time.Millisecond,
		headroom:    func(context.Context, Miss) int { return 1 },
		pullThrough: func(context.Context, PullRequest) (Entry, bool, error) {
			pullOnce.Do(func() { close(pullStarted) })
			<-releasePull
			return Entry{
				Bytes: []byte("late"), ContentType: "late/type", ExpiresAt: now.Add(time.Hour),
			}, true, nil
		},
	}
	server.pulls.waiterCanceled = make(chan struct{}, 1)
	server.startPrefetch(context.Background(), Miss{SegmentSetID: "segset", Segment: "0001.m4s"})
	select {
	case <-pullStarted:
	case <-time.After(time.Second):
		t.Fatal("prefetch pull did not start")
	}
	select {
	case <-server.pulls.waiterCanceled:
	case <-time.After(time.Second):
		t.Fatal("prefetch waiter did not time out")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	deadline := time.Now().Add(time.Second)
	for {
		server.lifecycleMu.Lock()
		closing := server.closing
		server.lifecycleMu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Server.Close did not enter lifecycle fence")
		}
		runtime.Gosched()
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Server.Close returned with timed-out pull flight active: %v", err)
	default:
	}

	releaseBlockedPull()
	select {
	case <-putStarted:
	case <-time.After(time.Second):
		t.Fatal("timed-out pull flight did not reach Store.Put")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Server.Close returned with pull-flight Store.Put active: %v", err)
	default:
	}

	releaseBlockedPut()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Server.Close did not join timed-out pull flight")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("remove closed cache root: %v", err)
	}
	if err := store.Put("segset", "late.m4s", Entry{
		Bytes: []byte("late"), ExpiresAt: now.Add(time.Hour),
	}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("late put error = %v, want closed store", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache root reappeared after flight shutdown: %v", err)
	}
}

func startCacheServer(t *testing.T, store *Store, now time.Time, signal PrewarmSignal) *Server {
	t.Helper()
	return startCacheServerWithPull(t, store, now, Config{PrewarmSignal: signal})
}

func startCacheServerWithPull(t *testing.T, store *Store, now time.Time, cfg Config) *Server {
	t.Helper()
	cfg.Addr = "127.0.0.1:0"
	cfg.AdminAddr = ""
	cfg.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{testCertificate(t)},
		MinVersion:   tls.VersionTLS13,
	}
	if cfg.TokenVerifier == nil {
		cfg.TokenVerifier = HMACTokenVerifier{
			Key: testKey,
			Now: func() time.Time {
				return now
			},
		}
	}
	cfg.Store = store
	server, err := Start(context.Background(), Config{
		Addr:             cfg.Addr,
		AdminAddr:        cfg.AdminAddr,
		TLSConfig:        cfg.TLSConfig,
		TokenVerifier:    cfg.TokenVerifier,
		Store:            cfg.Store,
		PrewarmSignal:    cfg.PrewarmSignal,
		PullThrough:      cfg.PullThrough,
		PullWaitTimeout:  cfg.PullWaitTimeout,
		PrefetchHeadroom: cfg.PrefetchHeadroom,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})
	return server
}

type carrierBoundVerifier struct {
	carrierID string
	verifier  TokenVerifier
}

func (v carrierBoundVerifier) VerifyCacheAccessToken(ctx context.Context, token string) (VerifiedAccess, error) {
	access, err := v.verifier.VerifyCacheAccessToken(ctx, token)
	if err != nil {
		return VerifiedAccess{}, err
	}
	access.CarrierID = v.carrierID
	return access, nil
}

func getCacheSegment(t *testing.T, server *Server, token, segment string) int {
	t.Helper()
	return getCacheSegmentResponse(t, server, token, segment).status
}

type cacheResponse struct {
	status int
	body   []byte
}

func getCacheSegmentResponse(t *testing.T, server *Server, token, segment string) cacheResponse {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local test certificate.
	req, err := http.NewRequest(http.MethodGet, "https://"+server.Addr()+"/cache/v1/segments/"+segment, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get segment: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read segment: %v", err)
	}
	return cacheResponse{status: resp.StatusCode, body: body}
}
