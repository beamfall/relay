package relay

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// TestRejectSamplingSuppressesRepeatedCallsWithinInterval exercises
// publicRejectSampler directly, mirroring how TestFairUseHardLimitAndSampledRefusalLogs
// (fairuse_test.go) proves tunnelUsage.shouldLogRefusal's sample-and-reset
// behaviour: repeated calls for the same reason inside the interval are
// suppressed, a different reason is tracked independently, and logging
// resumes once the interval elapses.
func TestRejectSamplingSuppressesRepeatedCallsWithinInterval(t *testing.T) {
	clock := &fakeClock{now: time.Unix(500*int64(time.Hour/time.Second), 0)}
	sampler := newPublicRejectSampler(time.Minute, clock.Now)

	if !sampler.shouldLog("no_carrier") {
		t.Fatal("first rejection for a reason should be logged")
	}
	if sampler.shouldLog("no_carrier") {
		t.Fatal("second rejection for the same reason inside the sample interval should not be logged")
	}
	if !sampler.shouldLog("peek_failed") {
		t.Fatal("a different reason should be logged independently of the already-sampled one")
	}

	clock.Advance(time.Minute)
	if !sampler.shouldLog("no_carrier") {
		t.Fatal("rejection after the sample interval elapsed should be logged again")
	}
}

// TestRejectSamplingNilSamplerFailsOpen documents that a Server built without
// going through Start (this package's white-box tests routinely construct a
// bare &Server{...} literal) still logs every rejection rather than panicking
// on a nil publicRejectLog.
func TestRejectSamplingNilSamplerFailsOpen(t *testing.T) {
	var sampler *publicRejectSampler
	if !sampler.shouldLog("no_carrier") {
		t.Fatal("a nil sampler must fail open (log), matching a Server built without Start")
	}
}

// TestRejectSamplingUnderFlood proves the sampler is actually wired into
// handlePublicConn's "public rejected" Warn calls, not just correct in
// isolation. It floods the peek-failure rejection path (the client end of a
// net.Pipe closed before the server side reads it, so sni.PeekClientHello
// fails immediately with io.EOF and no TLS/timeout machinery is needed) and
// asserts only the first Warn in the flood is logged, with logging resuming
// once the sample interval elapses.
func TestRejectSamplingUnderFlood(t *testing.T) {
	clock := &fakeClock{now: time.Unix(600*int64(time.Hour/time.Second), 0)}
	var logs bytes.Buffer
	s := &Server{
		logger:          slog.New(slog.NewTextHandler(&logs, nil)),
		redactConnLogs:  true,
		publicRejectLog: newPublicRejectSampler(time.Minute, clock.Now),
	}
	ctx := context.Background()

	const floodSize = 25
	for i := 0; i < floodSize; i++ {
		client, server := net.Pipe()
		client.Close() //nolint:errcheck // test peer close forces an immediate peek failure.
		s.handlePublicConn(ctx, server)
	}
	if got := strings.Count(logs.String(), "public rejected"); got != 1 {
		t.Fatalf("flood of %d rejections logged %d Warn lines, want 1 (sampled)", floodSize, got)
	}

	clock.Advance(time.Minute)
	client, server := net.Pipe()
	client.Close() //nolint:errcheck // test peer close forces an immediate peek failure.
	s.handlePublicConn(ctx, server)
	if got := strings.Count(logs.String(), "public rejected"); got != 2 {
		t.Fatalf("rejection after the sample interval elapsed logged %d total Warn lines, want 2", got)
	}
}
