package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/beamfall/relay/internal/protocol"
)

// rwPair is a minimal protocol.FrameReadWriter: reads drain a preloaded buffer
// (the carrier's hello), writes accumulate (any relay error frame). It lets the
// unexported carrierHandshake be exercised without a live listener.
type rwPair struct {
	r *bytes.Buffer
	w *bytes.Buffer
}

func (p *rwPair) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *rwPair) Write(b []byte) (int, error) { return p.w.Write(b) }

// tokenMap is an in-package TokenVerifier for handshake tests (the external
// relay_test package's mapTokenVerifier is not reachable from package relay).
type tokenMap map[string]VerifiedCarrier

func (m tokenMap) VerifyTunnelToken(_ context.Context, token []byte, _ []string) (VerifiedCarrier, error) {
	if v, ok := m[string(token)]; ok {
		return v, nil
	}
	return VerifiedCarrier{}, ErrUnauthorized
}

type canaryErrorVerifier struct {
	base  error
	claim string
}

func (v canaryErrorVerifier) VerifyTunnelToken(_ context.Context, token []byte, requested []string) (VerifiedCarrier, error) {
	return VerifiedCarrier{}, fmt.Errorf("%w: requested_hostname=%q token=%q claim_code=%q", v.base, requested[0], token, v.claim)
}

// newHandshakeServer builds the minimal Server carrierHandshake needs, wired to
// an in-memory span recorder so span attributes can be asserted.
func newHandshakeServer(t *testing.T, verifier TokenVerifier) (*Server, *tracetest.SpanRecorder) {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	s := &Server{
		verifier:          verifier,
		handshakeThrottle: newHandshakeThrottle(),
		logger:            slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)),
		redactConnLogs:    true,
		tracer:            tp.Tracer("test"),
	}
	s.metrics.initSLIs()
	return s, rec
}

func helloFrame(t *testing.T, token []byte, hosts []string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	if err := protocol.WriteFrame(&buf, protocol.Frame{Type: protocol.FrameHello, Hello: &protocol.Hello{
		Version:   protocol.Version,
		Token:     token,
		Hostnames: hosts,
	}}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	return &buf
}

func TestCarrierAuthorizationFailureLogsUseBoundedCodes(t *testing.T) {
	const (
		tokenCanary = "TOKEN-CANARY-%54%4f%4b%45%4e"
		claimCanary = "CLAIM-CODE-CANARY-雪-8847"
	)
	cases := []struct {
		name string
		host string
		err  error
		code string
	}{
		{
			name: "hostile",
			host: `hostile.relay.test/../../?<script>=HOST-CANARY`,
			err:  ErrUnauthorized,
			code: "unauthorized",
		},
		{
			name: "unicode",
			host: "unicode-雪-💥-HOST-CANARY.relay.test",
			err:  context.Canceled,
			code: "context_canceled",
		},
		{
			name: "percent-encoded",
			host: "encoded%2Ehost%252EHOST-CANARY.relay.test",
			err:  context.DeadlineExceeded,
			code: "deadline_exceeded",
		},
		{
			name: "punycode",
			host: "xn--host-canary-2za.relay.test",
			err:  errors.New("provider failure"),
			code: "verifier_error",
		},
	}
	for _, redact := range []bool{true, false} {
		mode := "metadata"
		if redact {
			mode = "redacted"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					var logs bytes.Buffer
					s, _ := newHandshakeServer(t, canaryErrorVerifier{base: tc.err, claim: claimCanary})
					s.redactConnLogs = redact
					s.logger = slog.New(slog.NewTextHandler(&logs, nil))

					rw := &rwPair{
						r: helloFrame(t, []byte(tokenCanary), []string{tc.host}),
						w: &bytes.Buffer{},
					}
					if _, ok := s.carrierHandshake(context.Background(), rw, nil); ok {
						t.Fatal("handshake should reject the canary verifier error")
					}

					got := logs.String()
					for _, forbidden := range []string{tc.host, tokenCanary, claimCanary, tc.err.Error()} {
						if strings.Contains(got, forbidden) {
							t.Fatalf("authorization log leaked canary %q:\n%s", forbidden, got)
						}
					}
					for _, want := range []string{"carrier unauthorized", "code=" + tc.code} {
						if !strings.Contains(got, want) {
							t.Fatalf("authorization log missing stable signal %q:\n%s", want, got)
						}
					}
					if strings.Contains(got, "err=") {
						t.Fatalf("authorization log retained raw verifier error field:\n%s", got)
					}
				})
			}
		})
	}
}

// TestCarrierHandshakeSpanIsMetadataOnly proves the mint→relay span carries only
// the bounded outcome attribute and never leaks the Stream/tunnel token,
// hostnames, carrier id, or any payload (ADR-0146 §7/§9 denylist, Invariant #7).
func TestCarrierHandshakeSpanIsMetadataOnly(t *testing.T) {
	secret := []byte("super-secret-tunnel-token-value")
	const correlationID = "0123456789abcdef0123456789abcdef"
	verifier := tokenMap{string(secret): VerifiedCarrier{ID: "carrier-abc-123", Hostnames: []string{testSpanHost}, TraceCorrelationID: correlationID}}
	s, rec := newHandshakeServer(t, verifier)

	rw := &rwPair{r: helloFrame(t, secret, []string{testSpanHost}), w: &bytes.Buffer{}}
	if _, ok := s.carrierHandshake(context.Background(), rw, nil); !ok {
		t.Fatal("handshake with valid token should succeed")
	}

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	span := spans[0]
	if span.Name() != "relay.carrier_handshake" {
		t.Errorf("span name = %q, want relay.carrier_handshake", span.Name())
	}

	// The only attributes permitted on this span are bounded metadata-only join
	// keys: outcome and the cloud-minted trace correlation ID.
	var outcome, gotCorrelationID string
	for _, a := range span.Attributes() {
		if string(a.Key) == "relay.handshake.outcome" {
			outcome = a.Value.AsString()
			continue
		}
		if string(a.Key) == "relay.mint.correlation_id" {
			gotCorrelationID = a.Value.AsString()
			continue
		}
		t.Errorf("unexpected span attribute %q = %q (ADR-0146 §9 metadata-only)", a.Key, a.Value.String())
	}
	if outcome != dialOutcomeSuccess {
		t.Errorf("outcome attribute = %q, want %q", outcome, dialOutcomeSuccess)
	}
	if gotCorrelationID != correlationID {
		t.Errorf("correlation id attribute = %q, want %q", gotCorrelationID, correlationID)
	}

	// No span attribute, event, or name may contain the token, carrier id, or host.
	forbidden := []string{string(secret), "carrier-abc-123", testSpanHost}
	haystack := span.Name()
	for _, a := range span.Attributes() {
		haystack += " " + string(a.Key) + "=" + a.Value.String()
	}
	for _, ev := range span.Events() {
		haystack += " " + ev.Name
		for _, a := range ev.Attributes {
			haystack += " " + string(a.Key) + "=" + a.Value.String()
		}
	}
	for _, secretStr := range forbidden {
		if strings.Contains(haystack, secretStr) {
			t.Errorf("span leaked forbidden value %q; span content: %s", secretStr, haystack)
		}
	}
}

// TestCarrierHandshakeSpanOutcomeForFailures covers the error-class outcomes so
// the denylist test above is not the only path exercised.
func TestCarrierHandshakeSpanOutcomeForFailures(t *testing.T) {
	verifier := tokenMap{"right": VerifiedCarrier{ID: "c", Hostnames: []string{testSpanHost}}}

	cases := []struct {
		name string
		read *bytes.Buffer
		want string
	}{
		{"unauthorized", helloFrame(t, []byte("wrong"), []string{testSpanHost}), dialOutcomeUnauthorized},
		{"error", bytes.NewBuffer(nil), dialOutcomeError}, // empty read -> ReadFrame fails
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, rec := newHandshakeServer(t, verifier)
			rw := &rwPair{r: tc.read, w: &bytes.Buffer{}}
			if _, ok := s.carrierHandshake(context.Background(), rw, nil); ok {
				t.Fatal("handshake should have failed")
			}
			spans := rec.Ended()
			if len(spans) != 1 {
				t.Fatalf("got %d spans, want 1", len(spans))
			}
			var outcome string
			for _, a := range spans[0].Attributes() {
				if string(a.Key) == "relay.handshake.outcome" {
					outcome = a.Value.AsString()
				}
			}
			if outcome != tc.want {
				t.Errorf("outcome = %q, want %q", outcome, tc.want)
			}
		})
	}
}

// TestTunnelDialSLIsExposed proves the SLI instruments increment and surface in
// the /metrics exposition after handshakes (ADR-0146 §8).
func TestTunnelDialSLIsExposed(t *testing.T) {
	secret := []byte("valid-token-abc")
	verifier := tokenMap{string(secret): VerifiedCarrier{ID: "c", Hostnames: []string{testSpanHost}}}
	s, _ := newHandshakeServer(t, verifier)

	good := &rwPair{r: helloFrame(t, secret, []string{testSpanHost}), w: &bytes.Buffer{}}
	if _, ok := s.carrierHandshake(context.Background(), good, nil); !ok {
		t.Fatal("valid handshake should succeed")
	}
	bad := &rwPair{r: helloFrame(t, []byte("nope"), []string{testSpanHost}), w: &bytes.Buffer{}}
	if _, ok := s.carrierHandshake(context.Background(), bad, nil); ok {
		t.Fatal("invalid handshake should fail")
	}

	rr := httptest.NewRecorder()
	s.metrics.metricsHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rr.Body.String()
	for _, want := range []string{
		`beamfall_relay_tunnel_dials_total{outcome="success"} 1`,
		`beamfall_relay_tunnel_dials_total{outcome="unauthorized"} 1`,
		"beamfall_relay_tunnel_setup_seconds_count 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\nbody:\n%s", want, body)
		}
	}
}

// TestRequireBearerTokenGate proves the non-loopback /metrics credential gate:
// no token or wrong token yields 401, the correct bearer yields 200.
func TestRequireBearerTokenGate(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("metrics-body"))
	})
	h := requireBearerToken("s3cret", next)

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"malformed scheme", "s3cret", http.StatusUnauthorized},
		{"correct token", "Bearer s3cret", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d", rr.Code, tc.want)
			}
			if tc.want == http.StatusUnauthorized && strings.Contains(rr.Body.String(), "metrics-body") {
				t.Error("unauthorized response leaked the protected body")
			}
		})
	}
}

const testSpanHost = "home.relay.test"
