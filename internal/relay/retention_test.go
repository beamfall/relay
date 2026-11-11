package relay

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ADR-0103 Decision 2: the retention window must be bounded — a non-positive
// (unbounded / "never delete") or over-ceiling window is rejected.
func TestValidateRetentionWindow(t *testing.T) {
	cases := []struct {
		name string
		d    time.Duration
		ok   bool
	}{
		{"zero is unbounded", 0, false},
		{"negative is unbounded", -time.Hour, false},
		{"one hour ok", time.Hour, true},
		{"at ceiling ok", MaxOperationalLogRetention, true},
		{"over ceiling rejected", MaxOperationalLogRetention + time.Second, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateRetentionWindow(c.d)
			if c.ok && err != nil {
				t.Fatalf("ValidateRetentionWindow(%s) = %v, want nil", c.d, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("ValidateRetentionWindow(%s) = nil, want error", c.d)
			}
		})
	}
}

// The published build-time window must itself satisfy the policy bound — guards
// against a future edit setting OperationalLogRetentionWindow out of policy.
func TestBuildTimeRetentionWindowIsBounded(t *testing.T) {
	if err := ValidateRetentionWindow(OperationalLogRetentionWindow); err != nil {
		t.Fatalf("build-time OperationalLogRetentionWindow invalid: %v", err)
	}
}

// /metrics publishes the bounded retention window (ADR-0103 "must be published"),
// in seconds, matching the build-time constant.
func TestMetricsPublishesRetentionWindow(t *testing.T) {
	m := &metrics{}
	rec := httptest.NewRecorder()
	m.metricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	want := int64(OperationalLogRetentionWindow / time.Second)
	found := false
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "beamfall_relay_log_retention_seconds ") {
			found = true
			got := strings.TrimSpace(strings.TrimPrefix(line, "beamfall_relay_log_retention_seconds"))
			if got != strconv.FormatInt(want, 10) {
				t.Fatalf("retention gauge = %s, want %d", got, want)
			}
		}
	}
	if !found {
		t.Fatalf("beamfall_relay_log_retention_seconds not published in:\n%s", body)
	}
}

// ADR-0103's metrics rule (label-free aggregates) is superseded for the SLI set
// by ADR-0146 §8/§9, which adds bounded low-cardinality labels: the tunnel-dial
// counter's `outcome` (a fixed error class) and the setup-latency histogram's
// `le` bucket boundary. Every OTHER series must stay label-free, and no label
// may ever be a high-cardinality dimension (hostname, id, token, IP). This test
// asserts the only labels present are the allowlisted bounded ones. Asserted
// both with fairUse nil AND populated, so the `if m.fairUse != nil` block is
// covered.
func TestMetricsLabelsAreBoundedOnly(t *testing.T) {
	// The bounded, allowlisted label keys (ADR-0146 §9). Any other label key is a
	// violation.
	allowedLabelKeys := map[string]bool{"outcome": true, "le": true}

	assertBoundedLabels := func(t *testing.T, m *metrics) {
		t.Helper()
		rec := httptest.NewRecorder()
		m.metricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		body := rec.Body.String()
		for _, line := range strings.Split(body, "\n") {
			open := strings.IndexByte(line, '{')
			if strings.HasPrefix(line, "#") || open < 0 {
				continue
			}
			labels := line[open+1 : strings.IndexByte(line, '}')]
			for _, pair := range strings.Split(labels, ",") {
				key := strings.TrimSpace(strings.SplitN(pair, "=", 2)[0])
				if key != "" && !allowedLabelKeys[key] {
					t.Fatalf("ADR-0146 §9 violation: unexpected label key %q in line %q", key, line)
				}
			}
		}
	}

	t.Run("fairUse nil", func(t *testing.T) {
		assertBoundedLabels(t, &metrics{})
	})
	t.Run("fairUse populated", func(t *testing.T) {
		fu := newFairUseLimiter(FairUseConfig{Enabled: true}, nil)
		if fu == nil {
			t.Fatal("newFairUseLimiter returned nil for an enabled config")
		}
		assertBoundedLabels(t, &metrics{fairUse: fu})
	})
}
