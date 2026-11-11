package relay

import (
	"net"
	"testing"
)

// TestPerIPLimiterCapsPerSource asserts a single source is held to its cap and
// that releasing frees a slot for a later acquire.
func TestPerIPLimiterCapsPerSource(t *testing.T) {
	l := newPerIPLimiter(2)

	if !l.acquire("10.0.0.1") {
		t.Fatal("first acquire for one IP should succeed")
	}
	if !l.acquire("10.0.0.1") {
		t.Fatal("second acquire for one IP (within cap) should succeed")
	}
	if l.acquire("10.0.0.1") {
		t.Fatal("third acquire for same IP should be refused over the cap")
	}
	// A different source is unaffected by the first IP's saturation.
	if !l.acquire("10.0.0.2") {
		t.Fatal("acquire for a distinct IP should succeed")
	}
	// Releasing one slot for the saturated IP frees room for exactly one more.
	l.release("10.0.0.1")
	if !l.acquire("10.0.0.1") {
		t.Fatal("acquire after release should succeed")
	}
	if l.acquire("10.0.0.1") {
		t.Fatal("acquire past the cap again should be refused")
	}
}

// TestPerIPLimiterReleasesPruneMap asserts fully-released IPs leave no map
// entry, so a churn of distinct sources cannot grow the counter map unbounded.
func TestPerIPLimiterReleasesPruneMap(t *testing.T) {
	l := newPerIPLimiter(4)
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if !l.acquire(ip) {
			t.Fatalf("acquire %s should succeed", ip)
		}
		l.release(ip)
	}
	l.mu.Lock()
	n := len(l.counts)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("counts map retained %d entries after full release, want 0", n)
	}
}

// TestPrefixIPv4Uses32AndStripsPort asserts IPv4 keys group every ephemeral
// port from one address into the required /32.
func TestPrefixIPv4Uses32AndStripsPort(t *testing.T) {
	a := &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 40001}
	b := &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 40002}
	if sourcePrefix(a) != sourcePrefix(b) {
		t.Fatalf("sourcePrefix should ignore port: %q vs %q", sourcePrefix(a), sourcePrefix(b))
	}
	if sourcePrefix(a) != "203.0.113.5/32" {
		t.Fatalf("sourcePrefix = %q, want 203.0.113.5/32", sourcePrefix(a))
	}
}

// TestIPv6PrefixSharesPerIPBudget proves addresses in one /64 cannot rotate
// interface identifiers to obtain independent per-IP connection budgets.
func TestIPv6PrefixSharesPerIPBudget(t *testing.T) {
	l := newPerIPLimiter(1)
	a := sourcePrefix(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 1})
	b := sourcePrefix(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::ffff"), Port: 2})
	c := sourcePrefix(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1"), Port: 3})

	if a != "2001:db8:1:2::/64" || b != a {
		t.Fatalf("same /64 produced distinct keys: a=%q b=%q", a, b)
	}
	if !l.acquire(a) {
		t.Fatal("first address in /64 should acquire the shared budget")
	}
	if l.acquire(b) {
		t.Fatal("second address in /64 bypassed the shared per-IP budget")
	}
	if !l.acquire(c) {
		t.Fatal("address in a distinct /64 should have an independent budget")
	}
}

// TestPerCarrierLimiterScopesBySourceAndCarrier proves saturation affects only
// one source-prefix/carrier pair and that fully released pairs are pruned.
func TestPerCarrierLimiterScopesBySourceAndCarrier(t *testing.T) {
	l := newSourceCarrierLimiter(2)
	first := l.acquire("203.0.113.1/32", "carrier-a")
	if !first || !l.acquire("203.0.113.1/32", "carrier-a") {
		t.Fatal("acquires within one source/carrier budget should succeed")
	}
	if l.acquire("203.0.113.1/32", "carrier-a") {
		t.Fatal("acquire above one source/carrier budget should fail")
	}
	if !l.acquire("203.0.113.2/32", "carrier-a") {
		t.Fatal("second source should retain capacity on the same carrier")
	}
	if !l.acquire("203.0.113.1/32", "carrier-b") {
		t.Fatal("same source should have an independent budget on another carrier")
	}

	l.release("203.0.113.1/32", "carrier-a")
	l.release("203.0.113.1/32", "carrier-a")
	l.release("203.0.113.2/32", "carrier-a")
	l.release("203.0.113.1/32", "carrier-b")
	if len(l.counts) != 0 {
		t.Fatalf("counts retained %d fully released source/carrier pairs", len(l.counts))
	}
}
