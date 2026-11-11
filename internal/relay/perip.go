package relay

import (
	"errors"
	"net"
	"net/netip"
	"sync"
)

// perIPLimiter caps the number of concurrently-handled public connections from
// any single source IP (SECREV-RELAY-9 defense-in-depth). It bounds how much of
// the public slot pool one source can occupy, so a partial-record flood — which
// can otherwise hold each slot for the whole peek deadline — cannot starve
// legitimate clients from other IPs.
type perIPLimiter struct {
	max int
	mu  sync.Mutex
	// counts holds only IPs with at least one in-flight connection; entries are
	// deleted on release so the map cannot grow without bound across a churn of
	// distinct source IPs.
	counts map[string]int
}

func newPerIPLimiter(max int) *perIPLimiter {
	return &perIPLimiter{max: max, counts: make(map[string]int)}
}

// acquire reserves one slot for ip, returning false when ip already holds max
// concurrent connections. On false the caller must not release.
func (l *perIPLimiter) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[ip] >= l.max {
		return false
	}
	l.counts[ip]++
	return true
}

// release returns one slot held by ip. It must be called exactly once per
// successful acquire.
func (l *perIPLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[ip] <= 1 {
		delete(l.counts, ip)
		return
	}
	l.counts[ip]--
}

// errSourceCarrierCapReached reports that one source prefix already holds its
// full stream budget on the carrier the stream would have been opened on.
var errSourceCarrierCapReached = errors.New("source carrier stream cap reached")

type sourceCarrierKey struct {
	source  string
	carrier string
}

// sourceCarrierLimiter caps concurrent streams for each source-prefix/carrier
// pair. Fully released pairs are removed so source churn cannot grow the map.
type sourceCarrierLimiter struct {
	max    int
	mu     sync.Mutex
	counts map[sourceCarrierKey]int
}

func newSourceCarrierLimiter(max int) *sourceCarrierLimiter {
	return &sourceCarrierLimiter{max: max, counts: make(map[sourceCarrierKey]int)}
}

func (l *sourceCarrierLimiter) acquire(source, carrier string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := sourceCarrierKey{source: source, carrier: carrier}
	if l.counts[key] >= l.max {
		return false
	}
	l.counts[key]++
	return true
}

func (l *sourceCarrierLimiter) release(source, carrier string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := sourceCarrierKey{source: source, carrier: carrier}
	if l.counts[key] <= 1 {
		delete(l.counts, key)
		return
	}
	l.counts[key]--
}

// sourcePrefix extracts and masks a connection's remote address. IPv4 sources
// use /32 keys and IPv6 sources use /64 keys, preventing an IPv6 prefix holder
// from bypassing per-source controls by rotating interface identifiers. An
// unparseable address falls back to its full string form, which remains a stable
// per-source key.
func sourcePrefix(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	ip = ip.Unmap().WithZone("")
	bits := 64
	if ip.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(ip, bits).Masked().String()
}
