package config

import (
	"fmt"
	"net"
)

// AdminExposureCheck classifies a "host:port" admin listener address
// (e.g. --admin-addr) as loopback/private, unparseable, or public, and
// returns:
//   - err non-nil: addr is bound to a non-local, non-private address and
//     allowPublic is false. The caller must refuse to start (SECREV-RELAY-5:
//     hard-fail by default; the operator must pass --admin-allow-public to
//     opt in).
//   - warning non-empty: addr could not be classified (unparseable
//     host:port, or a hostname rather than a literal IP), so exposure can't
//     be verified either way. This is advisory only, never a startup
//     failure.
//
// Both are empty/nil when addr is "" (admin listener disabled), resolves to
// loopback/private, or allowPublic is true. The admin endpoints (/healthz,
// /metrics) are aggregate-only per ADR-0103, so there is no per-user data
// leak from broader exposure — but an operator could unknowingly expose them
// beyond the intended local/private network.
func AdminExposureCheck(addr string, allowPublic bool) (warning string, err error) {
	if addr == "" {
		return "", nil
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		// Not a parseable host:port; nothing to hard-fail on, warn only.
		return fmt.Sprintf("admin listener %q could not be parsed as host:port; exposure cannot be verified as local-only", addr), nil
	}
	if host == "" {
		// e.g. ":9080" binds all interfaces on every address family.
		if allowPublic {
			return "", nil
		}
		return "", fmt.Errorf("admin listener %q binds all network interfaces (host is empty); refusing to start without --admin-allow-public", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A hostname rather than a literal IP: can't classify loopback/private
		// without a DNS lookup, so warn conservatively instead of hard-failing.
		return fmt.Sprintf("admin listener %q uses a hostname, not a loopback/private literal; exposure cannot be verified as local-only", addr), nil
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return "", nil
	}
	if allowPublic {
		return "", nil
	}
	return "", fmt.Errorf("admin listener %q is not bound to a loopback or private address; refusing to start without --admin-allow-public", addr)
}

// AdminAddrIsLoopback reports whether addr definitively binds a loopback
// interface only. It returns true solely for a literal loopback IP
// (127.0.0.0/8, ::1); an empty host (":9080" binds every interface), a
// non-loopback literal, or a hostname/unparseable address all return false —
// the conservative choice, since ADR-0146 §5 requires an operator credential on
// any non-loopback /metrics bind and false means "treat as exposed, demand the
// credential". An empty addr (admin listener disabled) returns false; there is
// no listener to protect.
func AdminAddrIsLoopback(addr string) bool {
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
