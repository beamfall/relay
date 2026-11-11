package protocol

import (
	"net"

	"github.com/hashicorp/yamux"
)

// Session is the carrier-multiplexer contract shared by every transport this
// relay supports (yamux-over-TLS/TCP in v1, QUIC in v2 per ADR-0018 §1). The
// relay server and the tunnel client both program against this interface so a
// carrier's wire transport is a pluggable detail, not something either side's
// business logic (registry, stream accounting, fair-use, splice) needs to know
// about.
//
// *yamux.Session already satisfies this interface with its existing method
// set; quicSession (quic.go) adapts *quic.Conn to it.
type Session interface {
	// Open opens a new stream on the session, returning it as a net.Conn.
	Open() (net.Conn, error)
	// Accept blocks until a peer-initiated stream arrives, returning it as a
	// net.Conn.
	Accept() (net.Conn, error)
	// Close tears down the session and all its streams.
	Close() error
	// IsClosed reports whether the session has been torn down.
	IsClosed() bool
	// CloseChan returns a channel that is closed when the session ends, so a
	// caller can wait for session death without polling IsClosed.
	CloseChan() <-chan struct{}
}

// compile-time assertion that *yamux.Session satisfies Session without any
// adapter: it already exposes exactly this method set. *yamux.Session itself
// is used directly everywhere else (no wrapper needed).
var _ Session = (*yamux.Session)(nil)
