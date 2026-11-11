package protocol

import (
	"io"
	"net"

	"github.com/hashicorp/yamux"
)

// HalfCloseWrite signals "no more writes" to dst while leaving its read side
// open, so one clean splice direction can finish without cutting the opposite
// direction. TCP exposes this as CloseWrite; yamux streams and QUIC streams
// (via quicStreamConn) both use Close as a local write-side-only close
// (quic.Stream.Close closes only the send direction, per its doc comment).
func HalfCloseWrite(dst io.Writer) {
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	if ys, ok := dst.(*yamux.Stream); ok {
		_ = ys.Close()
		return
	}
	if qs, ok := dst.(*quicStreamConn); ok {
		_ = qs.Close()
		return
	}
}

// AbortStream tears down both directions of a relayed stream after an abrupt
// splice error. QUIC requires an explicit read and write reset; yamux Close is
// a half-close whose configured StreamCloseTimeout supplies the final reset.
func AbortStream(stream net.Conn) {
	if aborter, ok := stream.(interface{ abort() }); ok {
		aborter.abort()
		return
	}
	if ys, ok := stream.(*yamux.Stream); ok {
		_ = ys.Close()
		return
	}
	_ = stream.Close()
}
