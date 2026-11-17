package protocol

import (
	"io"
	"net"
	"time"

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

// DiscardAbortedStream reads and discards what the peer still sends on a
// stream AbortStream has closed, and returns once the stream is gone. A QUIC
// abort resets the stream at once, so there is nothing to wait for. A yamux
// abort is only a half-close: the stream and its receive buffer stay in the
// session until the peer answers with its own close or StreamCloseTimeout
// resets it. A peer blocked on a shut window cannot answer, so the buffered
// bytes are taken off it here, which lets a well-behaved peer finish in
// milliseconds. A caller that accounts for the stream's memory keeps that
// account open until this returns (CORE-2252).
func DiscardAbortedStream(stream net.Conn) {
	ys, ok := stream.(*yamux.Stream)
	if !ok {
		return
	}
	// The close timeout ends the stream; the deadline only guards against a
	// read that would otherwise never return.
	_ = ys.SetReadDeadline(time.Now().Add(yamuxStreamCloseTimeout + 5*time.Second))
	_, _ = io.Copy(io.Discard, ys)
}
