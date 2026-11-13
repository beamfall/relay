// Package protocol: QUIC carrier (ADR-0018 §1 v2 upgrade).
//
// The v1 carrier multiplexes every relayed stream over one yamux session on
// top of a single TLS/TCP connection, so all streams share one congestion
// window and one yamux stream window (4 MiB by default): a loss event on one stream (or a
// high-bitrate stream saturating its window) stalls every other stream on the
// same carrier. QUIC gives each stream its own flow-control window and loss
// recovery, so a stalled or throttled stream no longer head-of-line-blocks
// its siblings, and per-stream windows can be sized well past yamux's default
// window without cross-stream interference.
//
// QuicSession adapts *quic.Conn to the Session interface so relay.go and
// tunnel/client.go drive both transports through the same seam.
package protocol

import (
	"context"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICConfig returns the quic-go transport config shared by the relay (server
// side) and the tunnel client (client side). Both ends MUST use the same
// config so flow-control and keep-alive expectations match, mirroring
// YamuxConfig's role for the v1 carrier.
//
//   - MaxStreamReceiveWindow / MaxConnectionReceiveWindow are set well past
//     yamux's default stream window (8 MiB / 64 MiB) since QUIC's per-stream
//     isolation means a large window on one stream no longer starves others;
//     the window only needs to clear the bandwidth-delay product of a 4K
//     remux on a long-RTT path (e.g. ~450 KiB at 60 Mbps / 60 ms RTT, before
//     even more headroom for loss recovery).
//   - MaxIncomingStreams bounds concurrent peer-initiated streams per carrier,
//     mirroring the relay's own StreamCap accounting (belt-and-suspenders: the
//     relay's carrier.open() still enforces the authoritative cap).
//   - KeepAlivePeriod keeps a idle carrier's NAT/firewall mapping alive and
//     lets a dead peer be detected, mirroring yamux's EnableKeepAlive default.
func QUICConfig() *quic.Config {
	return &quic.Config{
		MaxStreamReceiveWindow:     8 * 1024 * 1024,
		MaxConnectionReceiveWindow: 64 * 1024 * 1024,
		MaxIncomingStreams:         1024,
		KeepAlivePeriod:            15 * time.Second,
	}
}

// QuicSession adapts a *quic.Conn to the Session interface.
type QuicSession struct {
	conn *quic.Conn
}

// NewQUICSession wraps an established QUIC connection as a Session.
func NewQUICSession(conn *quic.Conn) *QuicSession {
	return &QuicSession{conn: conn}
}

var _ Session = (*QuicSession)(nil)

func (s *QuicSession) Open() (net.Conn, error) {
	stream, err := s.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	return &quicStreamConn{Stream: stream, conn: s.conn}, nil
}

func (s *QuicSession) Accept() (net.Conn, error) {
	stream, err := s.conn.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return &quicStreamConn{Stream: stream, conn: s.conn}, nil
}

func (s *QuicSession) Close() error {
	return s.conn.CloseWithError(0, "")
}

func (s *QuicSession) IsClosed() bool {
	select {
	case <-s.conn.Context().Done():
		return true
	default:
		return false
	}
}

func (s *QuicSession) CloseChan() <-chan struct{} {
	return s.conn.Context().Done()
}

// quicStreamConn adapts a *quic.Stream (Read/Write/Close/deadlines, no
// addresses) to net.Conn by sourcing LocalAddr/RemoteAddr from the parent
// connection, matching how yamux.Stream reports its session's addresses.
type quicStreamConn struct {
	*quic.Stream
	conn *quic.Conn
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *quicStreamConn) abort() {
	c.CancelRead(0)
	c.CancelWrite(0)
}
