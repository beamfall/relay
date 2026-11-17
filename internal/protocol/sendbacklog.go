package protocol

import "net"

// CarrierUnsentLowat is how many bytes a TLS/TCP carrier keeps written but not
// yet sent before its writer waits. yamux frames every stream onto the one
// carrier connection in arrival order, so bytes the kernel has accepted but not
// yet put on the wire are a queue a control frame cannot overtake. Left to the
// kernel's send-buffer autotuning that queue reaches megabytes; at 16 KiB it
// drains in 64 ms on a 2 Mbit/s uplink. It does not limit throughput: the bytes
// in flight are still governed by the congestion and receive windows.
const CarrierUnsentLowat = 16 << 10

// BoundUnsentBacklog bounds the unsent send backlog of a TCP carrier
// connection to CarrierUnsentLowat where the platform can (Linux and macOS),
// and returns the connection to use in its place. Connections that are not TCP,
// and platforms without the control, are returned unchanged. Call it on the
// raw connection, below TLS.
func BoundUnsentBacklog(conn net.Conn) net.Conn {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return conn
	}
	return boundUnsentBacklog(tcp)
}

// UnsentBacklogListener returns a listener whose accepted connections have
// passed through BoundUnsentBacklog.
func UnsentBacklogListener(ln net.Listener) net.Listener {
	return unsentBacklogListener{Listener: ln}
}

type unsentBacklogListener struct{ net.Listener }

func (l unsentBacklogListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return BoundUnsentBacklog(conn), nil
}
