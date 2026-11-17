package protocol

import (
	"net"

	"golang.org/x/sys/unix"
)

// boundUnsentBacklog sets TCP_NOTSENT_LOWAT: the kernel then refuses a write
// while that many bytes are still unsent, so the writer waits in the netpoller.
func boundUnsentBacklog(conn *net.TCPConn) net.Conn {
	raw, err := conn.SyscallConn()
	if err != nil {
		return conn
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, CarrierUnsentLowat)
	})
	return conn
}
