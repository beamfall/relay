package protocol

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	unsentPollInterval = time.Millisecond
	// unsentMaxWait bounds one write's wait, so a connection whose peer has
	// stopped reading falls through to the kernel's own blocking and the
	// caller's write deadline instead of polling forever.
	unsentMaxWait = 2 * time.Second
)

// boundUnsentBacklog wraps the connection so each write first waits for the
// unsent backlog to fall to CarrierUnsentLowat. macOS applies
// TCP_NOTSENT_LOWAT only to writability events, and Go writes before it polls,
// so the option alone does not hold a writer back here.
func boundUnsentBacklog(conn *net.TCPConn) net.Conn {
	raw, err := conn.SyscallConn()
	if err != nil {
		return conn
	}
	return &unsentBoundConn{TCPConn: conn, raw: raw}
}

type unsentBoundConn struct {
	*net.TCPConn
	raw syscall.RawConn
}

func (c *unsentBoundConn) Write(p []byte) (int, error) {
	for waited := time.Duration(0); waited < unsentMaxWait; waited += unsentPollInterval {
		unsent, ok := c.unsent()
		if !ok || unsent <= CarrierUnsentLowat {
			break
		}
		time.Sleep(unsentPollInterval)
	}
	return c.TCPConn.Write(p)
}

// unsent estimates the bytes written but not yet sent: the send buffer's
// content less what the congestion and peer windows allow in flight. The
// kernel does not report the unsent count itself.
func (c *unsentBoundConn) unsent() (int64, bool) {
	var info *unix.TCPConnectionInfo
	var infoErr error
	if err := c.raw.Control(func(fd uintptr) {
		info, infoErr = unix.GetsockoptTCPConnectionInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
	}); err != nil || infoErr != nil {
		return 0, false
	}
	return int64(info.Snd_sbbytes) - int64(min(info.Snd_cwnd, info.Snd_wnd)), true
}
