package protocol

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// A held writer rechecks quickly at first, so a fast link is not paced by
	// the poll, then every unsentPollInterval.
	unsentFastPollInterval = 100 * time.Microsecond
	unsentFastPollFor      = 2 * time.Millisecond
	unsentPollInterval     = time.Millisecond
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
	for start := time.Now(); ; {
		unsent, ok := c.unsent()
		if !ok || unsent <= CarrierUnsentLowat {
			break
		}
		waited := time.Since(start)
		if waited >= unsentMaxWait {
			break
		}
		if waited < unsentFastPollFor {
			time.Sleep(unsentFastPollInterval)
		} else {
			time.Sleep(unsentPollInterval)
		}
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
