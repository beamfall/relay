package protocol

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBoundUnsentBacklogSetsNotsentLowat(t *testing.T) {
	accepted, dialled := boundedPair(t)
	for name, conn := range map[string]net.Conn{"accepted": accepted, "dialled": dialled} {
		tcp, ok := conn.(*net.TCPConn)
		if !ok {
			t.Fatalf("%s connection is %T", name, conn)
		}
		raw, err := tcp.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var got int
		var optErr error
		if err := raw.Control(func(fd uintptr) {
			got, optErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
		}); err != nil || optErr != nil {
			t.Fatal(err, optErr)
		}
		if got != CarrierUnsentLowat {
			t.Errorf("%s TCP_NOTSENT_LOWAT = %d, want %d", name, got, CarrierUnsentLowat)
		}
	}
}
