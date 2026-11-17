package protocol

import (
	"io"
	"net"
	"testing"
)

func TestBoundUnsentBacklogLeavesOtherConnsAlone(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	if got := BoundUnsentBacklog(a); got != a {
		t.Fatalf("a non-TCP connection came back as %T", got)
	}
}

// TestUnsentBacklogListenerCarriesData checks a bounded connection still
// behaves as a connection, on every platform.
func TestUnsentBacklogListenerCarriesData(t *testing.T) {
	accepted, dialled := boundedPair(t)
	msg := []byte("carrier frame")
	for _, c := range []struct{ from, to net.Conn }{{dialled, accepted}, {accepted, dialled}} {
		if _, err := c.from.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c.to, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != string(msg) {
			t.Fatalf("read %q, want %q", got, msg)
		}
	}
}

// boundedPair returns both ends of a loopback TCP connection, the accepted end
// through UnsentBacklogListener and the dialled end through BoundUnsentBacklog.
func boundedPair(t *testing.T) (accepted, dialled net.Conn) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := UnsentBacklogListener(inner)
	t.Cleanup(func() { _ = ln.Close() })
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dialled = BoundUnsentBacklog(raw)
	t.Cleanup(func() { _ = dialled.Close() })
	accepted, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accepted.Close() })
	return accepted, dialled
}
