package relay

import (
	"errors"
	"net"
	"os"
	"time"

	"github.com/beamfall/relay/internal/protocol"
)

const (
	// DefaultClientWriteStallTimeout is how long a public client may accept no
	// bytes at all while the relay has data for it before its stream is closed.
	DefaultClientWriteStallTimeout = 5 * time.Minute

	// DefaultStreamMemoryBudgetBytes is the memory the relay lets relayed
	// streams buffer in total. It fits the shipped 512 MiB limit: see
	// StreamMemoryHeadroomBytes.
	DefaultStreamMemoryBudgetBytes = 320 * 1024 * 1024

	// StreamMemoryHeadroomBytes is the memory the relay needs besides stream
	// buffers at the default connection caps: goroutine stacks, TLS state, copy
	// buffers, the fair-use and replay maps, and garbage not yet collected. A
	// memory limit should be at least the stream memory budget plus this.
	StreamMemoryHeadroomBytes = 128 * 1024 * 1024
)

// errIdentityStreamCapReached reports that a carrier identity already holds
// its full stream cap across its live and superseded carriers.
var errIdentityStreamCapReached = errors.New("identity stream cap reached")

// streamMemoryCostBytes is the most memory one relayed stream can pin in the
// relay when its public client stops reading: the carrier's receive window,
// which the home can fill before flow control stops it. A yamux stream holds
// that window in a buffer that grows by doubling, so its capacity can reach
// twice the bytes it holds. A QUIC stream holds its window once.
func streamMemoryCostBytes(yamuxStreamWindowBytes int, quicEnabled bool) int64 {
	window := int64(yamuxStreamWindowBytes)
	if window <= 0 {
		window = protocol.DefaultYamuxStreamWindowBytes
	}
	cost := 2 * window
	if quicEnabled && protocol.QUICStreamReceiveWindowBytes > cost {
		cost = protocol.QUICStreamReceiveWindowBytes
	}
	return cost
}

// StreamMemoryStreamLimit is how many streams the relay carries at once for a
// stream memory budget: the budget divided by one stream's worst-case cost,
// and at least one. budgetBytes <= 0 selects DefaultStreamMemoryBudgetBytes.
func StreamMemoryStreamLimit(budgetBytes int64, yamuxStreamWindowBytes int, quicEnabled bool) int {
	if budgetBytes <= 0 {
		budgetBytes = DefaultStreamMemoryBudgetBytes
	}
	limit := budgetBytes / streamMemoryCostBytes(yamuxStreamWindowBytes, quicEnabled)
	return int(max(limit, 1))
}

// stallWriter writes to a public client and gives up when the client accepts
// no bytes for a whole timeout. A write that makes any progress starts a fresh
// timeout, so a slow reader, or a stream with nothing to send, is never cut:
// only a client whose receive window stays shut while the relay holds data
// for it. The carrier buffers up to a stream window for such a client, so
// leaving it open pins that memory for as long as the client likes.
type stallWriter struct {
	conn    net.Conn
	timeout time.Duration
	stalled func()
}

func (w *stallWriter) Write(p []byte) (int, error) {
	written := 0
	for {
		if err := w.conn.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
			return written, err
		}
		n, err := w.conn.Write(p[written:])
		written += n
		if err == nil || written == len(p) {
			return written, err
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return written, err
		}
		if n == 0 {
			if w.stalled != nil {
				w.stalled()
			}
			return written, err
		}
	}
}
