package protocol

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestBoundUnsentBacklogHoldsWriter writes to a peer that never reads. Once the
// peer's window is full, a bounded writer is held with about CarrierUnsentLowat
// unsent; an unbounded one keeps going until the send buffer is full, which
// autotuning puts far higher.
func TestBoundUnsentBacklogHoldsWriter(t *testing.T) {
	_, dialled := boundedPair(t)
	bound, ok := dialled.(*unsentBoundConn)
	if !ok {
		t.Fatalf("dialled connection is %T", dialled)
	}
	const chunk = 4 << 10
	var written atomic.Int64
	go func() {
		buf := make([]byte, chunk)
		for {
			n, err := bound.Write(buf)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()

	// Well inside unsentMaxWait, after which one more write is let through.
	time.Sleep(unsentMaxWait / 4)
	before := written.Load()
	time.Sleep(unsentMaxWait / 4)
	if after := written.Load(); after != before {
		t.Fatalf("writer was not held: %d more bytes accepted", after-before)
	}
	unsent, ok := bound.unsent()
	if !ok {
		t.Fatal("no connection info")
	}
	if limit := int64(CarrierUnsentLowat + chunk); unsent > limit {
		t.Fatalf("%d bytes unsent, want at most %d", unsent, limit)
	}
	if unsent <= 0 {
		t.Fatalf("%d bytes unsent: the peer's window never filled", unsent)
	}
}
