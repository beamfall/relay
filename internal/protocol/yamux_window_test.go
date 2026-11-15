package protocol

import (
	"math"
	"testing"

	"github.com/hashicorp/yamux"
)

func TestValidateYamuxStreamWindowBytesAcceptsDefaultAndBounds(t *testing.T) {
	for _, value := range []int64{0, MinYamuxStreamWindowBytes, DefaultYamuxStreamWindowBytes, math.MaxUint32} {
		if err := ValidateYamuxStreamWindowBytes(value); err != nil {
			t.Errorf("ValidateYamuxStreamWindowBytes(%d) = %v, want nil", value, err)
		}
		if value == 0 {
			continue
		}
		if err := yamux.VerifyConfig(YamuxConfig(int(value))); err != nil {
			t.Errorf("accepted window %d builds an invalid yamux config: %v", value, err)
		}
	}
}

func TestValidateYamuxStreamWindowBytesRejectsOutOfRange(t *testing.T) {
	for _, value := range []int64{-1, 1, 65536, MinYamuxStreamWindowBytes - 1, math.MaxUint32 + 1, math.MaxInt64} {
		if err := ValidateYamuxStreamWindowBytes(value); err == nil {
			t.Errorf("ValidateYamuxStreamWindowBytes(%d) = nil, want an error", value)
		}
	}
}

// Regression for RELAY-YAMUX-WINDOW-BOUND-1: 2^32 used to wrap to a zero window
// through the uint32 conversion in YamuxConfig, and 65536 used to pass startup
// and fail only in yamux.VerifyConfig when a carrier session was created.
func TestValidateYamuxStreamWindowBytesCatchesWrapAndBelowMinimumBeforeYamux(t *testing.T) {
	wrapsToZero := int64(math.MaxUint32) + 1
	if wrapped := uint32(wrapsToZero); wrapped != 0 {
		t.Fatalf("test premise: uint32(%d) = %d, want 0", wrapsToZero, wrapped)
	}
	if err := ValidateYamuxStreamWindowBytes(wrapsToZero); err == nil {
		t.Errorf("window %d accepted; it would wrap to a zero uint32 window", wrapsToZero)
	}

	const belowMinimum = 65536
	if err := ValidateYamuxStreamWindowBytes(belowMinimum); err == nil {
		t.Errorf("window %d accepted at flag validation", belowMinimum)
	}
	if err := yamux.VerifyConfig(YamuxConfig(belowMinimum)); err == nil {
		t.Fatalf("test premise: yamux.VerifyConfig accepted window %d", belowMinimum)
	}
}
