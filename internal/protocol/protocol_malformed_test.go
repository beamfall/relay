package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestReadFrameRejectsMalformedFrames is a normal-mode regression over the
// adversarial frame shapes a carrier could send before authentication. ReadFrame
// must reject each (never panic, never return a usable frame) so a malformed or
// hostile handshake cannot wedge the relay. The FuzzReadFrame target covers random
// inputs; this table pins the specific length-prefix and JSON failure modes.
func TestReadFrameRejectsMalformedFrames(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty input", nil},
		{"truncated length prefix", []byte{0x00, 0x00}},
		{"length declares payload that never arrives", []byte{0x00, 0x00, 0x00, 0x10, '{', '}'}},
		{"oversized length prefix", oversizedHeader()},
		{"non-json payload", framed([]byte("not json at all"))},
		{"json array not object", framed([]byte("[1,2,3]"))},
		{"truncated json object", framed([]byte("{\"type\":"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadFrame(bytes.NewReader(tc.data)); err == nil {
				t.Fatalf("malformed frame %q parsed without error", tc.name)
			}
		})
	}
}

// framed prefixes payload with its correct 4-byte big-endian length so the only
// thing under test is the JSON decode, not the length framing.
func framed(payload []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	return append(hdr[:], payload...)
}

func oversizedHeader() []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrameSize+1)
	return hdr[:]
}
