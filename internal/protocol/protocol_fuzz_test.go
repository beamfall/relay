package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Add(encodeFuzzFrame(Frame{Type: FrameHello, Hello: &Hello{
		Version:   Version,
		Token:     []byte("opaque-token"),
		Hostnames: []string{"home.relay.example"},
	}}))
	f.Add(oversizedFrameHeader())

	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := ReadFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		if frame.Hello != nil && frame.Hello.Version < 0 {
			t.Fatalf("hello version is negative: %d", frame.Hello.Version)
		}
		if frame.Ack != nil && frame.Ack.Version < 0 {
			t.Fatalf("ack version is negative: %d", frame.Ack.Version)
		}
	})
}

func encodeFuzzFrame(frame Frame) []byte {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func oversizedFrameHeader() []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrameSize+1)
	return hdr[:]
}
