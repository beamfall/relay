package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	hello := Hello{
		Version:   Version,
		Token:     []byte("opaque-token"),
		Hostnames: []string{"home.relay.example"},
	}

	if err := WriteFrame(&buf, Frame{Type: FrameHello, Hello: &hello}); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	frame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if frame.Type != FrameHello {
		t.Fatalf("frame type = %q, want %q", frame.Type, FrameHello)
	}
	if frame.Hello.Version != Version {
		t.Fatalf("version = %d, want %d", frame.Hello.Version, Version)
	}
	if string(frame.Hello.Token) != "opaque-token" {
		t.Fatalf("token did not round-trip")
	}
	if got := frame.Hello.Hostnames; len(got) != 1 || got[0] != "home.relay.example" {
		t.Fatalf("hostnames = %#v", got)
	}
}

func TestHelloSurfaceDefaultsToPassthrough(t *testing.T) {
	surface, err := HelloSurface(&Hello{Version: Version})
	if err != nil {
		t.Fatalf("surface: %v", err)
	}
	if surface != SurfacePassthrough {
		t.Fatalf("surface = %q, want %q", surface, SurfacePassthrough)
	}
}

func TestHelloSurfaceValidatesCacheVersionAndKey(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, MinCacheVerificationBytes)
	if _, err := HelloSurface(&Hello{
		Version:              Version,
		Surface:              SurfaceCache,
		CacheProtocolVersion: CacheProtocolVersion,
		CacheVerificationKey: key,
	}); err != nil {
		t.Fatalf("cache surface: %v", err)
	}
	if _, err := HelloSurface(&Hello{
		Version:              Version,
		Surface:              SurfaceCache,
		CacheProtocolVersion: CacheProtocolVersion + 1,
		CacheVerificationKey: key,
	}); err != ErrInvalidSurface {
		t.Fatalf("skew err = %v, want %v", err, ErrInvalidSurface)
	}
	if _, err := HelloSurface(&Hello{
		Version:              Version,
		Surface:              SurfacePassthrough,
		CacheProtocolVersion: CacheProtocolVersion,
	}); err != ErrInvalidSurface {
		t.Fatalf("passthrough cache fields err = %v, want %v", err, ErrInvalidSurface)
	}
}

func TestReadFrameRejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 1, 0, 1})
	buf.Write(bytes.Repeat([]byte{'x'}, MaxFrameSize+1))

	if _, err := ReadFrame(&buf); err == nil {
		t.Fatal("expected oversized frame to fail")
	}
}
