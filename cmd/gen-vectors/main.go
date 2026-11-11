// gen-vectors generates the committed relay contract vectors. Run from the repo
// root (or use `make gen-vectors`, which writes every set):
//
//	go run ./cmd/gen-vectors > contracts/protocol/v1/vectors.json
//	go run ./cmd/gen-vectors -set hmac-token-v2 > contracts/protocol/v1/hmac-token-v2-vectors.json
//
// The default "frames" set is captured from the live internal/protocol frame
// writer; regenerate it whenever internal/protocol/protocol.go changes. The
// "hmac-token-v2" set is minted from fixed inputs per PROTOCOL.md "Carrier token
// v2"; internal/relay replays it against the live HMACTokenVerifier.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/beamfall/relay/internal/protocol"
)

// vectorSets maps each -set name to the builder of its JSON document.
var vectorSets = map[string]func() (any, error){
	"frames":        frameVectors,
	"hmac-token-v2": hmacTokenV2Vectors,
}

type vector struct {
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	Struct       protocol.Frame `json:"struct"`
	WireBytesHex string         `json:"wire_bytes_hex"`
}

type vectorFile struct {
	SchemaVersion int      `json:"schema_version"`
	GeneratedBy   string   `json:"generated_by"`
	Carriers      []string `json:"carriers"`
	Vectors       []vector `json:"vectors"`
}

func capture(frame protocol.Frame) (string, error) {
	var buf bytes.Buffer
	if err := protocol.WriteFrame(&buf, frame); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func main() {
	set := flag.String("set", "frames", "vector set to emit: "+setNames())
	flag.Parse()
	out, err := render(*set)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-vectors: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		fmt.Fprintf(os.Stderr, "gen-vectors: write: %v\n", err)
		os.Exit(1)
	}
}

// render builds the named set and encodes it exactly as it is committed.
func render(set string) ([]byte, error) {
	build, ok := vectorSets[set]
	if !ok {
		return nil, fmt.Errorf("unknown -set %q (want one of %s)", set, setNames())
	}
	doc, err := build()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", set, err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("%s: encode: %w", set, err)
	}
	return buf.Bytes(), nil
}

func setNames() string {
	names := make([]string, 0, len(vectorSets))
	for name := range vectorSets {
		names = append(names, name)
	}
	sort.Strings(names)
	return fmt.Sprint(names)
}

// frameVectors captures every hello/ack/error/cache frame vector from the live
// internal/protocol frame writer.
func frameVectors() (any, error) {
	frames := []struct {
		name string
		desc string
		f    protocol.Frame
	}{
		{
			name: "hello_basic",
			desc: "Minimal hello frame: version=1, single hostname, short token.",
			f: protocol.Frame{
				Type: protocol.FrameHello,
				Hello: &protocol.Hello{
					Version:   protocol.Version,
					Token:     []byte("opaque-token-abc"),
					Hostnames: []string{"home.relay.example"},
				},
			},
		},
		{
			name: "hello_multi_hostname",
			desc: "Hello frame with multiple hostnames.",
			f: protocol.Frame{
				Type: protocol.FrameHello,
				Hello: &protocol.Hello{
					Version:   protocol.Version,
					Token:     []byte("tok"),
					Hostnames: []string{"a.example.com", "b.example.com", "c.example.com"},
				},
			},
		},
		{
			name: "ack_basic",
			desc: "Basic ack frame returned by server on acceptance.",
			f: protocol.Frame{
				Type: protocol.FrameAck,
				Ack: &protocol.Ack{
					Version:   protocol.Version,
					CarrierID: "carrier-uuid-0001",
					Hostnames: []string{"home.relay.example"},
				},
			},
		},
		{
			name: "error_invalid_hello",
			desc: "Error frame sent by server for malformed or version-mismatch hello.",
			f: protocol.Frame{
				Type:  protocol.FrameError,
				Error: "invalid hello",
			},
		},
		{
			name: "error_unauthorized",
			desc: "Error frame sent by server when token verification fails.",
			f: protocol.Frame{
				Type:  protocol.FrameError,
				Error: "unauthorized",
			},
		},
		{
			name: "cache_push",
			desc: "Cache-carrier push frame announcing one segment payload.",
			f: protocol.Frame{
				Type: protocol.FrameCachePush,
				CachePush: &protocol.CachePush{
					SegmentSetID: "segset_abc",
					Segment:      "0001.m4s",
					ContentType:  "video/mp4",
					ExpiresAt:    mustTime("2026-07-07T12:00:00Z"),
					Bytes:        10,
				},
			},
		},
		{
			name: "cache_ack_quota_exceeded",
			desc: "Cache-carrier typed quota rejection with quota state.",
			f: protocol.Frame{
				Type: protocol.FrameCacheAck,
				CacheAck: &protocol.CacheAck{
					Status: "rejected",
					Error:  "quota_exceeded",
					Quota:  protocol.CacheQuotaState{UsedBytes: 64, CapBytes: 64},
				},
			},
		},
		{
			name: "cache_inventory_request",
			desc: "Home-server inventory reconciliation request for one segment set.",
			f: protocol.Frame{
				Type:                  protocol.FrameCacheInventoryRequest,
				CacheInventoryRequest: &protocol.CacheInventoryRequest{SegmentSetID: "segset_abc"},
			},
		},
		{
			name: "cache_inventory",
			desc: "Relay inventory response listing currently-held unexpired segments.",
			f: protocol.Frame{
				Type: protocol.FrameCacheInventory,
				CacheInventory: &protocol.CacheInventory{
					Entries: []protocol.CacheInventoryEntry{{
						Segment:     "0001.m4s",
						Bytes:       10,
						ContentType: "video/mp4",
						ExpiresAt:   mustTime("2026-07-07T12:00:00Z"),
					}},
					Quota: protocol.CacheQuotaState{UsedBytes: 10, CapBytes: 1024},
				},
			},
		},
	}

	var vectors []vector
	for _, item := range frames {
		wireHex, err := capture(item.f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", item.name, err)
		}
		vectors = append(vectors, vector{
			Name:         item.name,
			Description:  item.desc,
			Struct:       item.f,
			WireBytesHex: wireHex,
		})
	}

	out := vectorFile{
		SchemaVersion: 1,
		GeneratedBy:   "cmd/gen-vectors (go run ./cmd/gen-vectors)",
		// The Hello/Ack/Error frame wire format is carried verbatim by every
		// registered carrier transport (ADR-0018 §1): the length-prefixed JSON
		// frame is written/read the same way whether the underlying stream is a
		// yamux stream over TLS/TCP (v1) or a QUIC stream (v2). internal/relay's
		// TestCarrierConformanceVectors replays every vector below over a real
		// session of each transport listed here, so this list is the set of
		// carriers this vector file's conformance guarantee actually covers.
		Carriers: []string{"tcp", "quic"},
		Vectors:  vectors,
	}
	return out, nil
}

func mustTime(value string) time.Time {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return t
}
