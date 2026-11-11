package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	Version      = 1
	MaxFrameSize = 64 * 1024

	FrameHello = "hello"
	FrameAck   = "ack"
	FrameError = "error"

	FrameCachePush             = "cache_push"
	FrameCacheAck              = "cache_ack"
	FrameCacheInventoryRequest = "cache_inventory_request"
	FrameCacheInventory        = "cache_inventory"
	FrameCachePullRequest      = "cache_pull_request"
	FrameCachePullResponse     = "cache_pull_response"

	SurfacePassthrough = "passthrough"
	SurfaceCache       = "cache"

	CacheProtocolVersion      = 1
	MinCacheVerificationBytes = 32
)

var ErrFrameTooLarge = errors.New("protocol frame too large")
var ErrInvalidSurface = errors.New("invalid carrier surface")

// FrameReadWriter is the byte-stream a carrier handshake reads Hello/Ack
// frames from and writes them to. A TLS/TCP carrier conn satisfies this
// directly; a QUIC carrier uses its handshake stream (net.Conn is a superset,
// so both already satisfy this without an adapter).
type FrameReadWriter interface {
	io.Reader
	io.Writer
}

type Frame struct {
	Type  string `json:"type"`
	Hello *Hello `json:"hello,omitempty"`
	Ack   *Ack   `json:"ack,omitempty"`
	Error string `json:"error,omitempty"`

	CachePush             *CachePush             `json:"cache_push,omitempty"`
	CacheAck              *CacheAck              `json:"cache_ack,omitempty"`
	CacheInventoryRequest *CacheInventoryRequest `json:"cache_inventory_request,omitempty"`
	CacheInventory        *CacheInventory        `json:"cache_inventory,omitempty"`
	CachePullRequest      *CachePullRequest      `json:"cache_pull_request,omitempty"`
	CachePullResponse     *CachePullResponse     `json:"cache_pull_response,omitempty"`
}

type Hello struct {
	Version              int      `json:"version"`
	Token                []byte   `json:"token"`
	Hostnames            []string `json:"hostnames"`
	Surface              string   `json:"surface,omitempty"`
	CacheProtocolVersion int      `json:"cache_protocol_version,omitempty"`
	CacheVerificationKey []byte   `json:"cache_verification_key,omitempty"`
}

type Ack struct {
	Version              int      `json:"version"`
	CarrierID            string   `json:"carrier_id"`
	Hostnames            []string `json:"hostnames"`
	Surface              string   `json:"surface,omitempty"`
	CacheProtocolVersion int      `json:"cache_protocol_version,omitempty"`
}

type CachePush struct {
	SegmentSetID string    `json:"segment_set_id"`
	Segment      string    `json:"segment"`
	ContentType  string    `json:"content_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Bytes        int64     `json:"bytes"`
}

type CacheAck struct {
	Status string          `json:"status"`
	Error  string          `json:"error,omitempty"`
	Quota  CacheQuotaState `json:"quota"`
}

type CacheQuotaState struct {
	UsedBytes int64 `json:"used_bytes"`
	CapBytes  int64 `json:"cap_bytes"`
}

type CacheInventoryRequest struct {
	SegmentSetID string `json:"segment_set_id"`
}

type CacheInventory struct {
	Entries []CacheInventoryEntry `json:"entries"`
	Quota   CacheQuotaState       `json:"quota"`
}

type CacheInventoryEntry struct {
	Segment     string    `json:"segment"`
	Bytes       int64     `json:"bytes"`
	ContentType string    `json:"content_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type CachePullRequest struct {
	SegmentSetID string `json:"segment_set_id"`
	Segment      string `json:"segment"`
}

type CachePullResponse struct {
	Status      string    `json:"status"`
	Error       string    `json:"error,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	Bytes       int64     `json:"bytes,omitempty"`
}

func HelloSurface(h *Hello) (string, error) {
	if h == nil {
		return "", ErrInvalidSurface
	}
	switch h.Surface {
	case "", SurfacePassthrough:
		if h.CacheProtocolVersion != 0 || len(h.CacheVerificationKey) != 0 {
			return "", ErrInvalidSurface
		}
		return SurfacePassthrough, nil
	case SurfaceCache:
		if h.CacheProtocolVersion != CacheProtocolVersion {
			return "", ErrInvalidSurface
		}
		if len(h.CacheVerificationKey) < MinCacheVerificationBytes {
			return "", ErrInvalidSurface
		}
		return SurfaceCache, nil
	default:
		return "", ErrInvalidSurface
	}
}

func WriteFrame(w io.Writer, frame Frame) error {
	payload, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	return nil
}

func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, fmt.Errorf("read frame length: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameSize {
		return Frame{}, ErrFrameTooLarge
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, fmt.Errorf("read frame payload: %w", err)
	}

	var frame Frame
	if err := json.Unmarshal(payload, &frame); err != nil {
		return Frame{}, fmt.Errorf("decode frame: %w", err)
	}
	return frame, nil
}
