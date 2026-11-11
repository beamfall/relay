package sni

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

var (
	ErrNotTLS         = errors.New("not a tls client hello")
	ErrNoSNI          = errors.New("client hello has no sni")
	ErrTooLarge       = errors.New("client hello exceeds maximum size")
	ErrShortHello     = errors.New("short client hello")
	ErrUnsupportedTLS = errors.New("unsupported tls handshake")
	ErrTooManyRecords = errors.New("client hello split across too many tls records")
)

// maxHandshakeRecords bounds the ClientHello reassembly loop in PeekClientHello,
// independent of the caller's deadline: defense-in-depth against a peer that
// dribbles a legal-but-pathological stream of many tiny handshake records.
const maxHandshakeRecords = 100

// maxTLSRecordBody is the TLS 1.2/1.3 spec limit (RFC 8446 §5.1) on a single
// record's plaintext body. Enforcing it per-record in readRecord is
// defense-in-depth alongside the aggregate maxBytes cap.
const maxTLSRecordBody = 16384

type Result struct {
	ServerName string
	Prefix     []byte
}

func PeekClientHello(conn net.Conn, maxBytes int, timeout time.Duration) (Result, error) {
	if maxBytes <= 0 {
		return Result{}, ErrTooLarge
	}
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck // best-effort deadline reset.
	}

	var prefix []byte
	// A ClientHello handshake message may be split across several TLS handshake
	// records (legally fragmented — common with post-quantum key shares or ECH
	// pushing the ClientHello past the record size). Accumulate handshake-record
	// bodies until we hold the full handshake message, bounded by maxBytes, then
	// parse the reassembled handshake stream.
	var handshake []byte
	for records := 0; ; records++ {
		if records >= maxHandshakeRecords {
			return Result{}, ErrTooManyRecords
		}
		body, err := readRecord(conn, maxBytes, &prefix)
		if err != nil {
			return Result{}, err
		}
		handshake = append(handshake, body...)
		// The 4-byte handshake header (type + 3-byte length) lives at the start of
		// the first record body. Once we have it, we know the total handshake size.
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 0x01 {
			return Result{}, ErrNotTLS
		}
		handshakeLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if 4+handshakeLen <= len(handshake) {
			break
		}
		// Need more records to complete the handshake. Bounded by the maxBytes cap
		// enforced in readRecord against the running prefix, and by
		// maxHandshakeRecords above as defense-in-depth against many tiny records.
	}
	serverName, err := parseClientHello(handshake)
	if err != nil {
		return Result{}, err
	}
	return Result{ServerName: serverName, Prefix: prefix}, nil
}

// readRecord reads one TLS handshake record (content type 0x16), appending the
// full record (header + body) to *prefix so the relay can splice the original
// bytes verbatim, and returns the record body only (handshake-stream fragment).
func readRecord(r io.Reader, maxBytes int, prefix *[]byte) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read tls record header: %w", err)
	}
	*prefix = append(*prefix, hdr[:]...)
	if hdr[0] != 0x16 {
		return nil, ErrNotTLS
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n <= 0 {
		return nil, ErrShortHello
	}
	if n > maxTLSRecordBody || n+len(*prefix) > maxBytes {
		return nil, ErrTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read tls record body: %w", err)
	}
	*prefix = append(*prefix, body...)
	return body, nil
}

// parseClientHelloRecord parses a single complete (unfragmented) TLS handshake
// record: it validates the 5-byte record header, strips it, and parses the
// contained handshake message. Retained for the fuzz and malformed-record
// regression suites, which exercise record-level rejection; the live peek path
// reassembles handshake-record bodies and calls parseClientHello directly.
func parseClientHelloRecord(record []byte) (string, error) {
	if len(record) < 5 {
		return "", ErrShortHello
	}
	if record[0] != 0x16 {
		return "", ErrNotTLS
	}
	n := int(binary.BigEndian.Uint16(record[3:5]))
	if n+5 > len(record) {
		return "", ErrShortHello
	}
	return parseClientHello(record[5 : 5+n])
}

// parseClientHello parses a reassembled handshake message (handshake type byte,
// 3-byte length, then the ClientHello body) and extracts the SNI server name.
func parseClientHello(handshake []byte) (string, error) {
	if len(handshake) < 4 {
		return "", ErrShortHello
	}
	if handshake[0] != 0x01 {
		return "", ErrNotTLS
	}
	handshakeLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if handshakeLen+4 > len(handshake) {
		return "", ErrShortHello
	}

	body := handshake[4 : 4+handshakeLen]
	if len(body) < 38 {
		return "", ErrShortHello
	}
	pos := 2 + 32
	if pos >= len(body) {
		return "", ErrShortHello
	}
	sessionIDLen := int(body[pos])
	pos++
	if pos+sessionIDLen+2 > len(body) {
		return "", ErrShortHello
	}
	pos += sessionIDLen
	cipherLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+cipherLen >= len(body) {
		return "", ErrShortHello
	}
	pos += cipherLen
	compressionLen := int(body[pos])
	pos++
	if pos+compressionLen+2 > len(body) {
		return "", ErrShortHello
	}
	pos += compressionLen
	extensionsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extensionsLen > len(body) {
		return "", ErrShortHello
	}
	extensions := body[pos : pos+extensionsLen]

	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[0:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if extLen > len(extensions) {
			return "", ErrShortHello
		}
		ext := extensions[:extLen]
		extensions = extensions[extLen:]
		if extType == 0 {
			return parseServerNameExtension(ext)
		}
	}
	return "", ErrNoSNI
}

func parseServerNameExtension(ext []byte) (string, error) {
	if len(ext) < 2 {
		return "", ErrShortHello
	}
	listLen := int(binary.BigEndian.Uint16(ext[0:2]))
	if listLen+2 > len(ext) {
		return "", ErrShortHello
	}
	names := ext[2 : 2+listLen]
	for len(names) >= 3 {
		nameType := names[0]
		nameLen := int(binary.BigEndian.Uint16(names[1:3]))
		names = names[3:]
		if nameLen > len(names) {
			return "", ErrShortHello
		}
		if nameType == 0 {
			name := string(names[:nameLen])
			if !validServerName(name) {
				return "", ErrNoSNI
			}
			return strings.ToLower(name), nil
		}
		names = names[nameLen:]
	}
	return "", ErrNoSNI
}

func validServerName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' {
				continue
			}
			if r >= 'A' && r <= 'Z' {
				continue
			}
			if r >= '0' && r <= '9' {
				continue
			}
			if r == '-' {
				continue
			}
			return false
		}
	}
	return true
}
