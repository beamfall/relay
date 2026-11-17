// Package loadtest is the in-process latency harness behind cmd/relay-loadgen's
// latency mode and the latency-budget test (CORE-2246). Nothing here runs in
// relayd.
package loadtest

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"time"
)

// Link describes an emulated carrier link, applied independently to each
// direction. It stands in for Linux tc/netem (script/netem-soak.sh), which
// needs root and does not exist on macOS, so the same numbers can be produced
// on any host and inside `go test`.
//
// The emulation is a proxy between the tunnel client and the relay's carrier
// listener, so neither end is modified:
//
//   - UDP (QUIC carrier): real packet loss. A datagram is dropped with
//     probability Loss, and tail-dropped when the queue is full.
//   - TCP (yamux carrier): a TCP byte stream cannot lose bytes, so loss is
//     modelled by its visible effect. A "lost" segment and everything behind it
//     on the connection is held until the retransmission would have arrived,
//     one round trip (2×Delay) later. This is head-of-line blocking without the
//     congestion-window cut or the retransmission timeout a real stack adds, so
//     it flatters TCP.
type Link struct {
	// Delay is the one-way propagation delay.
	Delay time.Duration
	// Loss is the per-packet (UDP) or per-segment (TCP) loss probability, 0..1.
	Loss float64
	// BitsPerSecond caps the link rate. Zero is uncapped.
	BitsPerSecond float64
	// Queue is the bottleneck buffer, as time at the link rate. Zero uses
	// defaultLinkQueue. It is unused when the link is uncapped.
	Queue time.Duration
	// Seed fixes the loss sequence.
	Seed int64
}

const (
	defaultLinkQueue = 50 * time.Millisecond
	tcpSegmentBytes  = 1460
	proxySocketBytes = 16 * 1024
	maxDatagramBytes = 64 * 1024
)

// shaper schedules one direction of a Link. It is used by one goroutine.
type shaper struct {
	link      Link
	rng       *rand.Rand
	busyUntil time.Time // when the link finishes sending what is queued
	holdUntil time.Time // TCP only: nothing is delivered before this
}

func newShaper(link Link, direction int64) *shaper {
	if link.Queue <= 0 {
		link.Queue = defaultLinkQueue
	}
	// The loss sequence only has to be repeatable, not unpredictable.
	return &shaper{link: link, rng: rand.New(rand.NewSource(link.Seed + direction))}
}

// backlog is how long the queue would take to drain at the link rate.
func (s *shaper) backlog(now time.Time) time.Duration {
	if s.link.BitsPerSecond <= 0 {
		return 0
	}
	return max(s.busyUntil.Sub(now), 0)
}

// schedule queues n bytes arriving now and returns their delivery time.
func (s *shaper) schedule(now time.Time, n int) time.Time {
	sent := now
	if s.link.BitsPerSecond > 0 {
		if s.busyUntil.After(now) {
			sent = s.busyUntil
		}
		sent = sent.Add(time.Duration(float64(n) * 8 / s.link.BitsPerSecond * float64(time.Second)))
		s.busyUntil = sent
	}
	return sent.Add(s.link.Delay)
}

// scheduleSegment is schedule for an in-order byte stream. A lost segment is
// retransmitted one round trip later, and no later segment can be delivered
// ahead of it.
func (s *shaper) scheduleSegment(now time.Time, n int) time.Time {
	at := s.schedule(now, n)
	if s.lose() {
		s.holdUntil = at.Add(2 * s.link.Delay)
	}
	if at.Before(s.holdUntil) {
		at = s.holdUntil
	}
	return at
}

func (s *shaper) lose() bool {
	return s.link.Loss > 0 && s.rng.Float64() < s.link.Loss
}

type scheduled struct {
	at   time.Time
	data []byte
}

// deliver hands each scheduled chunk to write at its delivery time, in order.
func deliver(ctx context.Context, queue <-chan scheduled, write func([]byte) error) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C
	for {
		var item scheduled
		select {
		case <-ctx.Done():
			return
		case next, ok := <-queue:
			if !ok {
				return
			}
			item = next
		}
		if wait := time.Until(item.at); wait > 0 {
			timer.Reset(wait)
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
		}
		if write(item.data) != nil {
			return
		}
	}
}

// ProxyTCP listens on loopback and forwards each connection to upstream
// through link. It returns the address to dial instead of upstream. The proxy
// stops when ctx is done.
func ProxyTCP(ctx context.Context, upstream string, link Link) (string, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxyTCPConn(ctx, conn, upstream, link)
		}
	}()
	return ln.Addr().String(), nil
}

func proxyTCPConn(ctx context.Context, down net.Conn, upstream string, link Link) {
	defer func() { _ = down.Close() }()
	up, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream)
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	// The link's only buffer is Link.Queue: keep the proxy's own sockets small
	// so they do not add a second, host-dependent one.
	for _, conn := range []net.Conn{down, up} {
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetReadBuffer(proxySocketBytes)
			_ = tcp.SetWriteBuffer(proxySocketBytes)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); defer cancel(); shapeTCP(ctx, up, down, newShaper(link, 0)) }()
	go func() { defer wg.Done(); defer cancel(); shapeTCP(ctx, down, up, newShaper(link, 1)) }()
	<-ctx.Done()
	// Unblock both directions' reads and writes.
	_ = down.Close()
	_ = up.Close()
	wg.Wait()
}

// shapeTCP copies src to dst one segment at a time through s. It stops reading
// while the queue is full, so the sender sees back-pressure as it would from a
// real bottleneck.
func shapeTCP(ctx context.Context, dst, src net.Conn, s *shaper) {
	queue := make(chan scheduled, 1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		deliver(ctx, queue, func(b []byte) error { _, err := dst.Write(b); return err })
	}()
	defer func() {
		close(queue)
		<-done
	}()
	for {
		if over := s.backlog(time.Now()) - s.link.Queue; over > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(over):
			}
		}
		buf := make([]byte, tcpSegmentBytes)
		n, err := src.Read(buf)
		if n > 0 {
			at := s.scheduleSegment(time.Now(), n)
			select {
			case <-ctx.Done():
				return
			case queue <- scheduled{at: at, data: buf[:n]}:
			}
		}
		if err != nil {
			return
		}
	}
}

// ProxyUDP listens on loopback and forwards datagrams between its clients and
// upstream through link. It returns the address to dial instead of upstream.
// The proxy stops when ctx is done.
func ProxyUDP(ctx context.Context, upstream string, link Link) (string, error) {
	upstreamAddr, err := net.ResolveUDPAddr("udp", upstream)
	if err != nil {
		return "", err
	}
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return "", err
	}
	go func() {
		<-ctx.Done()
		_ = front.Close()
	}()
	go func() {
		backs := map[string]chan<- scheduled{}
		toUpstream := newShaper(link, 0)
		buf := make([]byte, maxDatagramBytes)
		for {
			n, client, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			queue, ok := backs[client.String()]
			if !ok {
				back, err := net.DialUDP("udp", nil, upstreamAddr)
				if err != nil {
					continue
				}
				queue = shapeUDPBack(ctx, front, back, client, link)
				backs[client.String()] = queue
			}
			enqueueDatagram(toUpstream, queue, buf[:n])
		}
	}()
	return front.LocalAddr().String(), nil
}

// shapeUDPBack starts the two delivery loops for one client and returns the
// queue of datagrams bound for upstream.
func shapeUDPBack(ctx context.Context, front, back *net.UDPConn, client *net.UDPAddr, link Link) chan<- scheduled {
	toUpstream := make(chan scheduled, 4096)
	toClient := make(chan scheduled, 4096)
	go func() {
		<-ctx.Done()
		_ = back.Close()
	}()
	go deliver(ctx, toUpstream, func(b []byte) error { _, err := back.Write(b); return err })
	go deliver(ctx, toClient, func(b []byte) error { _, err := front.WriteToUDP(b, client); return err })
	go func() {
		s := newShaper(link, 1)
		buf := make([]byte, maxDatagramBytes)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			enqueueDatagram(s, toClient, buf[:n])
		}
	}()
	return toUpstream
}

// enqueueDatagram applies loss and the queue limit to one datagram, then
// schedules it. A dropped datagram is simply not forwarded.
func enqueueDatagram(s *shaper, queue chan<- scheduled, datagram []byte) {
	now := time.Now()
	if s.lose() || s.backlog(now) > s.link.Queue {
		return
	}
	item := scheduled{at: s.schedule(now, len(datagram)), data: append([]byte(nil), datagram...)}
	select {
	case queue <- item:
	default:
	}
}
