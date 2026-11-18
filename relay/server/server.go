// Package server is the relay's UDP loop: receive a datagram, let the session
// table decide where it goes, and send the same bytes on.
//
// It never reads the payload and never logs per packet. It only counts.
package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/padmor/linko/relay/envelope"
	"github.com/padmor/linko/relay/session"
)

const (
	// readBufSize is larger than any legitimate datagram (1400 tunnel MTU plus
	// the 18-byte header). A datagram that fills the buffer is dropped.
	readBufSize = 2048
	// expireEvery is how often silent sides are cleared from the table.
	expireEvery = 30 * time.Second
)

// Stats counts what the server did. All fields are safe for concurrent use.
type Stats struct {
	Forwarded     atomic.Uint64 // packets sent on to the partner
	DroppedFormat atomic.Uint64 // bad envelope or oversize datagram
	DroppedRoute  atomic.Uint64 // unknown token, keepalive, or partner not reachable
	DroppedSend   atomic.Uint64 // the write to the partner failed
}

// Server forwards packets between paired phones.
type Server struct {
	conn  *net.UDPConn
	table *session.Table
	Stats Stats
}

// New creates a server on an already-bound socket.
func New(conn *net.UDPConn, table *session.Table) *Server {
	return &Server{conn: conn, table: table}
}

// Serve runs until ctx is cancelled, then closes the socket, waits for the
// workers and returns nil. The socket belongs to the server after New.
func (s *Server) Serve(ctx context.Context) error {
	var wg sync.WaitGroup

	// One reader per CPU core. UDP reads on one socket are safe to share.
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.readLoop()
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.expireLoop(ctx)
	}()

	<-ctx.Done()
	s.conn.Close() // unblocks every pending read
	wg.Wait()
	return nil
}

// readLoop handles datagrams until the socket is closed.
func (s *Server) readLoop() {
	buf := make([]byte, readBufSize)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Anything else is transient. On Windows, sending to a phone that
			// just went away makes the next read fail with "connection reset";
			// stopping here would kill the relay.
			continue
		}
		s.handle(buf[:n], from, n == len(buf))
	}
}

// handle processes one datagram.
func (s *Server) handle(b []byte, from netip.AddrPort, oversize bool) {
	if oversize {
		s.Stats.DroppedFormat.Add(1)
		return
	}
	pkt, err := envelope.Parse(b)
	if err != nil {
		s.Stats.DroppedFormat.Add(1)
		return
	}

	// A dual-stack socket reports IPv4 peers as IPv4-in-IPv6. Normalise so the
	// same phone always has the same address, and writes use the right family.
	from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())

	to, ok := s.table.Route(pkt, from)
	if !ok {
		s.Stats.DroppedRoute.Add(1)
		return
	}
	if _, err := s.conn.WriteToUDPAddrPort(b, to); err != nil {
		s.Stats.DroppedSend.Add(1)
		return
	}
	s.Stats.Forwarded.Add(1)
}

// expireLoop clears stale addresses on a timer until ctx ends.
func (s *Server) expireLoop(ctx context.Context) {
	t := time.NewTicker(expireEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.table.Expire()
		case <-ctx.Done():
			return
		}
	}
}
