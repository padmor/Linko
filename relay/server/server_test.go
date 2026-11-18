package server

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/padmor/linko/protocol/envelope"
	"github.com/padmor/linko/relay/session"
)

var (
	tokA = envelope.SessionID{1}
	tokB = envelope.SessionID{2}
)

// rig is a running server plus two phone sockets.
type rig struct {
	srv    *Server
	addr   *net.UDPAddr
	a, b   *net.UDPConn
	cancel context.CancelFunc
	done   chan error
}

func newRig(t *testing.T) *rig {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	table := session.NewTable(2 * time.Minute)
	if err := table.Add(tokA, tokB); err != nil {
		t.Fatal(err)
	}
	r := &rig{srv: New(conn, table), addr: conn.LocalAddr().(*net.UDPAddr), done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { r.done <- r.srv.Serve(ctx) }()

	for _, p := range []**net.UDPConn{&r.a, &r.b} {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		*p = c
		t.Cleanup(func() { c.Close() })
	}
	t.Cleanup(cancel)
	return r
}

func wire(t *testing.T, p envelope.Packet) []byte {
	t.Helper()
	b, err := envelope.Marshal(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// waitFor polls cond for up to two seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestForwardsDataUnchanged(t *testing.T) {
	r := newRig(t)
	r.b.WriteToUDP(wire(t, envelope.Packet{Type: envelope.TypeKeepalive, Session: tokB}), r.addr)

	msg := wire(t, envelope.Packet{Type: envelope.TypeData, Session: tokA, Payload: []byte("ciphertext")})
	buf := make([]byte, readBufSize)

	// B's keepalive and A's data travel on different sockets, so their order
	// is not guaranteed. Resend A's data until B has been registered.
	var got []byte
	deadline := time.Now().Add(2 * time.Second)
	for got == nil && time.Now().Before(deadline) {
		r.a.WriteToUDP(msg, r.addr)
		r.b.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if n, _, err := r.b.ReadFromUDP(buf); err == nil {
			got = buf[:n]
		}
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("B received %x, want the exact datagram %x", got, msg)
	}
	if r.srv.Stats.Forwarded.Load() == 0 {
		t.Fatal("Forwarded counter is zero")
	}
}

func TestDropsBadAndUnroutable(t *testing.T) {
	r := newRig(t)
	r.b.WriteToUDP(wire(t, envelope.Packet{Type: envelope.TypeKeepalive, Session: tokB}), r.addr)

	unknown := wire(t, envelope.Packet{Type: envelope.TypeData, Session: envelope.SessionID{9}, Payload: []byte("x")})
	oversize := make([]byte, readBufSize+100)

	r.a.WriteToUDP([]byte("garbage"), r.addr)
	r.a.WriteToUDP(unknown, r.addr)
	r.a.WriteToUDP(oversize, r.addr)

	// The garbage datagram always counts. On Linux the oversize one counts too;
	// Windows reports a too-small buffer as a read error, which is skipped, so
	// only "at least one" holds on every platform. Either way nothing is forwarded.
	waitFor(t, "format drop", func() bool { return r.srv.Stats.DroppedFormat.Load() >= 1 })
	waitFor(t, "route drop", func() bool { return r.srv.Stats.DroppedRoute.Load() >= 1 })

	// None of that may have reached B.
	r.b.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := r.b.ReadFromUDP(make([]byte, readBufSize)); err == nil {
		t.Fatalf("B received %d bytes that should have been dropped", n)
	}
}

func TestServeStopsOnCancel(t *testing.T) {
	r := newRig(t)
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}
