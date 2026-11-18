package session

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/padmor/linko/relay/envelope"
)

const idle = 120 * time.Second

var (
	tokA  = envelope.SessionID{1}
	tokB  = envelope.SessionID{2}
	addrA = netip.MustParseAddrPort("10.0.0.1:1111")
	addrB = netip.MustParseAddrPort("10.0.0.2:2222")
)

// fakeClock lets tests move time by hand.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestTable(t *testing.T) (*Table, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	tbl := NewTable(idle)
	tbl.now = clk.now
	if err := tbl.Add(tokA, tokB); err != nil {
		t.Fatal(err)
	}
	return tbl, clk
}

func data(tok envelope.SessionID) envelope.Packet {
	return envelope.Packet{Type: envelope.TypeData, Session: tok, Payload: []byte("x")}
}

func keepalive(tok envelope.SessionID) envelope.Packet {
	return envelope.Packet{Type: envelope.TypeKeepalive, Session: tok}
}

func TestForwardsBothWays(t *testing.T) {
	tbl, _ := newTestTable(t)

	// B announces itself with a keepalive, then A sends data.
	tbl.Route(keepalive(tokB), addrB)
	to, ok := tbl.Route(data(tokA), addrA)
	if !ok || to != addrB {
		t.Fatalf("A->B: got %v, %v; want %v, true", to, ok, addrB)
	}
	to, ok = tbl.Route(data(tokB), addrB)
	if !ok || to != addrA {
		t.Fatalf("B->A: got %v, %v; want %v, true", to, ok, addrA)
	}
}

func TestDropsUnknownToken(t *testing.T) {
	tbl, _ := newTestTable(t)
	if _, ok := tbl.Route(data(envelope.SessionID{9}), addrA); ok {
		t.Fatal("packet with an unknown token was forwarded")
	}
}

func TestKeepaliveRegistersButDoesNotForward(t *testing.T) {
	tbl, _ := newTestTable(t)
	tbl.Route(keepalive(tokB), addrB)
	if _, ok := tbl.Route(keepalive(tokA), addrA); ok {
		t.Fatal("keepalive was forwarded")
	}
	// B's keepalive must still have registered B's address.
	if to, ok := tbl.Route(data(tokA), addrA); !ok || to != addrB {
		t.Fatalf("got %v, %v; want %v, true", to, ok, addrB)
	}
}

func TestDropsWhenPartnerUnknown(t *testing.T) {
	tbl, _ := newTestTable(t)
	if _, ok := tbl.Route(data(tokA), addrA); ok {
		t.Fatal("forwarded although B never sent anything")
	}
}

func TestRoamingFollowsNewAddress(t *testing.T) {
	tbl, _ := newTestTable(t)
	tbl.Route(keepalive(tokA), addrA)
	tbl.Route(keepalive(tokB), addrB)

	// B moves from Wi-Fi to mobile data: same token, new address.
	newB := netip.MustParseAddrPort("172.16.0.9:3333")
	tbl.Route(data(tokB), newB)

	if to, ok := tbl.Route(data(tokA), addrA); !ok || to != newB {
		t.Fatalf("got %v, %v; want %v, true", to, ok, newB)
	}
}

func TestIdlePartnerIsNotForwardedTo(t *testing.T) {
	tbl, clk := newTestTable(t)
	tbl.Route(keepalive(tokB), addrB)
	clk.advance(idle + time.Second)
	if _, ok := tbl.Route(data(tokA), addrA); ok {
		t.Fatal("forwarded to a partner that has been silent too long")
	}
}

func TestIdleBoundaryIsInclusive(t *testing.T) {
	tbl, clk := newTestTable(t)
	tbl.Route(keepalive(tokB), addrB)
	clk.advance(idle) // exactly the timeout: still alive
	if _, ok := tbl.Route(data(tokA), addrA); !ok {
		t.Fatal("partner dropped at exactly the idle timeout")
	}
}

func TestExpireClearsStaleAddresses(t *testing.T) {
	tbl, clk := newTestTable(t)
	tbl.Route(keepalive(tokA), addrA)
	clk.advance(idle / 2)
	tbl.Route(keepalive(tokB), addrB)
	clk.advance(idle/2 + time.Second) // A is stale, B is fresh

	if n := tbl.Expire(); n != 1 {
		t.Fatalf("Expire cleared %d, want 1", n)
	}
	if n := tbl.Expire(); n != 0 {
		t.Fatalf("second Expire cleared %d, want 0", n)
	}
}

func TestRemoveEndsPairing(t *testing.T) {
	tbl, _ := newTestTable(t)
	tbl.Route(keepalive(tokB), addrB)

	if !tbl.Remove(tokA) {
		t.Fatal("Remove found nothing")
	}
	if _, ok := tbl.Route(data(tokA), addrA); ok {
		t.Fatal("token A still works after Remove")
	}
	if _, ok := tbl.Route(data(tokB), addrB); ok {
		t.Fatal("token B still works after Remove")
	}
	if tbl.Remove(tokB) {
		t.Fatal("second Remove reported success")
	}
}

func TestAddRejects(t *testing.T) {
	tbl, _ := newTestTable(t)
	other := envelope.SessionID{7}
	tests := []struct {
		name string
		a, b envelope.SessionID
		want error
	}{
		{"same token", other, other, ErrSameToken},
		{"first already used", tokA, other, ErrExists},
		{"second already used", other, tokB, ErrExists},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tbl.Add(tc.a, tc.b); err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	// A rejected Add must not leave a half-registered pairing behind.
	if _, ok := tbl.Route(data(other), addrA); ok {
		t.Fatal("rejected Add left a usable token")
	}
}

// Run with -race: many goroutines routing and expiring at once.
func TestConcurrentUse(t *testing.T) {
	tbl, _ := newTestTable(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				tbl.Route(data(tokA), addrA)
				tbl.Route(data(tokB), addrB)
				tbl.Expire()
			}
		}()
	}
	wg.Wait()
}
