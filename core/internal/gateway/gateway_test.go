package gateway

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestCheckDestinationCountsBlockedAddresses(t *testing.T) {
	g := &Gateway{}

	if err := g.checkDestination("192.168.1.20"); err == nil {
		t.Fatal("private destination was allowed")
	}
	if got := g.Stats().BlockedDestinations; got != 1 {
		t.Fatalf("blocked destinations = %d, want 1", got)
	}

	if err := g.checkDestination("not-an-ip"); err == nil {
		t.Fatal("invalid destination was allowed")
	}
	if got := g.Stats().BlockedDestinations; got != 2 {
		t.Fatalf("blocked destinations = %d, want 2", got)
	}
}

func TestCheckDestinationAllowsOnlyConfiguredProofHost(t *testing.T) {
	allowed := netip.MustParseAddr("192.168.1.20")
	g := &Gateway{proofDestination: allowed}

	if err := g.checkDestination(allowed.String()); err != nil {
		t.Fatalf("configured proof destination was rejected: %v", err)
	}
	if got := g.Stats().BlockedDestinations; got != 0 {
		t.Fatalf("blocked destinations = %d, want 0", got)
	}

	if err := g.checkDestination("192.168.1.21"); err == nil {
		t.Fatal("a different private destination was allowed")
	}
	if got := g.Stats().BlockedDestinations; got != 1 {
		t.Fatalf("blocked destinations = %d, want 1", got)
	}
}

func TestDialContextCountsFailures(t *testing.T) {
	wantErr := errors.New("connection refused")
	g := &Gateway{
		dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, wantErr
		}),
	}

	_, err := g.dialContext(context.Background(), "tcp", "203.0.113.10:443")
	if !errors.Is(err, wantErr) {
		t.Fatalf("dial error = %v, want wrapped cause %v", err, wantErr)
	}
	if got := g.Stats().DialFailures; got != 1 {
		t.Fatalf("dial failures = %d, want 1", got)
	}
}

func TestStatsReturnsNumericSnapshot(t *testing.T) {
	g := &Gateway{}
	g.stats.blockedDestinations.Store(2)
	g.stats.dialFailures.Store(3)
	g.stats.endpointFailures.Store(4)

	got := g.Stats()
	if got != (Stats{
		BlockedDestinations: 2,
		DialFailures:        3,
		EndpointFailures:    4,
	}) {
		t.Fatalf("stats snapshot = %+v, want all three counters", got)
	}

	// A previously returned snapshot must not change when counters move on.
	g.stats.endpointFailures.Add(1)
	if got.EndpointFailures != 4 {
		t.Fatalf("previous snapshot changed after update: %+v", got)
	}
}
