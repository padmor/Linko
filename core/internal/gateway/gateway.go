// Package gateway is the exit side of Linko (Phone A).
//
// Packets from Phone B arrive decrypted in a gVisor stack. For every new TCP
// connection or UDP flow the gateway opens a real socket to the same
// destination after applying the destination policy, then copies bytes both
// ways. The stack sees every destination because it runs in promiscuous mode
// and may spoof source addresses (it answers as the server the client thinks
// it is talking to).
package gateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/padmor/linko/core/internal/gatewaytun"
)

const (
	// maxInFlightTCP caps half-open connections the stack tracks at once.
	maxInFlightTCP = 1024
	// dialTimeout bounds how long a client waits while we reach the real server.
	dialTimeout = 10 * time.Second
	// udpIdleTimeout closes a UDP flow that has been silent this long.
	udpIdleTimeout = 30 * time.Second
	// udpMaxDatagram is the largest UDP payload we read in one go.
	udpMaxDatagram = 65535
)

// Stats is a point-in-time snapshot of gateway forwarding diagnostics.
// It contains counters only; it never includes addresses, keys, tokens or payloads.
type Stats struct {
	BlockedDestinations uint64
	DialFailures        uint64
	EndpointFailures    uint64
}

type gatewayCounters struct {
	blockedDestinations atomic.Uint64
	dialFailures        atomic.Uint64
	endpointFailures    atomic.Uint64
}

type contextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Gateway forwards tunnel traffic to the real network.
type Gateway struct {
	stack            *stack.Stack
	dialer           contextDialer
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	proofDestination netip.Addr
	stats            gatewayCounters
}

// New wires the forwarders into s. Call Close to stop all flows.
func New(s *stack.Stack) (*Gateway, error) {
	return newGateway(s, netip.Addr{})
}

// NewForProof permits one explicitly supplied private IPv4 address for the
// local performance-proof server. It must never be used by a running gateway.
func NewForProof(s *stack.Stack, allowedDestination netip.Addr) (*Gateway, error) {
	if !allowedDestination.Is4() || !allowedDestination.IsPrivate() {
		return nil, fmt.Errorf("gateway: proof destination must be a private IPv4 address")
	}
	return newGateway(s, allowedDestination)
}

func newGateway(s *stack.Stack, proofDestination netip.Addr) (*Gateway, error) {
	ctx, cancel := context.WithCancel(context.Background())
	g := &Gateway{
		stack:            s,
		dialer:           &net.Dialer{Timeout: dialTimeout},
		ctx:              ctx,
		cancel:           cancel,
		proofDestination: proofDestination,
	}

	// Accept packets for any destination and answer as that destination.
	if err := s.SetPromiscuousMode(gatewaytun.NICID, true); err != nil {
		cancel()
		return nil, tcpipError("promiscuous mode", err)
	}
	if err := s.SetSpoofing(gatewaytun.NICID, true); err != nil {
		cancel()
		return nil, tcpipError("spoofing", err)
	}

	tcpForwarder := tcp.NewForwarder(s, 0, maxInFlightTCP, g.onTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(s, g.onUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	return g, nil
}

// Stats returns a race-safe snapshot of forwarding diagnostics.
func (g *Gateway) Stats() Stats {
	return Stats{
		BlockedDestinations: g.stats.blockedDestinations.Load(),
		DialFailures:        g.stats.dialFailures.Load(),
		EndpointFailures:    g.stats.endpointFailures.Load(),
	}
}

// Close stops every flow and waits for the copy loops to end.
func (g *Gateway) Close() {
	g.cancel()
	g.wg.Wait()
}

// checkDestination applies the normal policy, except for the exact private
// host explicitly allowed by the local proof harness.
func (g *Gateway) checkDestination(value string) error {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		g.stats.blockedDestinations.Add(1)
		return fmt.Errorf("invalid destination address %q: %w", value, err)
	}
	addr = addr.Unmap()
	if g.proofDestination.IsValid() && addr == g.proofDestination {
		return nil
	}
	if err := validateDestination(addr); err != nil {
		g.stats.blockedDestinations.Add(1)
		return err
	}
	return nil
}

// dialContext records failed upstream connection attempts without logging
// destination addresses or any request data.
func (g *Gateway) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := g.dialer.DialContext(ctx, network, address)
	if err != nil {
		g.stats.dialFailures.Add(1)
	}
	return conn, err
}

// destination returns the "ip:port" the client was trying to reach.
func destination(id stack.TransportEndpointID) string {
	return net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
}

// onTCP is called by the stack for every new TCP connection attempt.
func (g *Gateway) onTCP(req *tcp.ForwarderRequest) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		g.serveTCP(req)
	}()
}

func (g *Gateway) serveTCP(req *tcp.ForwarderRequest) {
	// Reject private and special-use destinations before opening a real socket.
	if err := g.checkDestination(req.ID().LocalAddress.String()); err != nil {
		req.Complete(true)
		return
	}

	// Reach the real server first, so a failed dial resets the client at once
	// instead of leaving it with a connection that dies silently.
	upstream, err := g.dialContext(g.ctx, "tcp", destination(req.ID()))
	if err != nil {
		req.Complete(true)
		return
	}
	defer upstream.Close()

	var wq waiter.Queue
	ep, tcpErr := req.CreateEndpoint(&wq)
	if tcpErr != nil {
		g.stats.endpointFailures.Add(1)
		req.Complete(true)
		return
	}
	req.Complete(false)

	client := gonet.NewTCPConn(&wq, ep)
	defer client.Close()

	g.pipeTCP(client, upstream.(*net.TCPConn))
}

// pipeTCP copies both directions until each side finishes, passing half-closes
// along so the far end sees EOF at the right time.
func (g *Gateway) pipeTCP(client *gonet.TCPConn, upstream *net.TCPConn) {
	// Unblock the copies if the gateway is shutting down.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-g.ctx.Done():
			client.Close()
			upstream.Close()
		case <-done:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upstream, client) // client -> internet
		upstream.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, upstream) // internet -> client
		client.CloseWrite()
	}()
	wg.Wait()
}

// onUDP is called by the stack for every new UDP flow (DNS, QUIC, ...).
func (g *Gateway) onUDP(req *udp.ForwarderRequest) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		g.serveUDP(req)
	}()
}

func (g *Gateway) serveUDP(req *udp.ForwarderRequest) {
	// Apply the same policy as TCP before opening a real socket.
	if err := g.checkDestination(req.ID().LocalAddress.String()); err != nil {
		return
	}

	upstream, err := g.dialContext(g.ctx, "udp", destination(req.ID()))
	if err != nil {
		return
	}
	defer upstream.Close()

	var wq waiter.Queue
	ep, tcpErr := req.CreateEndpoint(&wq)
	if tcpErr != nil {
		g.stats.endpointFailures.Add(1)
		return
	}
	client := gonet.NewUDPConn(&wq, ep)
	defer client.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-g.ctx.Done():
			client.Close()
			upstream.Close()
		case <-done:
		}
	}()

	// Each direction ends when it has been idle for udpIdleTimeout. Whichever
	// ends first closes both sockets, which ends the other direction too.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		relayDatagrams(upstream, client) // client -> internet
		upstream.Close()
		client.Close()
	}()
	go func() {
		defer wg.Done()
		relayDatagrams(client, upstream) // internet -> client
		upstream.Close()
		client.Close()
	}()
	wg.Wait()
}

// relayDatagrams reads datagrams from src and writes them to dst until src
// has been quiet for udpIdleTimeout or either side errors.
func relayDatagrams(dst, src net.Conn) {
	buf := make([]byte, udpMaxDatagram)
	for {
		src.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return
		}
	}
}

// tcpipError turns a gVisor error value into a normal Go error.
func tcpipError(what string, err tcpip.Error) error {
	return &stackError{what: what, err: err}
}

type stackError struct {
	what string
	err  tcpip.Error
}

func (e *stackError) Error() string { return "gateway: " + e.what + ": " + e.err.String() }
