// Package relaybind adapts Linko's UDP relay protocol to WireGuard's conn.Bind.
package relaybind

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/padmor/linko/protocol/envelope"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	keepaliveInterval = 25 * time.Second
	maxDatagramSize   = 65535
)

// Bind sends WireGuard datagrams through one Linko relay endpoint.
type Bind struct {
	relayAddr netip.AddrPort
	token     envelope.SessionID

	mu          sync.Mutex
	socket      *net.UDPConn
	stop        chan struct{}
	keepaliveWG sync.WaitGroup
}

// New resolves and validates the relay address for this endpoint.
func New(relayAddress string, token envelope.SessionID) (*Bind, error) {
	relay, err := resolveAddress(relayAddress)
	if err != nil {
		return nil, fmt.Errorf("relaybind: resolve relay: %w", err)
	}
	if relay.Port() == 0 {
		return nil, errors.New("relaybind: relay port must be non-zero")
	}
	return &Bind{relayAddr: relay, token: token}, nil
}

// resolveAddress accepts IP addresses and DNS names, then stores a numeric endpoint.
func resolveAddress(address string) (netip.AddrPort, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if udpAddr.IP == nil {
		return netip.AddrPort{}, errors.New("address did not resolve to an IP")
	}
	addr := udpAddr.AddrPort()
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), nil
}

// Open connects one UDP socket to the relay and registers this endpoint's address.
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.socket != nil {
		return nil, 0, errors.New("relaybind: already open")
	}

	network := "udp6"
	if b.relayAddr.Addr().Is4() {
		network = "udp4"
	}
	socket, err := net.DialUDP(network, &net.UDPAddr{Port: int(port)}, net.UDPAddrFromAddrPort(b.relayAddr))
	if err != nil {
		return nil, 0, fmt.Errorf("relaybind: open UDP socket: %w", err)
	}

	// Register before WireGuard can send its first handshake packet.
	if err := writeKeepalive(socket, b.token); err != nil {
		socket.Close()
		return nil, 0, fmt.Errorf("relaybind: register with relay: %w", err)
	}

	local, ok := socket.LocalAddr().(*net.UDPAddr)
	if !ok {
		socket.Close()
		return nil, 0, errors.New("relaybind: unexpected local address type")
	}

	stop := make(chan struct{})
	b.socket = socket
	b.stop = stop
	b.keepaliveWG.Add(1)
	go b.keepaliveLoop(socket, stop)

	return []conn.ReceiveFunc{b.receive}, uint16(local.Port), nil
}

// keepaliveLoop refreshes the relay's address mapping while the tunnel is idle.
func (b *Bind) keepaliveLoop(socket *net.UDPConn, stop <-chan struct{}) {
	defer b.keepaliveWG.Done()
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// A temporary network failure is retried on the next interval.
			_ = writeKeepalive(socket, b.token)
		case <-stop:
			return
		}
	}
}

// writeKeepalive registers or refreshes this endpoint at the relay.
func writeKeepalive(socket *net.UDPConn, token envelope.SessionID) error {
	packet, err := envelope.Marshal(nil, envelope.Packet{
		Type:    envelope.TypeKeepalive,
		Session: token,
	})
	if err != nil {
		return err
	}
	_, err = socket.Write(packet)
	return err
}

// Close stops keepalives and unblocks any pending receive call.
func (b *Bind) Close() error {
	b.mu.Lock()
	socket := b.socket
	stop := b.stop
	if socket == nil {
		b.mu.Unlock()
		return nil
	}
	b.socket = nil
	b.stop = nil
	close(stop)
	b.mu.Unlock()

	err := socket.Close()
	b.keepaliveWG.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// SetMark is a no-op for mark zero. This portable desktop transport cannot apply non-zero marks.
func (b *Bind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("relaybind: non-zero socket marks are not supported")
	}
	return nil
}

// Send wraps each WireGuard datagram and sends it to the configured relay.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	destination, ok := ep.(*endpoint)
	if !ok || destination.addr != b.relayAddr {
		return conn.ErrWrongEndpointType
	}
	if len(bufs) > b.BatchSize() {
		return fmt.Errorf("relaybind: batch has %d packets; maximum is %d", len(bufs), b.BatchSize())
	}

	b.mu.Lock()
	socket := b.socket
	b.mu.Unlock()
	if socket == nil {
		return net.ErrClosed
	}

	for _, payload := range bufs {
		packet, err := envelope.Marshal(make([]byte, 0, envelope.HeaderSize+len(payload)), envelope.Packet{
			Type:    envelope.TypeData,
			Session: b.token,
			Payload: payload,
		})
		if err != nil {
			return err
		}
		n, err := socket.Write(packet)
		if err != nil {
			return fmt.Errorf("relaybind: send packet: %w", err)
		}
		if n != len(packet) {
			return fmt.Errorf("relaybind: send packet: %w", io.ErrShortWrite)
		}
	}
	return nil
}

// receive removes the Linko envelope before passing a packet to WireGuard.
func (b *Bind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
		return 0, errors.New("relaybind: WireGuard supplied empty receive buffers")
	}

	b.mu.Lock()
	socket := b.socket
	b.mu.Unlock()
	if socket == nil {
		return 0, net.ErrClosed
	}

	buffer := make([]byte, maxDatagramSize)
	for {
		n, err := socket.Read(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return 0, net.ErrClosed
			}
			return 0, err
		}

		packet, err := envelope.Parse(buffer[:n])
		if err != nil || packet.Type != envelope.TypeData {
			// Keepalives are local to the relay and malformed envelopes are dropped.
			continue
		}
		if len(packet.Payload) > len(packets[0]) {
			continue
		}

		sizes[0] = copy(packets[0], packet.Payload)
		eps[0] = &endpoint{addr: b.relayAddr}
		return 1, nil
	}
}

// ParseEndpoint accepts only the relay configured in New.
func (b *Bind) ParseEndpoint(address string) (conn.Endpoint, error) {
	parsed, err := resolveAddress(address)
	if err != nil {
		return nil, fmt.Errorf("relaybind: parse endpoint: %w", err)
	}
	if parsed != b.relayAddr {
		return nil, errors.New("relaybind: peer endpoint must be the configured relay")
	}
	return &endpoint{addr: parsed}, nil
}

// BatchSize keeps the first proof simple: one datagram per receive operation.
func (b *Bind) BatchSize() int { return 1 }

// endpoint is WireGuard's view of the relay as the peer's network destination.
type endpoint struct {
	addr netip.AddrPort
}

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "" }
func (e *endpoint) DstToString() string { return e.addr.String() }
func (e *endpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *endpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (e *endpoint) DstToBytes() []byte {
	value, _ := e.addr.MarshalBinary()
	return value
}

var (
	_ conn.Bind     = (*Bind)(nil)
	_ conn.Endpoint = (*endpoint)(nil)
)
