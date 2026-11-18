package relaybind

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/padmor/linko/protocol/envelope"
	"golang.zx2c4.com/wireguard/conn"
)

func TestBindWrapsAndUnwrapsPackets(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	token := envelope.SessionID{1, 2, 3}
	bind, err := New(relay.LocalAddr().String(), token)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()

	receive, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if port == 0 || len(receive) != 1 {
		t.Fatalf("Open returned port %d and %d receive functions", port, len(receive))
	}

	// Open registers the socket before WireGuard sends a handshake.
	relay.SetReadDeadline(time.Now().Add(time.Second))
	wire := make([]byte, 128)
	n, source, err := relay.ReadFromUDP(wire)
	if err != nil {
		t.Fatalf("read initial keepalive: %v", err)
	}
	registered, err := envelope.Parse(wire[:n])
	if err != nil {
		t.Fatalf("parse initial keepalive: %v", err)
	}
	if registered.Type != envelope.TypeKeepalive || registered.Session != token {
		t.Fatalf("unexpected registration packet: %+v", registered)
	}

	endpoint, err := bind.ParseEndpoint(relay.LocalAddr().String())
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	payload := []byte("wireguard encrypted datagram")
	response, err := envelope.Marshal(nil, envelope.Packet{
		Type:    envelope.TypeData,
		Session: envelope.SessionID{4, 5, 6},
		Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.WriteToUDP(response, source); err != nil {
		t.Fatalf("send relay response: %v", err)
	}

	packets := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	endpoints := make([]conn.Endpoint, 1)
	count, err := receive[0](packets, sizes, endpoints)
	if err != nil {
		t.Fatalf("receive relay response: %v", err)
	}
	if count != 1 || string(packets[0][:sizes[0]]) != string(payload) {
		t.Fatalf("received %d packets and payload %q", count, packets[0][:sizes[0]])
	}
	if endpoints[0].DstToString() != relay.LocalAddr().String() {
		t.Fatalf("endpoint = %q, want %q", endpoints[0].DstToString(), relay.LocalAddr())
	}

	if err := bind.Send([][]byte{payload}, endpoint); err != nil {
		t.Fatalf("send: %v", err)
	}
	relay.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = relay.ReadFromUDP(wire)
	if err != nil {
		t.Fatalf("read wrapped packet: %v", err)
	}
	sent, err := envelope.Parse(wire[:n])
	if err != nil {
		t.Fatalf("parse wrapped packet: %v", err)
	}
	if sent.Type != envelope.TypeData || sent.Session != token || string(sent.Payload) != string(payload) {
		t.Fatalf("unexpected sent packet: %+v", sent)
	}
}

func TestReceiveUnblocksAfterClose(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	bind, err := New(relay.LocalAddr().String(), envelope.SessionID{9})
	if err != nil {
		t.Fatal(err)
	}
	receive, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := receive[0]([][]byte{make([]byte, 128)}, make([]int, 1), make([]conn.Endpoint, 1))
		result <- err
	}()
	if err := bind.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive returned %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("receive did not unblock after Close")
	}
}

func TestParseEndpointRejectsDifferentRelay(t *testing.T) {
	relayA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relayA.Close()
	relayB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relayB.Close()

	bind, err := New(relayA.LocalAddr().String(), envelope.SessionID{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bind.ParseEndpoint(relayB.LocalAddr().String()); err == nil {
		t.Fatal("accepted an endpoint that bypasses the configured relay")
	}
}
