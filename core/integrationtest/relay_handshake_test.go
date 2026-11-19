// Package integrationtest verifies that two WireGuard devices can communicate
// through the real Linko UDP relay without exposing packets to the relay.
package integrationtest

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/padmor/linko/core/internal/relaybind"
	"github.com/padmor/linko/core/internal/tunnel"
	"github.com/padmor/linko/protocol/envelope"
	"github.com/padmor/linko/relay/server"
	"github.com/padmor/linko/relay/session"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

const (
	tunnelAddressA = "10.77.0.1"
	tunnelAddressB = "10.77.0.2"
	handshakeLimit = 10 * time.Second
)

// TestWireGuardHandshakeThroughRelay uses real WireGuard devices, the Linko
// relay server, and in-memory TUN devices. It needs no root access or OS TUN.
func TestWireGuardHandshakeThroughRelay(t *testing.T) {
	relaySocket, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	if err != nil {
		t.Fatalf("listen for relay: %v", err)
	}

	tokenA, err := envelope.NewSessionID()
	if err != nil {
		relaySocket.Close()
		t.Fatalf("create Phone A token: %v", err)
	}
	tokenB, err := envelope.NewSessionID()
	if err != nil {
		relaySocket.Close()
		t.Fatalf("create Phone B token: %v", err)
	}

	table := session.NewTable(120 * time.Second)
	if err := table.Add(tokenA, tokenB); err != nil {
		relaySocket.Close()
		t.Fatalf("register pairing: %v", err)
	}

	relayServer := server.New(relaySocket, table)
	ctx, cancel := context.WithCancel(context.Background())
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- relayServer.Serve(ctx)
	}()

	// The relay is stopped after the WireGuard devices close their sockets.
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-relayDone:
			if err != nil {
				t.Errorf("stop relay: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("relay did not stop after cancellation")
		}
	})

	relayAddress := relaySocket.LocalAddr().String()
	privateA, publicA, err := tunnel.NewKeyPair()
	if err != nil {
		t.Fatalf("create Phone A keys: %v", err)
	}
	privateB, publicB, err := tunnel.NewKeyPair()
	if err != nil {
		t.Fatalf("create Phone B keys: %v", err)
	}

	tunA := tuntest.NewChannelTUN()
	tunB := tuntest.NewChannelTUN()

	bindA, err := relaybind.New(relayAddress, tokenA)
	if err != nil {
		t.Fatalf("create Phone A relay bind: %v", err)
	}
	deviceA, err := tunnel.UpWithBind(tunA.TUN(), tunnel.Config{
		PrivateKey: privateA,
		Peer: tunnel.Peer{
			PublicKey:  publicB,
			AllowedIPs: []string{tunnelAddressB + "/32"},
			Endpoint:   relayAddress,
		},
	}, "phone-a", bindA)
	if err != nil {
		t.Fatalf("start Phone A WireGuard device: %v", err)
	}
	t.Cleanup(deviceA.Close)

	bindB, err := relaybind.New(relayAddress, tokenB)
	if err != nil {
		t.Fatalf("create Phone B relay bind: %v", err)
	}
	deviceB, err := tunnel.UpWithBind(tunB.TUN(), tunnel.Config{
		PrivateKey: privateB,
		Peer: tunnel.Peer{
			PublicKey:  publicA,
			AllowedIPs: []string{tunnelAddressA + "/32"},
			Endpoint:   relayAddress,
		},
	}, "phone-b", bindB)
	if err != nil {
		t.Fatalf("start Phone B WireGuard device: %v", err)
	}
	t.Cleanup(deviceB.Close)

	addressA := netip.MustParseAddr(tunnelAddressA)
	addressB := netip.MustParseAddr(tunnelAddressB)

	// A packet from B has no key yet, so WireGuard must negotiate through
	// the relay before it can deliver the encrypted traffic to A.
	ping := tuntest.Ping(addressA, addressB)
	sendAndReceive(t, tunB.Outbound, tunA.Inbound, ping, "Phone B to Phone A")
	waitForHandshake(t, deviceA, deviceB, relayServer)

	// Send a reply in the other direction using the established keypair.
	reply := tuntest.Ping(addressB, addressA)
	sendAndReceive(t, tunA.Outbound, tunB.Inbound, reply, "Phone A to Phone B")

	if got := relayServer.Stats.Forwarded.Load(); got < 2 {
		t.Fatalf("relay forwarded %d packets, want at least 2", got)
	}
}

func sendAndReceive(t *testing.T, outbound chan<- []byte, inbound <-chan []byte, want []byte, direction string) {
	t.Helper()

	select {
	case outbound <- want:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: WireGuard did not read the outbound TUN packet", direction)
	}

	select {
	case got := <-inbound:
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: received packet differs from the original", direction)
		}
	case <-time.After(handshakeLimit):
		t.Fatalf("%s: packet did not arrive through the relay", direction)
	}
}

// waitForHandshake reads only the public handshake timestamps from UAPI output.
// It deliberately never prints the full configuration, which contains private keys.
func waitForHandshake(t *testing.T, deviceA, deviceB *device.Device, relay *server.Server) {
	t.Helper()
	deadline := time.NewTimer(handshakeLimit)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for {
		completeA, errA := hasCompletedHandshake(deviceA)
		completeB, errB := hasCompletedHandshake(deviceB)
		if errA == nil && errB == nil && completeA && completeB {
			return
		}

		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf(
				"WireGuard handshake did not complete on both endpoints (Phone A: %t, Phone B: %t, relay forwarded: %d, format drops: %d, route drops: %d; UAPI errors: %v, %v)",
				completeA,
				completeB,
				relay.Stats.Forwarded.Load(),
				relay.Stats.DroppedFormat.Load(),
				relay.Stats.DroppedRoute.Load(),
				errA,
				errB,
			)
		}
	}
}

// hasCompletedHandshake reports whether UAPI records a non-zero handshake time.
func hasCompletedHandshake(device *device.Device) (bool, error) {
	state, err := device.IpcGet()
	if err != nil {
		return false, fmt.Errorf("read WireGuard state: %w", err)
	}

	var seconds, nanoseconds int64
	for _, line := range strings.Split(state, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "last_handshake_time_sec":
			seconds, err = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nanoseconds, err = strconv.ParseInt(value, 10, 64)
		default:
			continue
		}
		if err != nil {
			return false, fmt.Errorf("parse handshake timestamp: %w", err)
		}
	}
	return seconds > 0 || nanoseconds > 0, nil
}
