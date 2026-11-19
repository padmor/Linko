package phonea

import (
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
	testLocalAddress = "10.77.0.1"
	testPeerAddress  = "10.77.0.2"
)

func TestStartCompletesRelayHandshakeAndCloses(t *testing.T) {
	relaySocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen for relay: %v", err)
	}

	tokenA, err := envelope.NewSessionID()
	if err != nil {
		relaySocket.Close()
		t.Fatalf("create Phone A session: %v", err)
	}
	tokenB, err := envelope.NewSessionID()
	if err != nil {
		relaySocket.Close()
		t.Fatalf("create Phone B session: %v", err)
	}
	table := session.NewTable(120 * time.Second)
	if err := table.Add(tokenA, tokenB); err != nil {
		relaySocket.Close()
		t.Fatalf("register paired sessions: %v", err)
	}

	relay := server.New(relaySocket, table)
	ctx, cancel := context.WithCancel(context.Background())
	relayDone := make(chan error, 1)
	go func() { relayDone <- relay.Serve(ctx) }()
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

	phone, err := Start(Config{
		PrivateKey:    privateA,
		PeerPublicKey: publicB,
		Session:       tokenA,
		RelayAddress:  relayAddress,
		LocalAddress:  netip.MustParseAddr(testLocalAddress),
		PeerAddress:   netip.MustParseAddr(testPeerAddress),
		MTU:           1280,
	})
	if err != nil {
		t.Fatalf("start Phone A: %v", err)
	}

	peerTun := tuntest.NewChannelTUN()
	bindB, err := relaybind.New(relayAddress, tokenB)
	if err != nil {
		phone.Close()
		t.Fatalf("create Phone B relay bind: %v", err)
	}
	peer, err := tunnel.UpWithBind(peerTun.TUN(), tunnel.Config{
		PrivateKey: privateB,
		Peer: tunnel.Peer{
			PublicKey:  publicA,
			AllowedIPs: []string{testLocalAddress + "/32"},
			Endpoint:   relayAddress,
			Keepalive:  true,
		},
	}, "phone-b-test", bindB)
	if err != nil {
		phone.Close()
		t.Fatalf("start Phone B test peer: %v", err)
	}
	t.Cleanup(peer.Close)
	t.Cleanup(phone.Close)

	waitForHandshake(t, phone.device, peer)
	phone.Close()
	phone.Close()
}

func TestStartRejectsInvalidConfiguration(t *testing.T) {
	private, public, err := tunnel.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := envelope.NewSessionID()
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		PrivateKey:    private,
		PeerPublicKey: public,
		Session:       sessionID,
		RelayAddress:  "127.0.0.1:51820",
		LocalAddress:  netip.MustParseAddr(testLocalAddress),
		PeerAddress:   netip.MustParseAddr(testPeerAddress),
		MTU:           1280,
	}
	cfg.MTU = 0
	if _, err := Start(cfg); err == nil {
		t.Fatal("Start accepted an invalid MTU")
	}
}

func waitForHandshake(t *testing.T, a, b *device.Device) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for {
		completeA, errA := hasHandshake(a)
		completeB, errB := hasHandshake(b)
		if errA == nil && errB == nil && completeA && completeB {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("WireGuard handshake did not complete (Phone A: %t, Phone B: %t; errors: %v, %v)", completeA, completeB, errA, errB)
		}
	}
}

func hasHandshake(dev *device.Device) (bool, error) {
	state, err := dev.IpcGet()
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
		}
		if err != nil {
			return false, fmt.Errorf("parse handshake timestamp: %w", err)
		}
	}
	return seconds > 0 || nanoseconds > 0, nil
}
