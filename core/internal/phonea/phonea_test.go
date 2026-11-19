package phonea

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/padmor/linko/core/internal/relaybind"
	"github.com/padmor/linko/core/internal/tunnel"
	"github.com/padmor/linko/protocol/envelope"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

const (
	testLocalAddress = "10.77.0.1"
	testPeerAddress  = "10.77.0.2"
)

func TestStartCompletesRelayHandshakeAndCloses(t *testing.T) {
	tokenA, err := envelope.NewSessionID()
	if err != nil {
		t.Fatalf("create Phone A session: %v", err)
	}
	tokenB, err := envelope.NewSessionID()
	if err != nil {
		t.Fatalf("create Phone B session: %v", err)
	}
	relayAddress, stopRelay := startTestRelay(t, tokenA, tokenB)
	t.Cleanup(stopRelay)

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
		MTU:           0,
	}
	if _, err := Start(cfg); err == nil {
		t.Fatal("Start accepted an invalid MTU")
	}
}

func startTestRelay(t *testing.T, tokenA, tokenB envelope.SessionID) (string, func()) {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen for test relay: %v", err)
	}

	addresses := make(map[envelope.SessionID]*net.UDPAddr, 2)
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		for {
			n, source, err := socket.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			packet, err := envelope.Parse(buffer[:n])
			if err != nil {
				continue
			}

			mu.Lock()
			addresses[packet.Session] = source
			var destination *net.UDPAddr
			switch packet.Session {
			case tokenA:
				destination = addresses[tokenB]
			case tokenB:
				destination = addresses[tokenA]
			}
			mu.Unlock()

			if packet.Type == envelope.TypeData && destination != nil {
				_, _ = socket.WriteToUDP(buffer[:n], destination)
			}
		}
	}()

	return socket.LocalAddr().String(), func() {
		_ = socket.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("test relay did not stop")
		}
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
