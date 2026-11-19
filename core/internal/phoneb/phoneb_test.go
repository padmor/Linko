package phoneb

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/padmor/linko/core/internal/phonea"
	"github.com/padmor/linko/core/internal/tunnel"
	"github.com/padmor/linko/protocol/envelope"
)

const (
	testPhoneAAddress = "10.77.0.1"
	testPhoneBAddress = "10.77.0.2"
	testMTU           = 1280
)

func TestStartCompletesRelayHandshakeAndCloses(t *testing.T) {
	sessionA, err := envelope.NewSessionID()
	if err != nil {
		t.Fatalf("create Phone A session: %v", err)
	}
	sessionB, err := envelope.NewSessionID()
	if err != nil {
		t.Fatalf("create Phone B session: %v", err)
	}

	relayAddress, stopRelay := startTestRelay(t, sessionA, sessionB)
	t.Cleanup(stopRelay)

	privateA, publicA, err := tunnel.NewKeyPair()
	if err != nil {
		t.Fatalf("create Phone A keys: %v", err)
	}
	privateB, publicB, err := tunnel.NewKeyPair()
	if err != nil {
		t.Fatalf("create Phone B keys: %v", err)
	}

	phoneA, err := phonea.Start(phonea.Config{
		PrivateKey:    privateA,
		PeerPublicKey: publicB,
		Session:       sessionA,
		RelayAddress:  relayAddress,
		LocalAddress:  netip.MustParseAddr(testPhoneAAddress),
		PeerAddress:   netip.MustParseAddr(testPhoneBAddress),
		MTU:           testMTU,
	})
	if err != nil {
		t.Fatalf("start Phone A: %v", err)
	}

	phoneB, err := Start(Config{
		PrivateKey:    privateB,
		PeerPublicKey: publicA,
		Session:       sessionB,
		RelayAddress:  relayAddress,
		LocalAddress:  netip.MustParseAddr(testPhoneBAddress),
		PeerAddress:   netip.MustParseAddr(testPhoneAAddress),
		DNSAddress:    netip.MustParseAddr(testPhoneAAddress),
		MTU:           testMTU,
	})
	if err != nil {
		phoneA.Close()
		t.Fatalf("start Phone B: %v", err)
	}
	t.Cleanup(phoneA.Close)
	t.Cleanup(phoneB.Close)

	if phoneB.HTTPClient() == nil {
		t.Fatal("Phone B did not expose its tunnel-backed HTTP client")
	}

	waitForHandshake(t, phoneB.device)
	state, err := phoneB.device.IpcGet()
	if err != nil {
		t.Fatalf("read Phone B WireGuard configuration: %v", err)
	}
	if !strings.Contains(state, "allowed_ip=0.0.0.0/0") {
		t.Fatalf("Phone B does not route the IPv4 default route through Phone A:\n%s", state)
	}

	phoneB.Close()
	phoneB.Close()
	phoneA.Close()
	phoneA.Close()
}

func TestStartRejectsInvalidConfiguration(t *testing.T) {
	private, public, err := tunnel.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	session, err := envelope.NewSessionID()
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		PrivateKey:    private,
		PeerPublicKey: public,
		Session:       session,
		RelayAddress:  "127.0.0.1:51820",
		LocalAddress:  netip.MustParseAddr(testPhoneBAddress),
		PeerAddress:   netip.MustParseAddr(testPhoneAAddress),
		DNSAddress:    netip.MustParseAddr(testPhoneAAddress),
		MTU:           0,
	}
	if _, err := Start(cfg); err == nil {
		t.Fatal("Start accepted an invalid MTU")
	}

	cfg.MTU = testMTU
	cfg.DNSAddress = netip.Addr{}
	if _, err := Start(cfg); err == nil {
		t.Fatal("Start accepted a missing DNS address")
	}
}

func startTestRelay(t *testing.T, sessionA, sessionB envelope.SessionID) (string, func()) {
	t.Helper()

	socket, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
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
			n, source, readErr := socket.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}

			packet, parseErr := envelope.Parse(buffer[:n])
			if parseErr != nil {
				continue
			}

			mu.Lock()
			addresses[packet.Session] = source
			var destination *net.UDPAddr
			switch packet.Session {
			case sessionA:
				destination = addresses[sessionB]
			case sessionB:
				destination = addresses[sessionA]
			}
			mu.Unlock()

			if packet.Type == envelope.TypeData && destination != nil {
				// Copy before the next read reuses buffer.
				out := append([]byte(nil), buffer[:n]...)
				_, _ = socket.WriteToUDP(out, destination)
			}
		}
	}()

	stop := func() {
		_ = socket.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("test relay did not stop")
		}
	}
	return socket.LocalAddr().String(), stop
}

func waitForHandshake(t *testing.T, dev interface {
	IpcGet() (string, error)
}) {
	t.Helper()

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for {
		state, err := dev.IpcGet()
		if err == nil && handshakeRecorded(state) {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("WireGuard handshake did not complete; last state error: %v", err)
		}
	}
}

func handshakeRecorded(state string) bool {
	var seconds, nanoseconds int64
	for _, line := range strings.Split(state, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		switch key {
		case "last_handshake_time_sec":
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return false
			}
			seconds = parsed
		case "last_handshake_time_nsec":
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return false
			}
			nanoseconds = parsed
		}
	}
	return seconds > 0 || nanoseconds > 0
}
