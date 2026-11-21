package phonea

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/padmor/linko/core/internal/phoneb"
	"github.com/padmor/linko/core/internal/tunnel"
	"github.com/padmor/linko/protocol/envelope"
)

const (
	// wireGuardTransportData is WireGuard's message type for encrypted
	// transport packets. Handshake messages use different message types.
	wireGuardTransportData = 4
	plaintextProofMarker   = "LINKO-PLAINTEXT-PROOF-BOX6-9d4c7a2e"
)

// TestRelayCaptureContainsCiphertext proves that an ordinary HTTP request
// reaches Phone A while the relay capture contains only Linko envelopes
// carrying WireGuard packets, never the request's plaintext marker.
func TestRelayCaptureContainsCiphertext(t *testing.T) {
	serverAddress := localPrivateIPv4(t)
	destination, err := netip.ParseAddr(serverAddress)
	if err != nil {
		t.Fatalf("parse local HTTP server address: %v", err)
	}

	received := make(chan []byte, 1)
	pageServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				http.Error(w, "could not read request", http.StatusBadRequest)
				return
			}
			received <- body
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "request received")
		}),
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(serverAddress, "0"))
	if err != nil {
		t.Fatalf("listen on local test address %s: %v", serverAddress, err)
	}
	go func() {
		_ = pageServer.Serve(listener)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = pageServer.Shutdown(ctx)
	})

	sessionA, err := envelope.NewSessionID()
	if err != nil {
		t.Fatalf("create Phone A session: %v", err)
	}
	sessionB, err := envelope.NewSessionID()
	if err != nil {
		t.Fatalf("create Phone B session: %v", err)
	}
	relayAddress, capture, stopRelay := startCaptureRelay(t, sessionA, sessionB)
	t.Cleanup(stopRelay)

	privateA, publicA, err := tunnel.NewKeyPair()
	if err != nil {
		t.Fatalf("create Phone A keys: %v", err)
	}
	privateB, publicB, err := tunnel.NewKeyPair()
	if err != nil {
		t.Fatalf("create Phone B keys: %v", err)
	}

	phoneA, err := startForProof(Config{
		PrivateKey:    privateA,
		PeerPublicKey: publicB,
		Session:       sessionA,
		RelayAddress:  relayAddress,
		LocalAddress:  netip.MustParseAddr(testLocalAddress),
		PeerAddress:   netip.MustParseAddr(testPeerAddress),
		MTU:           1280,
	}, destination)
	if err != nil {
		t.Fatalf("start Phone A proof gateway: %v", err)
	}
	t.Cleanup(phoneA.Close)

	phoneB, err := phoneb.Start(phoneb.Config{
		PrivateKey:    privateB,
		PeerPublicKey: publicA,
		Session:       sessionB,
		RelayAddress:  relayAddress,
		LocalAddress:  netip.MustParseAddr(testPeerAddress),
		PeerAddress:   netip.MustParseAddr(testLocalAddress),
		DNSAddress:    netip.MustParseAddr(testLocalAddress),
		MTU:           1280,
	})
	if err != nil {
		t.Fatalf("start Phone B: %v", err)
	}
	t.Cleanup(phoneB.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://"+listener.Addr().String()+"/ciphertext-proof",
		bytes.NewBufferString(plaintextProofMarker),
	)
	if err != nil {
		t.Fatalf("create HTTP proof request: %v", err)
	}
	request.Header.Set("Content-Type", "text/plain")

	response, err := phoneB.HTTPClient().Do(request)
	if err != nil {
		t.Fatalf("send HTTP request through Phone B tunnel: %v", err)
	}
	responseBody, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatalf("read HTTP response: %v", readErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTP page returned %s: %s", response.Status, responseBody)
	}

	select {
	case body := <-received:
		if string(body) != plaintextProofMarker {
			t.Fatalf("Phone A received %q, want the original request marker", body)
		}
	case <-ctx.Done():
		t.Fatal("Phone A did not receive the original HTTP request")
	}

	datagrams := capture.snapshot()
	if len(datagrams) == 0 {
		t.Fatal("relay captured no data datagrams")
	}

	var sawTransportData bool
	var joinedCapture []byte
	for i, datagram := range datagrams {
		packet, parseErr := envelope.Parse(datagram)
		if parseErr != nil {
			t.Fatalf("captured datagram %d is not a valid Linko envelope: %v", i, parseErr)
		}
		if packet.Type != envelope.TypeData {
			t.Fatalf("captured datagram %d has packet type %d, want data", i, packet.Type)
		}
		if bytes.Contains(datagram, []byte(plaintextProofMarker)) {
			t.Fatalf("relay capture exposed the plaintext marker in datagram %d", i)
		}
		joinedCapture = append(joinedCapture, datagram...)
		if len(packet.Payload) >= 4 && binary.LittleEndian.Uint32(packet.Payload[:4]) == wireGuardTransportData {
			sawTransportData = true
		}
	}

	if bytes.Contains(joinedCapture, []byte(plaintextProofMarker)) {
		t.Fatal("relay capture contains the plaintext marker across captured datagrams")
	}
	if !sawTransportData {
		t.Fatal("relay capture contains no WireGuard encrypted transport-data packet")
	}

	t.Logf("Phone A received the plaintext HTTP marker; relay captured %d WireGuard data datagrams without exposing it", len(datagrams))
}

type relayCapture struct {
	mu        sync.Mutex
	datagrams [][]byte
}

func (c *relayCapture) add(datagram []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.datagrams = append(c.datagrams, append([]byte(nil), datagram...))
}

func (c *relayCapture) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([][]byte, len(c.datagrams))
	for i, datagram := range c.datagrams {
		out[i] = append([]byte(nil), datagram...)
	}
	return out
}

// startCaptureRelay is a small local relay fixture. It applies the same
// session-token routing rule as the production relay while recording the
// exact UDP datagrams at the relay boundary before forwarding them unchanged.
func startCaptureRelay(t *testing.T, sessionA, sessionB envelope.SessionID) (string, *relayCapture, func()) {
	t.Helper()

	socket, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	if err != nil {
		t.Fatalf("listen for capture relay: %v", err)
	}

	addresses := make(map[envelope.SessionID]*net.UDPAddr, 2)
	capture := &relayCapture{}
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

			addresses[packet.Session] = source
			var destination *net.UDPAddr
			switch packet.Session {
			case sessionA:
				destination = addresses[sessionB]
			case sessionB:
				destination = addresses[sessionA]
			}

			if packet.Type != envelope.TypeData {
				continue
			}

			raw := append([]byte(nil), buffer[:n]...)
			capture.add(raw)
			if destination != nil {
				if _, writeErr := socket.WriteToUDP(raw, destination); writeErr != nil {
					// A peer may close as the test is cleaning up.
					continue
				}
			}
		}
	}()

	stop := func() {
		_ = socket.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("capture relay did not stop")
		}
	}

	return socket.LocalAddr().String(), capture, stop
}

