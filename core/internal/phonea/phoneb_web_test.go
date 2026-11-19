package phonea

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/padmor/linko/core/internal/phoneb"
	"github.com/padmor/linko/core/internal/tunnel"
	"github.com/padmor/linko/protocol/envelope"
)

const phoneBPage = "<!doctype html><html><body><h1>Linko tunnel proof</h1></body></html>"

// TestPhoneBLoadsHTTPSPageThroughPhoneA proves that a real HTTPS request from
// Phone B reaches a local test server only through Phone B's WireGuard tunnel,
// the Linko relay, and Phone A's gateway forwarder.
func TestPhoneBLoadsHTTPSPageThroughPhoneA(t *testing.T) {
	serverAddress := localPrivateIPv4(t)
	destination, err := netip.ParseAddr(serverAddress)
	if err != nil {
		t.Fatalf("parse local test server address: %v", err)
	}

	pageServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, phoneBPage)
	}))
	listener, err := net.Listen("tcp", net.JoinHostPort(serverAddress, "0"))
	if err != nil {
		t.Fatalf("listen on local test address %s: %v", serverAddress, err)
	}
	pageServer.Listener = listener
	pageServer.StartTLS()
	t.Cleanup(pageServer.Close)

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

	// The test server uses httptest's local certificate. Trust that certificate
	// explicitly and verify its localhost identity without disabling TLS checks.
	roots := x509.NewCertPool()
	roots.AddCert(pageServer.Certificate())
	httpClient := *phoneB.HTTPClient()
	transport := phoneB.HTTPClient().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
	httpClient.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pageServer.URL, nil)
	if err != nil {
		t.Fatalf("create HTTPS request: %v", err)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatalf("load HTTPS page through Phone B tunnel: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read page response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("page returned %s, want %s: %s", response.Status, http.StatusOK, body)
	}
	if string(body) != phoneBPage {
		t.Fatalf("unexpected page response: got %q, want %q", body, phoneBPage)
	}
	t.Logf("Phone B loaded the HTTPS page through Phone A: %s (%d bytes)", response.URL, len(body))
}

// localPrivateIPv4 selects an address that the test server can bind to and
// that the proof gateway can allow as its one exact private destination.
func localPrivateIPv4(t *testing.T) string {
	t.Helper()

	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("list local interface addresses: %v", err)
	}
	for _, address := range addresses {
		prefix, ok := address.(*net.IPNet)
		if !ok || prefix.IP.To4() == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(prefix.IP.To4())
		if ok && ip.Is4() && ip.IsPrivate() {
			return ip.String()
		}
	}
	t.Skip("no private non-loopback IPv4 address available for the local HTTPS server")
	return ""
}
