package client

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/padmor/linko/core/internal/tunnel"
)

func TestNewAddsContextToWireGuardSetupErrors(t *testing.T) {
	privateKey, publicKey, err := tunnel.NewKeyPair()
	if err != nil {
		t.Fatalf("create test key pair: %v", err)
	}

	cfg := tunnel.Config{
		PrivateKey: privateKey,
		Peer: tunnel.Peer{
			PublicKey:  publicKey,
			AllowedIPs: []string{"10.77.0.1/32"},
			Endpoint:   "not-an-endpoint",
		},
	}
	_, err = New(
		cfg,
		netip.MustParseAddr("10.77.0.2"),
		netip.MustParseAddr("10.77.0.1"),
		1280,
	)
	if err == nil {
		t.Fatal("New accepted an invalid WireGuard endpoint")
	}
	if !strings.Contains(err.Error(), "client: start WireGuard:") {
		t.Fatalf("error lacks client startup context: %v", err)
	}
}
