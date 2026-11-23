// Package mobile exposes a small gomobile-compatible API for Android.
//
// Keep this package at the platform boundary. Android-specific lifecycle,
// permissions and key storage belong in Kotlin, while tunnel and forwarding
// behavior remain in the shared Go core.
package mobile

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/padmor/linko/core/internal/phonea"
	"github.com/padmor/linko/core/internal/tunnel"
	"github.com/padmor/linko/protocol/envelope"
)

const (
	wireGuardKeySize = 32
	sessionIDSize    = envelope.IDSize
)

// PhoneAGateway owns one running Phone A endpoint.
type PhoneAGateway struct {
	endpoint  *phonea.PhoneA
	closeOnce sync.Once
}

// NewPhoneAGateway starts Phone A using raw WireGuard key bytes and its
// sender-specific relay session ID. The caller should clear its key buffers
// after this call returns. The relay address must include its UDP port.
func NewPhoneAGateway(
	privateKeyBytes []byte,
	peerPublicKeyBytes []byte,
	sessionIDBytes []byte,
	relayAddress string,
	localAddress string,
	peerAddress string,
	mtu int32,
) (*PhoneAGateway, error) {
	privateKey, err := parseKey(privateKeyBytes, "private")
	if err != nil {
		return nil, err
	}
	defer clear(privateKey[:])

	peerPublicKey, err := parseKey(peerPublicKeyBytes, "peer public")
	if err != nil {
		return nil, err
	}

	if len(sessionIDBytes) != sessionIDSize {
		return nil, fmt.Errorf("mobile: session ID must be %d bytes", sessionIDSize)
	}
	var sessionID envelope.SessionID
	copy(sessionID[:], sessionIDBytes)

	localAddr, err := parseIPv4(localAddress, "local tunnel address")
	if err != nil {
		return nil, err
	}
	peerAddr, err := parseIPv4(peerAddress, "peer tunnel address")
	if err != nil {
		return nil, err
	}

	cfg := phonea.Config{
		PrivateKey:    privateKey,
		PeerPublicKey: peerPublicKey,
		Session:       sessionID,
		RelayAddress:  relayAddress,
		LocalAddress:  localAddr,
		PeerAddress:   peerAddr,
		MTU:           int(mtu),
	}
	defer clear(cfg.PrivateKey[:])

	endpoint, err := phonea.Start(cfg)
	if err != nil {
		return nil, fmt.Errorf("mobile: start Phone A: %w", err)
	}

	return &PhoneAGateway{endpoint: endpoint}, nil
}

// Close stops the gateway. It is safe to call more than once.
func (g *PhoneAGateway) Close() {
	if g == nil {
		return
	}

	g.closeOnce.Do(func() {
		if g.endpoint != nil {
			g.endpoint.Close()
			g.endpoint = nil
		}
	})
}

func parseKey(value []byte, name string) (tunnel.Key, error) {
	if len(value) != wireGuardKeySize {
		return tunnel.Key{}, fmt.Errorf("mobile: %s key must be %d bytes", name, wireGuardKeySize)
	}

	var key tunnel.Key
	copy(key[:], value)
	return key, nil
}

func parseIPv4(value, name string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return netip.Addr{}, fmt.Errorf("mobile: %s must be a valid IPv4 address", name)
	}
	return address, nil
}
