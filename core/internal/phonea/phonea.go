// Package phonea assembles the Phone A gateway endpoint for the desktop prototype.
package phonea

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/padmor/linko/core/internal/gateway"
	"github.com/padmor/linko/core/internal/gatewaytun"
	"github.com/padmor/linko/core/internal/relaybind"
	"github.com/padmor/linko/core/internal/tunnel"
	"github.com/padmor/linko/protocol/envelope"
	"golang.zx2c4.com/wireguard/device"
)

const (
	minMTU = 576
	maxMTU = 65535
)

// Config contains the values Phone A needs to join one paired tunnel.
type Config struct {
	PrivateKey      tunnel.Key
	PeerPublicKey   tunnel.Key
	Session         envelope.SessionID
	RelayAddress    string
	LocalAddress    netip.Addr
	PeerAddress     netip.Addr
	MTU             int
}

// PhoneA owns the WireGuard device and the gateway forwarding its decrypted traffic.
type PhoneA struct {
	device  *device.Device
	gateway *gateway.Gateway
	closeMu sync.Mutex
	closed  bool
}

// Start validates the endpoint configuration, starts the gateway, and connects
// Phone A to its peer through the configured Linko relay.
func Start(cfg Config) (*PhoneA, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	tunDevice, stack, err := gatewaytun.New(cfg.LocalAddress, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("phonea: create gateway TUN: %w", err)
	}

	gw, err := gateway.New(stack)
	if err != nil {
		_ = tunDevice.Close()
		return nil, fmt.Errorf("phonea: start gateway: %w", err)
	}

	bind, err := relaybind.New(cfg.RelayAddress, cfg.Session)
	if err != nil {
		gw.Close()
		_ = tunDevice.Close()
		return nil, fmt.Errorf("phonea: configure relay: %w", err)
	}

	dev, err := tunnel.UpWithBind(tunDevice, tunnel.Config{
		PrivateKey: cfg.PrivateKey,
		Peer: tunnel.Peer{
			PublicKey:  cfg.PeerPublicKey,
			AllowedIPs: []string{cfg.PeerAddress.String() + "/32"},
			Endpoint:   cfg.RelayAddress,
			Keepalive:  true,
		},
	}, "phone-a", bind)
	if err != nil {
		gw.Close()
		_ = tunDevice.Close()
		return nil, fmt.Errorf("phonea: start WireGuard: %w", err)
	}

	return &PhoneA{device: dev, gateway: gw}, nil
}

// Close stops forwarding before closing WireGuard and its TUN device.
// It is safe to call more than once.
func (p *PhoneA) Close() {
	if p == nil {
		return
	}

	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.closed {
		return
	}
	p.closed = true

	p.gateway.Close()
	p.device.Close()
}

func validateConfig(cfg Config) error {
	if cfg.PrivateKey == (tunnel.Key{}) {
		return errors.New("phonea: private key is required")
	}
	if cfg.PeerPublicKey == (tunnel.Key{}) {
		return errors.New("phonea: peer public key is required")
	}
	if cfg.Session == (envelope.SessionID{}) {
		return errors.New("phonea: relay session is required")
	}
	if strings.TrimSpace(cfg.RelayAddress) == "" {
		return errors.New("phonea: relay address is required")
	}
	if !cfg.LocalAddress.Is4() || !cfg.PeerAddress.Is4() {
		return errors.New("phonea: tunnel addresses must be IPv4")
	}
	if cfg.LocalAddress == cfg.PeerAddress {
		return errors.New("phonea: local and peer addresses must differ")
	}
	if cfg.MTU < minMTU || cfg.MTU > maxMTU {
		return fmt.Errorf("phonea: MTU must be between %d and %d", minMTU, maxMTU)
	}
	return nil
}
