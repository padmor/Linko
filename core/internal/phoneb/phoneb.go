// Package phoneb assembles the Phone B client endpoint for the desktop prototype.
package phoneb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/padmor/linko/core/internal/relaybind"
	"github.com/padmor/linko/core/internal/tunnel"
	"github.com/padmor/linko/protocol/envelope"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	minMTU = 576
	maxMTU = 65535
)

// Config contains the values Phone B needs to join one paired tunnel.
type Config struct {
	PrivateKey    tunnel.Key
	PeerPublicKey tunnel.Key
	Session       envelope.SessionID
	RelayAddress  string
	LocalAddress  netip.Addr
	PeerAddress   netip.Addr
	DNSAddress    netip.Addr
	MTU           int
}

// PhoneB owns the userspace WireGuard device and its tunnel-backed HTTP client.
type PhoneB struct {
	device     *device.Device
	httpClient *http.Client
	closeOnce  sync.Once
}

// Start validates the endpoint configuration and connects Phone B to Phone A
// through the configured Linko relay. All IPv4 destinations are routed into
// the tunnel; the relay socket itself remains on the host network.
func Start(cfg Config) (*PhoneB, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	tunDevice, tunnelNet, err := netstack.CreateNetTUN(
		[]netip.Addr{cfg.LocalAddress},
		[]netip.Addr{cfg.DNSAddress},
		cfg.MTU,
	)
	if err != nil {
		return nil, fmt.Errorf("phoneb: create userspace TUN: %w", err)
	}

	bind, err := relaybind.New(cfg.RelayAddress, cfg.Session)
	if err != nil {
		_ = tunDevice.Close()
		return nil, fmt.Errorf("phoneb: configure relay: %w", err)
	}

	dev, err := tunnel.UpWithBind(tunDevice, tunnel.Config{
		PrivateKey: cfg.PrivateKey,
		Peer: tunnel.Peer{
			PublicKey:  cfg.PeerPublicKey,
			AllowedIPs: []string{"0.0.0.0/0"},
			Endpoint:   cfg.RelayAddress,
			Keepalive:  true,
		},
	}, "phone-b", bind)
	if err != nil {
		return nil, fmt.Errorf("phoneb: start WireGuard: %w", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return tunnelNet.DialContext(ctx, network, address)
			},
			// Keep each proof request independent and avoid idle connections
			// surviving after the Phone B tunnel is closed.
			DisableKeepAlives: true,
		},
	}

	return &PhoneB{device: dev, httpClient: httpClient}, nil
}

// HTTPClient returns an HTTP client whose TCP connections use the Phone B
// userspace network stack and therefore follow the WireGuard tunnel.
func (p *PhoneB) HTTPClient() *http.Client {
	if p == nil {
		return nil
	}
	return p.httpClient
}

// Close shuts down HTTP connections and the WireGuard device.
// It is safe to call more than once.
func (p *PhoneB) Close() {
	if p == nil {
		return
	}

	p.closeOnce.Do(func() {
		p.httpClient.CloseIdleConnections()
		p.device.Close()
	})
}

func validateConfig(cfg Config) error {
	if cfg.PrivateKey == (tunnel.Key{}) {
		return errors.New("phoneb: private key is required")
	}
	if cfg.PeerPublicKey == (tunnel.Key{}) {
		return errors.New("phoneb: peer public key is required")
	}
	if cfg.Session == (envelope.SessionID{}) {
		return errors.New("phoneb: relay session is required")
	}
	if strings.TrimSpace(cfg.RelayAddress) == "" {
		return errors.New("phoneb: relay address is required")
	}
	if !cfg.LocalAddress.Is4() || !cfg.PeerAddress.Is4() || !cfg.DNSAddress.Is4() {
		return errors.New("phoneb: tunnel and DNS addresses must be IPv4")
	}
	if cfg.LocalAddress == cfg.PeerAddress {
		return errors.New("phoneb: local and peer addresses must differ")
	}
	if cfg.MTU < minMTU || cfg.MTU > maxMTU {
		return fmt.Errorf("phoneb: MTU must be between %d and %d", minMTU, maxMTU)
	}
	return nil
}
