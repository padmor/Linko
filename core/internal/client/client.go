// Package client is a stand-in for Phone B used by the gateway proof.
//
// The real Phone B will use Android's VpnService. This stand-in keeps the
// tunnel in userspace so the proof needs no admin rights and no OS driver.
package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/padmor/linko/core/internal/tunnel"
)

// Client sends all its traffic through the tunnel.
type Client struct {
	dev *device.Device
	net *netstack.Net
}

// New starts the client. local is its address inside the tunnel and dns is the
// resolver it asks, through the tunnel, to turn names into addresses.
func New(cfg tunnel.Config, local, dns netip.Addr, mtu int) (*Client, error) {
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{local}, []netip.Addr{dns}, mtu)
	if err != nil {
		return nil, fmt.Errorf("client: create tun: %w", err)
	}
	dev, err := tunnel.Up(tdev, cfg, "client")
	if err != nil {
		return nil, err
	}
	return &Client{dev: dev, net: tnet}, nil
}

// HTTPClient returns an HTTP client whose connections all go through the tunnel.
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return c.net.DialContext(ctx, network, addr)
			},
			// One connection per test keeps the measurement simple and honest.
			DisableKeepAlives: true,
		},
	}
}

// Close shuts the tunnel down.
func (c *Client) Close() { c.dev.Close() }
