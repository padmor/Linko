// Package proof runs the whole gateway test on one machine: a gateway, a
// client behind it, and a download measured with and without the tunnel.
package proof

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/device"

	"github.com/padmor/linko/core/internal/client"
	"github.com/padmor/linko/core/internal/gateway"
	"github.com/padmor/linko/core/internal/gatewaytun"
	"github.com/padmor/linko/core/internal/speedtest"
	"github.com/padmor/linko/core/internal/tunnel"
)

// Addresses inside the tunnel.
var (
	gatewayAddr = netip.MustParseAddr("10.77.0.1")
	clientAddr  = netip.MustParseAddr("10.77.0.2")
	// dnsAddr is asked through the tunnel, so it exercises UDP forwarding too.
	dnsAddr = netip.MustParseAddr("1.1.1.1")
)

// Options configures one run.
type Options struct {
	URL        string // file to download
	MTU        int    // tunnel MTU
	Port       int    // UDP port the gateway listens on (loopback)
	SkipDirect bool   // skip the direct baseline download
}

// Report holds the outcome.
type Report struct {
	Direct speedtest.Result
	Tunnel speedtest.Result
	MTU    int
	Passed bool
}

// Run starts both ends, downloads Options.URL through the tunnel and, unless
// skipped, directly, then returns the measurements.
func Run(ctx context.Context, opt Options) (Report, error) {
	gwKey, gwPub, err := tunnel.NewKeyPair()
	if err != nil {
		return Report{}, err
	}
	clKey, clPub, err := tunnel.NewKeyPair()
	if err != nil {
		return Report{}, err
	}

	// Gateway side: listens on loopback, accepts only the client's address.
	gwTun, stack, err := gatewaytun.New(gatewayAddr, opt.MTU)
	if err != nil {
		return Report{}, err
	}
	gwDev, err := tunnel.Up(gwTun, tunnel.Config{
		PrivateKey: gwKey,
		ListenPort: opt.Port,
		Peer:       tunnel.Peer{PublicKey: clPub, AllowedIPs: []string{clientAddr.String() + "/32"}},
	}, "gateway")
	if err != nil {
		return Report{}, err
	}
	defer closeDevice(gwDev)

	gw, err := gateway.New(stack)
	if err != nil {
		return Report{}, err
	}
	defer gw.Close()

	// Client side: sends everything to the gateway.
	cl, err := client.New(tunnel.Config{
		PrivateKey: clKey,
		Peer: tunnel.Peer{
			PublicKey:  gwPub,
			AllowedIPs: []string{"0.0.0.0/0"},
			Endpoint:   net.JoinHostPort("127.0.0.1", fmt.Sprint(opt.Port)),
			Keepalive:  true,
		},
	}, clientAddr, dnsAddr, opt.MTU)
	if err != nil {
		return Report{}, err
	}
	defer cl.Close()

	rep := Report{MTU: opt.MTU}

	if !opt.SkipDirect {
		direct := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
		if rep.Direct, err = speedtest.Download(ctx, direct, opt.URL); err != nil {
			return rep, fmt.Errorf("direct download: %w", err)
		}
	}

	tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if rep.Tunnel, err = speedtest.Download(tctx, cl.HTTPClient(), opt.URL); err != nil {
		return rep, fmt.Errorf("tunnel download: %w", err)
	}

	rep.Passed = !opt.SkipDirect && speedtest.Passes(rep.Tunnel, rep.Direct)
	return rep, nil
}

func closeDevice(d *device.Device) { d.Close() }
