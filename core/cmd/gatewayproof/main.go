// Command gatewayproof is Phase 1, box 1 of the Linko roadmap: it proves that a
// userspace WireGuard gateway can carry real traffic fast enough, on one machine.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/padmor/linko/core/internal/proof"
	"github.com/padmor/linko/core/internal/speedtest"
)

func main() {
	url := flag.String("url", "https://speed.cloudflare.com/__down?bytes=25000000", "file to download")
	mtu := flag.Int("mtu", 1400, "tunnel MTU")
	port := flag.Int("port", 51820, "UDP port for the gateway (loopback)")
	skipDirect := flag.Bool("skip-direct", false, "skip the direct baseline")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	rep, err := proof.Run(ctx, proof.Options{URL: *url, MTU: *mtu, Port: *port, SkipDirect: *skipDirect})
	if err != nil {
		fmt.Fprintln(os.Stderr, "gatewayproof:", err)
		os.Exit(1)
	}

	fmt.Printf("MTU:     %d\n", rep.MTU)
	if !*skipDirect {
		fmt.Printf("Direct:  %.1f Mbit/s (%d bytes in %s)\n", rep.Direct.Mbit(), rep.Direct.Bytes, rep.Direct.Elapsed.Round(1e6))
	}
	fmt.Printf("Tunnel:  %.1f Mbit/s (%d bytes in %s)\n", rep.Tunnel.Mbit(), rep.Tunnel.Bytes, rep.Tunnel.Elapsed.Round(1e6))
	if *skipDirect {
		return
	}
	fmt.Printf("Ratio:   %.0f%% of direct (need %.0f%%)\n", 100*rep.Tunnel.Mbit()/rep.Direct.Mbit(), 100*speedtest.PassRatio)
	if rep.Passed {
		fmt.Println("Result:  PASS")
		return
	}
	fmt.Println("Result:  FAIL")
	os.Exit(2)
}
