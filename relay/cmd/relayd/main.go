// Command relayd is the Linko relay: a blind UDP forwarder between two paired phones.
//
// It never sees keys or plaintext, and it logs only when it starts, stops or fails.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/padmor/linko/relay/server"
	"github.com/padmor/linko/relay/session"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "relayd:", err)
		os.Exit(1)
	}
}

// run parses args, serves until ctx ends, and prints the final counters.
// It is separate from main so tests can drive it.
func run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("relayd", flag.ContinueOnError)
	listen := fs.String("listen", ":51821", "UDP address to listen on")
	idle := fs.Duration("idle", 120*time.Second, "forget a phone that is silent this long (keep at least 4x the 25 s keepalive)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *idle <= 0 {
		return fmt.Errorf("-idle must be positive, got %v", *idle)
	}

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		return fmt.Errorf("bad -listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	srv := server.New(conn, session.NewTable(*idle))
	fmt.Fprintf(out, "relay listening on %s\n", conn.LocalAddr())

	if err := srv.Serve(ctx); err != nil {
		return err
	}
	fmt.Fprintf(out, "relay stopped: forwarded=%d dropped_format=%d dropped_route=%d dropped_send=%d\n",
		srv.Stats.Forwarded.Load(), srv.Stats.DroppedFormat.Load(),
		srv.Stats.DroppedRoute.Load(), srv.Stats.DroppedSend.Load())
	return nil
}
