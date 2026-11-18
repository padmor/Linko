package proof

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// payloadSize is how much the local test server sends.
const payloadSize = 8 << 20 // 8 MiB

// TestTunnelCarriesTraffic downloads from a local server through the tunnel.
// The server listens on this machine's real (non-loopback) address. The client
// has no direct path to it, so the only way to get the bytes is through the
// gateway's real sockets. Loopback cannot be used: gVisor drops packets to
// loopback addresses as martians.
func TestTunnelCarriesTraffic(t *testing.T) {
	host := localAddr(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, payloadSize))
	})}
	go srv.Serve(ln)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rep, err := Run(ctx, Options{
		URL:        "http://" + ln.Addr().String() + "/",
		MTU:        1400,
		Port:       51899,
		SkipDirect: true,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Tunnel.Bytes != payloadSize {
		t.Fatalf("got %d bytes through the tunnel, want %d", rep.Tunnel.Bytes, payloadSize)
	}
	t.Logf("tunnel: %.1f Mbit/s over loopback", rep.Tunnel.Mbit())
}

// localAddr returns this machine's first non-loopback IPv4 address.
func localAddr(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot list addresses: %v", err)
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
			return ipn.IP.String()
		}
	}
	t.Skip("no non-loopback IPv4 address on this machine")
	return ""
}
