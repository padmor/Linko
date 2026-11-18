// Package speedtest measures download speed and applies the pass rule that
// decides whether the userspace gateway is fast enough.
package speedtest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PassRatio is the share of the direct speed the tunnel must reach.
// Agreed with Padmore: 0.7 x 12.3 Mbit/s = 8.6 Mbit/s on his campus baseline.
const PassRatio = 0.7

// Result is one finished download.
type Result struct {
	Bytes   int64
	Elapsed time.Duration
}

// Mbit returns the speed in megabits per second.
func (r Result) Mbit() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(r.Bytes) * 8 / r.Elapsed.Seconds() / 1e6
}

// Download fetches url with hc and discards the body, timing the whole transfer.
func Download(ctx context.Context, hc *http.Client, url string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, err
	}
	start := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("speedtest: %s returned %s", url, resp.Status)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return Result{}, err
	}
	return Result{Bytes: n, Elapsed: time.Since(start)}, nil
}

// Passes reports whether the tunnel reached PassRatio of the direct speed.
func Passes(tunnel, direct Result) bool {
	return tunnel.Mbit() >= PassRatio*direct.Mbit()
}
