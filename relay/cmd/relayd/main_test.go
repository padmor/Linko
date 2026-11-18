package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunStartsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-listen", "127.0.0.1:0"}, &out) }()

	time.Sleep(100 * time.Millisecond) // let it bind
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop after cancel")
	}
	if s := out.String(); !strings.Contains(s, "relay listening on") || !strings.Contains(s, "relay stopped:") {
		t.Fatalf("unexpected output %q", s)
	}
}

func TestRunRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"zero idle", []string{"-idle", "0s"}},
		{"bad address", []string{"-listen", "not-an-address"}},
		{"unknown flag", []string{"-nope"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := run(context.Background(), tc.args, &out); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
