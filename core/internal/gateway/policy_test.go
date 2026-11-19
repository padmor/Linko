package gateway

import (
	"net/netip"
	"testing"
)

func TestValidateDestination(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{name: "public IPv4", address: "8.8.8.8"},
		{name: "public IPv6", address: "2606:4700:4700::1111"},
		{name: "private 10 range", address: "10.1.2.3", wantErr: true},
		{name: "private 172 range", address: "172.20.1.2", wantErr: true},
		{name: "private 192 range", address: "192.168.1.2", wantErr: true},
		{name: "carrier grade NAT", address: "100.64.0.1", wantErr: true},
		{name: "loopback", address: "127.0.0.1", wantErr: true},
		{name: "link local", address: "169.254.1.1", wantErr: true},
		{name: "multicast", address: "224.0.0.1", wantErr: true},
		{name: "unspecified", address: "0.0.0.0", wantErr: true},
		{name: "documentation IPv4", address: "203.0.113.10", wantErr: true},
		{name: "benchmark IPv4", address: "198.18.0.1", wantErr: true},
		{name: "reserved IPv4", address: "240.0.0.1", wantErr: true},
		{name: "IPv4 mapped private", address: "::ffff:192.168.1.1", wantErr: true},
		{name: "IPv4 mapped public", address: "::ffff:8.8.8.8"},
		{name: "IPv6 loopback", address: "::1", wantErr: true},
		{name: "IPv6 unique local", address: "fd12:3456::1", wantErr: true},
		{name: "IPv6 link local", address: "fe80::1", wantErr: true},
		{name: "IPv6 multicast", address: "ff02::1", wantErr: true},
		{name: "IPv6 documentation", address: "2001:db8::1", wantErr: true},
		{name: "IPv6 6to4", address: "2002:0808:0808::1", wantErr: true},
		{name: "IPv6 outside global unicast", address: "4000::1", wantErr: true},
		{name: "invalid address", address: "not-an-ip", wantErr: true},
		{name: "invalid zero value", address: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.address)
			if err != nil && tt.address != "not-an-ip" && tt.address != "" {
				t.Fatalf("test address %q is invalid: %v", tt.address, err)
			}
			if err == nil {
				err = validateDestination(addr)
			} else {
				err = validateDestinationString(tt.address)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateDestination(%q) error = %v, wantErr %v", tt.address, err, tt.wantErr)
			}
		})
	}
}
