// Package gateway is the exit side of Linko (Phone A).
//
// This file contains the destination policy shared by TCP and UDP forwarding.
package gateway

import (
	"fmt"
	"net/netip"
)

// blockedDestinationPrefixes contains special-use ranges that must never be
// reached through Phone A. The policy is deliberately conservative: a false
// positive blocks a destination rather than exposing a private network.
//
// Keep this list explicit instead of relying only on IsGlobalUnicast, which
// also returns true for several non-public ranges (including RFC 1918).
var blockedDestinationPrefixes = mustParsePrefixes([]string{
	// IPv4 special-use and non-public ranges.
	"0.0.0.0/8",       // this network
	"10.0.0.0/8",      // private
	"100.64.0.0/10",   // carrier-grade NAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local
	"172.16.0.0/12",   // private
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation
	"192.88.99.0/24",  // deprecated 6to4 relay
	"192.168.0.0/16",  // private
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved and limited broadcast

	// IPv6 special-use and non-global ranges.
	"::/128",           // unspecified
	"::1/128",          // loopback
	"::ffff:0:0/96",    // IPv4-mapped (also unwrapped before checking)
	"64:ff9b:1::/48",   // local-use NAT64
	"100::/64",         // discard-only
	"2001::/23",        // IETF protocol assignments, including Teredo
	"2001:db8::/32",    // documentation
	"2002::/16",        // 6to4 (embeds an IPv4 destination)
	"3fff::/20",        // documentation
	"fc00::/7",         // unique-local
	"fe80::/10",        // link-local
	"ff00::/8",         // multicast
})

func mustParsePrefixes(values []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic(fmt.Sprintf("gateway: invalid destination prefix %q: %v", value, err))
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// validateDestination permits only globally routable unicast IP addresses.
// IPv4-mapped IPv6 addresses are normalized before policy checks so they
// cannot bypass an IPv4 restriction.
func validateDestination(addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("invalid destination address")
	}

	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return fmt.Errorf("destination %s is not global unicast", addr)
	}

	for _, prefix := range blockedDestinationPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("destination %s is in blocked range %s", addr, prefix)
		}
	}

	// Only the currently allocated IPv6 global-unicast space is accepted.
	// This also rejects IPv6 transition and future special-purpose space unless
	// it is explicitly reviewed and added later.
	if addr.Is6() && !netip.MustParsePrefix("2000::/3").Contains(addr) {
		return fmt.Errorf("destination %s is outside IPv6 global-unicast space", addr)
	}

	return nil
}

// validateDestinationString parses the destination address from a transport
// endpoint and applies the same policy used by both TCP and UDP.
func validateDestinationString(value string) error {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return fmt.Errorf("invalid destination address %q: %w", value, err)
	}
	return validateDestination(addr)
}
