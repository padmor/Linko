module github.com/padmor/linko/core

go 1.23.1

// Versions are pinned to the set WireGuard itself builds with.
// gVisor in particular must match: its newest versions need a newer Go.
require (
	golang.org/x/crypto v0.37.0
	golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
)
