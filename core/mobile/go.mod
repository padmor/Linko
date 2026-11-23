module github.com/padmor/linko/core/mobile

go 1.27.0

toolchain go1.27.4

tool golang.org/x/mobile/cmd/gobind

tool golang.org/x/mobile/cmd/gomobile

require (
	github.com/padmor/linko/core v0.0.0
	github.com/padmor/linko/protocol v0.0.0
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/mobile v0.0.0-20261117202452-47699113848a // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/net v0.63.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.org/x/tools v0.53.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)

replace github.com/padmor/linko/core => ..

replace github.com/padmor/linko/protocol => ../../protocol
