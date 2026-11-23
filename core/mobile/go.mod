module github.com/padmor/linko/core/mobile

go 1.27.0

toolchain go1.27.4

tool golang.org/x/mobile/cmd/gobind
tool golang.org/x/mobile/cmd/gomobile

require (
	github.com/padmor/linko/core v0.0.0
	golang.org/x/mobile v0.0.0-20261117202452-47699113848a
)

replace github.com/padmor/linko/core => ..
replace github.com/padmor/linko/protocol => ../../protocol
