module github.com/padmor/linko/core/integrationtest

go 1.23.1

require (
	github.com/padmor/linko/core v0.0.0
	github.com/padmor/linko/protocol v0.0.0
	github.com/padmor/linko/relay v0.0.0
)

replace github.com/padmor/linko/core => ..
replace github.com/padmor/linko/protocol => ../../protocol
replace github.com/padmor/linko/relay => ../../relay
