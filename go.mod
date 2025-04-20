module TyrShield

go 1.24.0

require (
	github.com/cilium/ebpf v0.18.0
	github.com/pawelgaczynski/giouring v0.0.0-20230826085535-69588b89acb9
	go.uber.org/zap v1.27.0
)

require (
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace github.com/pawelgaczynski/giouring => github.com/boylegu/giouring v1.0.0
