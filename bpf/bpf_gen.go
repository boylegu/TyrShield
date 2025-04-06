//go:build ignore
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go Bpf ./src/ssh_defense.c -- -Isrc -O2 -Wall
package bpf
