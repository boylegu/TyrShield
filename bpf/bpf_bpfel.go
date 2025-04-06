// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type BpfAttemptInfo struct {
	Count            uint32
	_                [4]byte
	FirstAttemptTime uint64
	LastAttemptTime  uint64
	BlockUntil       uint64
}

type BpfConfig struct {
	SshPort      uint32
	MaxAttempts  uint32
	TimeWindowNs uint64
	BlockTimeNs  uint64
}

// LoadBpf returns the embedded CollectionSpec for Bpf.
func LoadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Bpf: %w", err)
	}

	return spec, err
}

// LoadBpfObjects loads Bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*BpfObjects
//	*BpfPrograms
//	*BpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// BpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfSpecs struct {
	BpfProgramSpecs
	BpfMapSpecs
	BpfVariableSpecs
}

// BpfProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfProgramSpecs struct {
	XdpSshFilter *ebpf.ProgramSpec `ebpf:"xdp_ssh_filter"`
}

// BpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfMapSpecs struct {
	ConfigMap   *ebpf.MapSpec `ebpf:"config_map"`
	Events      *ebpf.MapSpec `ebpf:"events"`
	SshAttempts *ebpf.MapSpec `ebpf:"ssh_attempts"`
}

// BpfVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfVariableSpecs struct {
}

// BpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfObjects struct {
	BpfPrograms
	BpfMaps
	BpfVariables
}

func (o *BpfObjects) Close() error {
	return _BpfClose(
		&o.BpfPrograms,
		&o.BpfMaps,
	)
}

// BpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfMaps struct {
	ConfigMap   *ebpf.Map `ebpf:"config_map"`
	Events      *ebpf.Map `ebpf:"events"`
	SshAttempts *ebpf.Map `ebpf:"ssh_attempts"`
}

func (m *BpfMaps) Close() error {
	return _BpfClose(
		m.ConfigMap,
		m.Events,
		m.SshAttempts,
	)
}

// BpfVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfVariables struct {
}

// BpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfPrograms struct {
	XdpSshFilter *ebpf.Program `ebpf:"xdp_ssh_filter"`
}

func (p *BpfPrograms) Close() error {
	return _BpfClose(
		p.XdpSshFilter,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfel.o
var _BpfBytes []byte
