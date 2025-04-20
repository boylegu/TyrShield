package protector

import (
	"TyrShield/bpf"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
)

type Protector interface {
	Configure(cfg Config) error
	Attach(ifaceName, mode string) error
	StartEventLoop(perfPages int) error
	EventChannel() <-chan Event
	Stop()
}

func New() (Protector, error) {
	return NewSSHProtector()
}

// Config corresponds to the `config` struct in the BPF program
type Config struct {
	SSHPort      uint32
	MaxAttempts  uint32
	TimeWindowNs uint64
	BlockTimeNs  uint64
}

// Event corresponds to the `event` struct in the BPF program
type Event struct {
	IP    uint32
	Count uint32
}

type SSHProtector struct {
	objs    *bpf.BpfObjects
	xdpLink link.Link
	eventCh chan Event
	done    chan struct{}
}

func NewSSHProtector() (*SSHProtector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	objs := bpf.BpfObjects{}
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	return &SSHProtector{
		objs:    &objs,
		eventCh: make(chan Event, 100),
		done:    make(chan struct{}),
	}, nil
}

func (p *SSHProtector) Configure(cfg Config) error {
	key := uint32(0)
	if err := p.objs.ConfigMap.Put(&key, &cfg); err != nil {
		return fmt.Errorf("update config map: %w", err)
	}
	return nil
}

func (p *SSHProtector) Attach(ifaceName string, mode string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("get interface %s: %w", ifaceName, err)
	}

	var flags link.XDPAttachFlags
	switch mode {
	case "skb", "generic":
		flags = link.XDPGenericMode
	case "hw":
		flags = link.XDPDriverMode
	case "native":
		flags = link.XDPDriverMode
	default:
		flags = link.XDPGenericMode
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   p.objs.XdpSshFilter,
		Interface: iface.Index,
		Flags:     flags,
	})
	if err != nil {
		return fmt.Errorf("attach XDP: %w", err)
	}

	p.xdpLink = xdpLink
	return nil
}

func (p *SSHProtector) StartEventLoop(bufferPages int) error {
	var cfg Config
	key := uint32(0)
	if err := p.objs.ConfigMap.Lookup(&key, &cfg); err == nil {
		log.Printf("Current config: Port=%d, MaxAttempts=%d, TimeWindow=%ds",
			cfg.SSHPort, cfg.MaxAttempts, cfg.TimeWindowNs/1000000000)
	}

	pageSize := os.Getpagesize()
	log.Printf("Perf buffer: %d pages (%d bytes)", bufferPages, bufferPages*pageSize)

	rd, err := perf.NewReader(p.objs.Events, bufferPages*pageSize)
	if err != nil {
		return fmt.Errorf("create perf reader: %w", err)
	}

	var totalLost uint64
	const warnThreshold = 100 // trigger an alert when 100 dropped events occur consecutively.

	go func() {
		defer rd.Close()

		for {
			select {
			case <-p.done:
				return
			default:
				record, err := rd.Read()
				if err != nil {
					if errors.Is(err, perf.ErrClosed) {
						return
					}
					log.Printf("read perf event: %v", err)
					continue
				}

				if record.LostSamples > 0 {
					totalLost += record.LostSamples
					log.Printf("WARNING: lost %d events (total lost = %d)", record.LostSamples, totalLost)
					if totalLost >= warnThreshold {
						log.Printf("ERROR: total lost samples %d ≥ %d, consider increasing perf buffer size", totalLost, warnThreshold)
						totalLost = 0
					}
					continue
				}

				var e Event
				if err := binary.Read(
					bytes.NewReader(record.RawSample),
					binary.LittleEndian,
					&e,
				); err != nil {
					log.Printf("decode event: %v", err)
					continue
				}

				p.eventCh <- e
			}
		}
	}()

	return nil
}

func (p *SSHProtector) Stop() {
	close(p.done)
	if p.xdpLink != nil {
		p.xdpLink.Close()
	}
	p.objs.Close()
}

func (p *SSHProtector) EventChannel() <-chan Event {
	return p.eventCh
}
