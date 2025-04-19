package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"go.uber.org/zap"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"TyrShield/bpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

var logger *zap.SugaredLogger

func initLogger() {
	// 生产环境用 NewProduction，开发环境可用 NewDevelopment
	zapLog, err := zap.NewProduction()
	if err != nil {
		panic(fmt.Sprintf("cannot initialize zap logger: %v", err))
	}
	logger = zapLog.Sugar()
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

func intToIP(ip uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], ip)
	return net.IP(b[:]).String()
}

func main() {
	initLogger()
	defer logger.Sync() // flush any buffered logs

	var (
		iface      string
		port       int
		maxAttempt int
		timeWindow int
		mode       string
		blockTime  int
		perfPages  int
	)

	flag.StringVar(&iface, "interface", "", "Network interface to bind (e.g. eth0)")
	flag.IntVar(&port, "port", 22, "SSH port to protect (default: 22)")
	flag.IntVar(&maxAttempt, "max-attempts", 5, "Max attempts within time window (default: 5)")
	flag.IntVar(&timeWindow, "time-window", 60, "Time window in seconds (default: 60)")
	flag.IntVar(&blockTime, "block-time", 300, "Ban duration in seconds (default: 300)")
	flag.StringVar(&mode, "mode", "generic",
		"XDP mode: generic (default), native (driver), hw (hardware)")
	flag.IntVar(&perfPages, "perf-pages", 8, "Perf buffer size in pages (default 8)")
	flag.Parse()

	if iface == "" {
		logger.Fatal("must specify network interface", "usage", flag.CommandLine)
		flag.PrintDefaults()
		os.Exit(1)
	}

	protector, err := NewSSHProtector()
	if err != nil {
		logger.Fatalw("failed to create protector: %v", err)
	}
	defer protector.Stop()

	cfg := Config{
		SSHPort:      uint32(port),
		MaxAttempts:  uint32(maxAttempt),
		TimeWindowNs: uint64(timeWindow) * 1e9,
		BlockTimeNs:  uint64(blockTime) * 1e9,
	}
	if err := protector.Configure(cfg); err != nil {
		logger.Fatalw("failed to configure: %v", err)
	}

	if err := protector.Attach(iface, mode); err != nil {
		logger.Fatalw("failed to attach XDP program: %v", err)
	}

	if err := protector.StartEventLoop(perfPages); err != nil {
		logger.Fatalw("failed to start event loop: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	logger.Infow("SSH protection started",
		"port", port,
		"maxAttempts", maxAttempt,
		"timeWindow", timeWindow,
		"blockTime", blockTime,
		"mode", mode,
		"perfPages", perfPages,
	)

	log.Printf("SSH protection started on port %d", port)
	log.Printf("Settings: %d attempts / %d seconds, ban for %d seconds", maxAttempt, timeWindow, blockTime)
	log.Println("Press Ctrl+C to stop...")

	for {
		select {
		case e := <-protector.EventChannel():
			ip := intToIP(e.IP)
			logger.Infow("[%s] Banning IP: %s, Attempts: %d",
				time.Now().Format("2006-01-02 15:04:05"), ip, e.Count)

		case <-sigCh:
			logger.Infow("\nShutting down XDP program...")
			return
		}
	}
}
