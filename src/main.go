package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	iouringzap "TyrShield/src/logs"
	"TyrShield/src/protector"
	"TyrShield/src/utils"
)

func main() {
	logger := iouringzap.GetLogger()
	defer iouringzap.CloseGlobal()

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

	prot, err := protector.New()
	if err != nil {
		logger.Fatalw("failed to create protector: %v", err)
	}
	defer prot.Stop()

	cfg := protector.Config{
		SSHPort:      uint32(port),
		MaxAttempts:  uint32(maxAttempt),
		TimeWindowNs: uint64(timeWindow) * 1e9,
		BlockTimeNs:  uint64(blockTime) * 1e9,
	}
	if err := prot.Configure(cfg); err != nil {
		logger.Fatalw("failed to configure: %v", err)
	}

	if err := prot.Attach(iface, mode); err != nil {
		logger.Fatalw("failed to attach XDP program: %v", err)
	}

	if err := prot.StartEventLoop(perfPages); err != nil {
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
		case e := <-prot.EventChannel():
			ip := utils.IntToIP(e.IP)
			logger.Infow("[%s] Banning IP: %s, Attempts: %d",
				time.Now().Format("2006-01-02 15:04:05"), ip, e.Count)

		case <-sigCh:
			logger.Infow("\nShutting down XDP program...")
			return
		}
	}
}
