package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	iouringzap "TyrShield/src/logs"
	"TyrShield/src/protector"
	"TyrShield/src/utils"
	"github.com/spf13/cobra"
)

func main() {
	var (
		iface      string
		port       int
		maxAttempt int
		timeWindow int
		mode       string
		blockTime  int
		perfPages  int
		debug      string
	)

	var rootCmd = &cobra.Command{
		Use:   "tyrshield",
		Short: "SSH protector using XDP",
		Run: func(cmd *cobra.Command, args []string) {
			// Logger initialization
			logger := iouringzap.GetLogger()
			defer iouringzap.CloseGlobal()

			if debug == "true" {
				logger = iouringzap.GetDebugLogger()
				defer iouringzap.CloseDebugGlobal()
			}
			utils.RunASCIILogo()

			// Check if network interface is provided
			if iface == "" {
				logger.Fatal("must specify network interface", "usage", cmd.Flags())
				cmd.Help()
				os.Exit(1)
			}

			// Create and configure the protector
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

			// Attach the XDP program to the interface
			if err := prot.Attach(iface, mode); err != nil {
				logger.Fatalw("failed to attach XDP program: %v", err)
			}

			// Start the event loop for processing incoming events
			if err := prot.StartEventLoop(perfPages); err != nil {
				logger.Fatalw("failed to start event loop: %v", err)
			}

			// Signal handling (SIGINT, SIGTERM)
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL)

			logger.Infow("SSH protection started",
				"port", port,
				"maxAttempts", maxAttempt,
				"timeWindow", timeWindow,
				"blockTime", blockTime,
				"mode", mode,
				"perfPages", perfPages,
			)

			fmt.Printf("SSH protection started on port %d\n", port)
			fmt.Printf("Settings: %d attempts / %d seconds, ban for %d seconds\n", maxAttempt, timeWindow, blockTime)
			fmt.Println("Press Ctrl+C to stop...")

			// Process events from the event loop
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
		},
	}

	rootCmd.Flags().StringVar(&iface, "iface", "", "Network interface to bind (e.g. eth0)")
	rootCmd.Flags().IntVar(&port, "port", 22, "SSH port to protect (default: 22)")
	rootCmd.Flags().IntVar(&maxAttempt, "max-attempts", 5, "Max attempts within time window (default: 5)")
	rootCmd.Flags().IntVar(&timeWindow, "time-window", 60, "Time window in seconds (default: 60)")
	rootCmd.Flags().IntVar(&blockTime, "block-time", 300, "Ban duration in seconds (default: 300)")
	rootCmd.Flags().StringVar(&mode, "mode", "generic", "XDP mode: generic (default), native (driver), hw (hardware)")
	rootCmd.Flags().IntVar(&perfPages, "perf-pages", 8, "Perf buffer size in pages (default 8)")
	rootCmd.Flags().StringVar(&debug, "debug", "false", "DEBUG mode (default: false) Enable Performance iouring logger")
	rootCmd.MarkFlagRequired("iface")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
