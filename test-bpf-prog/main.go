package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alvee/ebpf-tool/test-bpf-prog/pkg/ebpf"
)

func main() {
	// Parse command line flags
	intervalSec := flag.Int("interval", 2, "Interval in seconds between map reads")
	flag.Parse()

	// Check if we're running as root
	if os.Geteuid() != 0 {
		log.Fatalf("This program must be run as root (or with sudo)")
	}

	// Create a new tracker
	tracker, err := ebpf.NewExecTracker()
	if err != nil {
		log.Fatalf("Failed to create exec tracker: %v", err)
	}
	defer tracker.Close()

	// Handle termination signals
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Start watching for processes in a separate goroutine
	go tracker.WatchProcesses(time.Duration(*intervalSec) * time.Second)

	// Wait for termination signal
	<-stopper
	log.Println("Received signal, shutting down...")
}
