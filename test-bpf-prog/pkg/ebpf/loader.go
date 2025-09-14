package ebpf

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include/bpf" bpf ../../bpf/program.c

// ExecTracker represents a process execution tracker
type ExecTracker struct {
	objs       bpfObjects
	execveLink link.Link
}

// ProcessInfo represents information about a process
type ProcessInfo struct {
	PID   uint32
	Count uint64
	Name  string
}

// NewExecTracker creates a new ExecTracker
func NewExecTracker() (*ExecTracker, error) {
	tracker := &ExecTracker{}

	// Load the BPF program
	if err := loadBpfObjects(&tracker.objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	// Attach the execve tracepoint
	link, err := link.Tracepoint("syscalls", "sys_enter_execve", tracker.objs.TraceExecve, nil)
	if err != nil {
		tracker.Close()
		return nil, fmt.Errorf("attaching tracepoint: %w", err)
	}
	tracker.execveLink = link

	return tracker, nil
}

// Close closes the tracker and releases all resources
func (t *ExecTracker) Close() error {
	if t.execveLink != nil {
		t.execveLink.Close()
	}
	t.objs.Close()
	return nil
}

// GetProcessInfo returns a list of all tracked processes
func (t *ExecTracker) GetProcessInfo() ([]ProcessInfo, error) {
	var result []ProcessInfo
	var key uint32
	var value uint64
	var name [16]byte

	// Iterate through the exec_count map
	entries := t.objs.ExecCount.Iterate()
	for entries.Next(&key, &value) {
		info := ProcessInfo{
			PID:   key,
			Count: value,
			Name:  "unknown",
		}

		// Try to get the process name from the process_names map
		err := t.objs.ProcessNames.Lookup(&key, &name)
		if err == nil {
			// Convert the byte array to a string, stopping at the first null byte
			for i, b := range name {
				if b == 0 {
					info.Name = string(name[:i])
					break
				}
			}
		}

		result = append(result, info)
	}

	return result, nil
}

// WatchProcesses continuously polls the BPF maps and prints process information
func (t *ExecTracker) WatchProcesses(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Println("Starting process execution tracker...")
	log.Println("Press Ctrl+C to exit")

	for range ticker.C {
		processes, err := t.GetProcessInfo()
		if err != nil {
			log.Printf("Error getting process info: %v", err)
			continue
		}

		log.Printf("Tracked %d processes:", len(processes))
		for _, p := range processes {
			log.Printf("PID: %d, Name: %s, Executions: %d", p.PID, p.Name, p.Count)
		}
		log.Println("---")
	}
}
