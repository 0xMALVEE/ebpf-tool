# eBPF Process Execution Tracker

This project demonstrates how to use Cilium eBPF to create an eBPF program that tracks process executions in the system. It uses BPF maps to store execution counts and process names.

## Overview

The project consists of:

1. An eBPF program written in C that attaches to the `execve` syscall tracepoint
2. A Go application that loads the eBPF program and reads the map data

The eBPF program tracks:
- Process IDs (PIDs)
- Process names (up to 16 characters)
- Number of times each process has been executed

## Requirements

- Linux kernel 5.5 or newer (for BPF CO-RE support)
- Go 1.21 or newer
- Clang and LLVM (for compiling the eBPF program)
- Root privileges (to load the eBPF program)

## Installation

1. Install the required dependencies:

```bash
# For Debian/Ubuntu
sudo apt-get install clang llvm

# For Fedora/RHEL
sudo dnf install clang llvm
```
```
clang & llvm
sudo apt update
sudo apt install clang llvm

linux headers
sudo apt-get install -y linux-headers-$(uname -r)

libbpf development headers
sudo apt-get install -y libbpf-dev

architecture-specific headers
sudo apt-get install -y gcc-multilib
```

2. Install the Go dependencies:

```bash
go mod tidy
```

## Building

Use the provided Makefile to build the project:

```bash
# Generate the Go code from the eBPF C code and build the binary
make build

# Or simply:
make
```

## Running

Since loading eBPF programs requires root privileges, you'll need to run the program with `sudo`:

```bash
sudo ./execve-tracker
```

Or use the Makefile:

```bash
make run
```

By default, the program will print information about tracked processes every 2 seconds. You can change this interval using the `-interval` flag:

```bash
sudo ./execve-tracker -interval 5
```

## Output

The program will continuously print information about process executions:

```
2023/12/01 12:34:56 Starting process execution tracker...
2023/12/01 12:34:56 Press Ctrl+C to exit
2023/12/01 12:34:58 Tracked 3 processes:
2023/12/01 12:34:58 PID: 1234, Name: bash, Executions: 2
2023/12/01 12:34:58 PID: 5678, Name: ls, Executions: 1
2023/12/01 12:34:58 PID: 9012, Name: grep, Executions: 1
2023/12/01 12:34:58 ---
```

## How it Works

1. The eBPF C program (`bpf/program.c`) defines two BPF maps:
   - `exec_count`: A hash map that stores process execution counts by PID
   - `process_names`: A hash map that stores process names by PID

2. The `trace_execve` function attaches to the `sys_enter_execve` tracepoint and is called whenever a process calls the `execve` syscall.

3. The Go program loads the compiled eBPF program, attaches it to the tracepoint, and periodically reads and displays the contents of the BPF maps.

## Extending the Project

You can extend this project in several ways:

1. Add more information to track (e.g., parent PID, user ID)
2. Implement filtering to only track specific processes
3. Add visualization for the collected data
4. Integrate with other observability systems

## License

This project is licensed under the MIT License - see the LICENSE file for details.
