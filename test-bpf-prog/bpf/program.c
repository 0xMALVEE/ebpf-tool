//go:build ignore

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>

// Define necessary struct for tracepoint handler
struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long syscall_nr;
    unsigned long args[6];
};

// Define a BPF map to store process execution count by PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);    // PID
    __type(value, __u64);  // Count
} exec_count SEC(".maps");

// Define a BPF map to store process names
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);            // PID
    __type(value, char[16]);       // Process name (limited to 16 bytes)
} process_names SEC(".maps");

// This program attaches to the execve syscall tracepoint
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id;
    
    // Try to get the current count for this PID
    __u64 *count = bpf_map_lookup_elem(&exec_count, &pid);
    __u64 init_val = 1;
    
    // If this PID doesn't exist in the map yet, insert it with count 1
    if (!count) {
        bpf_map_update_elem(&exec_count, &pid, &init_val, BPF_ANY);
    } else {
        // Otherwise, increment the existing count
        (*count)++;
        bpf_map_update_elem(&exec_count, &pid, count, BPF_ANY);
    }
    
    // Get and store the process name
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_map_update_elem(&process_names, &pid, &comm, BPF_ANY);
    
    return 0;
}

// License is required for certain BPF program types
char LICENSE[] SEC("license") = "GPL";