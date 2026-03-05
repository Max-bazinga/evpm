/*
 * eBPF VM Performance Monitor - vCPU Scheduling Monitor (CO-RE version)
 * 
 * Monitors vCPU lifecycle: run, halt, wakeup, schedule latency
 * Compile Once - Run Everywhere (CO-RE) compatible
 * 
 * Note: Using bpf_probe_read_kernel for compatibility with kernels
 * that don't export tracepoint structs in BTF.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_VCPUS 256

/* Event types */
enum vcpu_event_type {
    VCPU_RUN_BEGIN = 1,
    VCPU_RUN_END,
    VCPU_HALT,
    VCPU_WAKEUP,
};

/* vCPU scheduling event */
struct vcpu_sched_event {
    u32 pid;
    u32 vcpu_id;
    u64 timestamp;
    u32 event_type;
    u64 duration_ns;
    char comm[TASK_COMM_LEN];
};

/* Per-vCPU state */
struct vcpu_state {
    u64 last_run_ns;
    u64 last_halt_ns;
    u64 total_run_ns;
    u64 total_halt_ns;
    u32 schedule_count;
    u32 pid;
};

/* Maps - CO-RE compatible libbpf style */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VCPUS);
    __type(key, u32);
    __type(value, struct vcpu_state);
} vcpu_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} sched_latencies SEC(".maps");

/* License */
char LICENSE[] SEC("license") = "GPL";

/*
 * Tracepoint field offsets (may vary by kernel version)
 * These are common offsets for kvm tracepoints
 * trace_entry is 8 bytes, then comes the payload
 */
#define TP_OFFSET_VCPU_ID 8

/* Helper to read vcpu_id from kvm tracepoints */
static __always_inline u32 read_vcpu_id(void *ctx)
{
    u32 vcpu_id = 0;
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + TP_OFFSET_VCPU_ID);
    return vcpu_id;
}

/* Tracepoint: kvm_vcpu_run_begin 
 * Compatible with kernels that don't export trace_event_raw_* in BTF
 */
SEC("tp/kvm/kvm_vcpu_run_begin")
int trace_vcpu_run_begin(void *ctx)
{
    u32 vcpu_id = read_vcpu_id(ctx);
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    /* Update vCPU state */
    struct vcpu_state *state = bpf_map_lookup_elem(&vcpu_states, &vcpu_id);
    if (!state) {
        struct vcpu_state new_state = {};
        new_state.last_run_ns = now;
        new_state.pid = pid;
        bpf_map_update_elem(&vcpu_states, &vcpu_id, &new_state, BPF_ANY);
    } else {
        state->last_run_ns = now;
        state->pid = pid;
        state->schedule_count++;
    }
    
    /* Send event */
    struct vcpu_sched_event *event = bpf_ringbuf_reserve(
        &events, sizeof(*event), 0);
    if (event) {
        event->pid = pid;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = VCPU_RUN_BEGIN;
        event->duration_ns = 0;
        bpf_get_current_comm(event->comm, sizeof(event->comm));
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Tracepoint: kvm_vcpu_run_end */
SEC("tp/kvm/kvm_vcpu_run_end")
int trace_vcpu_run_end(void *ctx)
{
    u32 vcpu_id = read_vcpu_id(ctx);
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vcpu_state *state = bpf_map_lookup_elem(
        &vcpu_states, &vcpu_id);
    if (state && state->last_run_ns > 0) {
        u64 duration = now - state->last_run_ns;
        state->total_run_ns += duration;
        
        struct vcpu_sched_event *event = bpf_ringbuf_reserve(
            &events, sizeof(*event), 0);
        if (event) {
            event->pid = pid;
            event->vcpu_id = vcpu_id;
            event->timestamp = now;
            event->event_type = VCPU_RUN_END;
            event->duration_ns = duration;
            bpf_get_current_comm(event->comm, sizeof(event->comm));
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return 0;
}

/* Tracepoint: kvm_vcpu_halt */
SEC("tp/kvm/kvm_vcpu_halt")
int trace_vcpu_halt(void *ctx)
{
    u32 vcpu_id = read_vcpu_id(ctx);
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vcpu_state *state = bpf_map_lookup_elem(
        &vcpu_states, &vcpu_id);
    if (state) {
        state->last_halt_ns = now;
    }
    
    struct vcpu_sched_event *event = bpf_ringbuf_reserve(
        &events, sizeof(*event), 0);
    if (event) {
        event->pid = pid;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = VCPU_HALT;
        event->duration_ns = 0;
        bpf_get_current_comm(event->comm, sizeof(event->comm));
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Tracepoint: kvm_vcpu_wakeup */
SEC("tp/kvm/kvm_vcpu_wakeup")
int trace_vcpu_wakeup(void *ctx)
{
    u32 vcpu_id = read_vcpu_id(ctx);
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vcpu_state *state = bpf_map_lookup_elem(
        &vcpu_states, &vcpu_id);
    if (state && state->last_halt_ns > 0) {
        u64 halt_duration = now - state->last_halt_ns;
        state->total_halt_ns += halt_duration;
        
        struct vcpu_sched_event *event = bpf_ringbuf_reserve(
            &events, sizeof(*event), 0);
        if (event) {
            event->pid = pid;
            event->vcpu_id = vcpu_id;
            event->timestamp = now;
            event->event_type = VCPU_WAKEUP;
            event->duration_ns = halt_duration;
            bpf_get_current_comm(event->comm, sizeof(event->comm));
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return 0;
}
