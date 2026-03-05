/*
 * eBPF VM Performance Monitor - vCPU Scheduling Monitor (Pure BCC)
 * 
 * Monitors vCPU lifecycle: run, halt, wakeup, schedule latency
 * Compatible with kernels without tracepoint struct definitions
 */

/* Basic types */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;

/* SEC macro for section attributes */
#define SEC(NAME) __attribute__((section(NAME), used))

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
struct evpm_vcpu_state {
    u64 last_run_ns;
    u64 last_halt_ns;
    u64 total_run_ns;
    u64 total_halt_ns;
    u32 schedule_count;
    u32 pid;
};

/* Maps - BCC style */
BPF_RINGBUF_OUTPUT(events, 256 * 1024);
BPF_HASH(vcpu_states, u32, struct evpm_vcpu_state, MAX_VCPUS);

/* 
 * Tracepoint args layout for kvm tracepoints:
 * struct trace_entry (8 bytes) + vcpu_id (4 bytes) + ...
 * We use bpf_probe_read to safely access fields
 */

/* Tracepoint: kvm_vcpu_run_begin */
SEC("tracepoint/kvm/kvm_vcpu_run_begin")
int trace_kvm_vcpu_run_begin(void *ctx)
{
    u32 vcpu_id = 0;
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct evpm_vcpu_state *state = vcpu_states.lookup(&vcpu_id);
    if (!state) {
        struct evpm_vcpu_state new_state = {};
        new_state.last_run_ns = now;
        new_state.pid = pid;
        vcpu_states.update(&vcpu_id, &new_state);
    } else {
        state->last_run_ns = now;
        state->pid = pid;
        state->schedule_count++;
    }
    
    struct vcpu_sched_event event = {};
    event.pid = pid;
    event.vcpu_id = vcpu_id;
    event.timestamp = now;
    event.event_type = VCPU_RUN_BEGIN;
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    events.ringbuf_output(&event, sizeof(event), 0);
    
    return 0;
}

/* Tracepoint: kvm_vcpu_run_end */
SEC("tracepoint/kvm/kvm_vcpu_run_end")
int trace_kvm_vcpu_run_end(void *ctx)
{
    u32 vcpu_id = 0;
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct evpm_vcpu_state *state = vcpu_states.lookup(&vcpu_id);
    if (state && state->last_run_ns > 0) {
        u64 duration = now - state->last_run_ns;
        state->total_run_ns += duration;
        
        struct vcpu_sched_event event = {};
        event.pid = pid;
        event.vcpu_id = vcpu_id;
        event.timestamp = now;
        event.event_type = VCPU_RUN_END;
        event.duration_ns = duration;
        bpf_get_current_comm(event.comm, sizeof(event.comm));
        events.ringbuf_output(&event, sizeof(event), 0);
    }
    
    return 0;
}

/* Tracepoint: kvm_vcpu_halt */
SEC("tracepoint/kvm/kvm_vcpu_halt")
int trace_kvm_vcpu_halt(void *ctx)
{
    u32 vcpu_id = 0;
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct evpm_vcpu_state *state = vcpu_states.lookup(&vcpu_id);
    if (state) {
        state->last_halt_ns = now;
    }
    
    struct vcpu_sched_event event = {};
    event.pid = pid;
    event.vcpu_id = vcpu_id;
    event.timestamp = now;
    event.event_type = VCPU_HALT;
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    events.ringbuf_output(&event, sizeof(event), 0);
    
    return 0;
}

/* Tracepoint: kvm_vcpu_wakeup */
SEC("tracepoint/kvm/kvm_vcpu_wakeup")
int trace_kvm_vcpu_wakeup(void *ctx)
{
    u32 vcpu_id = 0;
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct evpm_vcpu_state *state = vcpu_states.lookup(&vcpu_id);
    if (state && state->last_halt_ns > 0) {
        u64 halt_duration = now - state->last_halt_ns;
        state->total_halt_ns += halt_duration;
        
        struct vcpu_sched_event event = {};
        event.pid = pid;
        event.vcpu_id = vcpu_id;
        event.timestamp = now;
        event.event_type = VCPU_WAKEUP;
        event.duration_ns = halt_duration;
        bpf_get_current_comm(event.comm, sizeof(event.comm));
        events.ringbuf_output(&event, sizeof(event), 0);
    }
    
    return 0;
}
