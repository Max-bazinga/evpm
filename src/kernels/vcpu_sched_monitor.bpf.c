/*
 * eBPF VM Performance Monitor - vCPU Scheduling Monitor (Kprobe version)
 */

/* Basic types */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

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
 * Kprobe on kvm_vcpu_run (called when vCPU starts running)
 * This is a simpler alternative to tracepoints
 */
int trace_vcpu_run(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // vcpu_id would need to be extracted from vcpu struct
    // For now use PID as identifier
    u32 vcpu_id = pid;
    
    struct evpm_vcpu_state *state = vcpu_states.lookup(&vcpu_id);
    if (!state) {
        struct evpm_vcpu_state new_state = {};
        new_state.last_run_ns = now;
        new_state.pid = pid;
        vcpu_states.update(&vcpu_id, &new_state);
    } else {
        state->last_run_ns = now;
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
