/*
 * eBPF VM Performance Monitor - vCPU Scheduling Monitor
 * 
 * Monitors vCPU lifecycle: run, halt, wakeup, schedule latency
 */

#include <uapi/linux/bpf.h>

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

/* Maps - BCC style with BPF_ macros */
BPF_RINGBUF(events, 256 * 1024);
BPF_HASH(vcpu_states, u32, struct vcpu_state, MAX_VCPUS);
BPF_HASH(sched_latencies, u32, u64, 1);

/* Tracepoint: kvm_vcpu_run_begin */
TRACEPOINT_PROBE(kvm, kvm_vcpu_run_begin) {
    u32 vcpu_id = args->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    /* Update vCPU state */
    struct vcpu_state *state = vcpu_states.lookup(&vcpu_id);
    if (!state) {
        struct vcpu_state new_state = {};
        new_state.last_run_ns = now;
        new_state.pid = pid;
        vcpu_states.update(&vcpu_id, &new_state);
    } else {
        state->last_run_ns = now;
        state->pid = pid;
        state->schedule_count++;
    }
    
    /* Send event */
    struct vcpu_sched_event *event = events.ringbuf_reserve(sizeof(*event));
    if (event) {
        event->pid = pid;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = VCPU_RUN_BEGIN;
        event->duration_ns = 0;
        bpf_get_current_comm(event->comm, sizeof(event->comm));
        events.ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Tracepoint: kvm_vcpu_run_end */
TRACEPOINT_PROBE(kvm, kvm_vcpu_run_end) {
    u32 vcpu_id = args->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vcpu_state *state = vcpu_states.lookup(&vcpu_id);
    if (state && state->last_run_ns > 0) {
        u64 duration = now - state->last_run_ns;
        state->total_run_ns += duration;
        
        /* Send event with duration */
        struct vcpu_sched_event *event = events.ringbuf_reserve(sizeof(*event));
        if (event) {
            event->pid = pid;
            event->vcpu_id = vcpu_id;
            event->timestamp = now;
            event->event_type = VCPU_RUN_END;
            event->duration_ns = duration;
            bpf_get_current_comm(event->comm, sizeof(event->comm));
            events.ringbuf_submit(event, 0);
        }
    }
    
    return 0;
}

/* Tracepoint: kvm_vcpu_halt */
TRACEPOINT_PROBE(kvm, kvm_vcpu_halt) {
    u32 vcpu_id = args->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vcpu_state *state = vcpu_states.lookup(&vcpu_id);
    if (state) {
        state->last_halt_ns = now;
    }
    
    struct vcpu_sched_event *event = events.ringbuf_reserve(sizeof(*event));
    if (event) {
        event->pid = pid;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = VCPU_HALT;
        event->duration_ns = 0;
        bpf_get_current_comm(event->comm, sizeof(event->comm));
        events.ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Tracepoint: kvm_vcpu_wakeup */
TRACEPOINT_PROBE(kvm, kvm_vcpu_wakeup) {
    u32 vcpu_id = args->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vcpu_state *state = vcpu_states.lookup(&vcpu_id);
    if (state && state->last_halt_ns > 0) {
        u64 halt_duration = now - state->last_halt_ns;
        state->total_halt_ns += halt_duration;
        
        struct vcpu_sched_event *event = events.ringbuf_reserve(sizeof(*event));
        if (event) {
            event->pid = pid;
            event->vcpu_id = vcpu_id;
            event->timestamp = now;
            event->event_type = VCPU_WAKEUP;
            event->duration_ns = halt_duration;
            bpf_get_current_comm(event->comm, sizeof(event->comm));
            events.ringbuf_submit(event, 0);
        }
    }
    
    return 0;
}

char LICENSE[] = "GPL";
