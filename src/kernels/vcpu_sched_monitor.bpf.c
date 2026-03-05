/*
 * eBPF VM Performance Monitor - vCPU Scheduling Monitor (Working version)
 * 
 * Uses BPF_HASH instead of ring buffer due to BCC 0.26.0 issues
 */

/* Basic types */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define MAX_VCPUS 256

/* Event structure */
struct vcpu_event {
    u32 pid;
    u32 vcpu_id;
    u64 timestamp;
    u32 event_type;
    u64 duration_ns;
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

/* Maps */
BPF_HASH(events, u32, struct vcpu_event, 1024);
BPF_HASH(vcpu_states, u32, struct vcpu_state, MAX_VCPUS);

/* Event counter for unique keys */
BPF_ARRAY(event_counter, u32, 1);

/* Helper to get next event ID */
static __always_inline u32 get_next_event_id() {
    u32 key = 0;
    u32 *counter = event_counter.lookup(&key);
    if (counter) {
        u32 old_val = *counter;
        *counter = old_val + 1;
        return old_val;
    }
    return 0;
}

/* Tracepoint: kvm_exit */
TRACEPOINT_PROBE(kvm, kvm_exit) {
    u32 vcpu_id = args->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Update state
    struct vcpu_state *state = vcpu_states.lookup(&vcpu_id);
    if (!state) {
        struct vcpu_state new_state = {};
        new_state.last_run_ns = now;
        new_state.pid = pid;
        vcpu_states.update(&vcpu_id, &new_state);
    }
    
    // Store event
    u32 event_id = get_next_event_id();
    struct vcpu_event event = {};
    event.pid = pid;
    event.vcpu_id = vcpu_id;
    event.timestamp = now;
    event.event_type = 2; // EXIT
    events.update(&event_id, &event);
    
    return 0;
}

/* Tracepoint: kvm_entry */
TRACEPOINT_PROBE(kvm, kvm_entry) {
    u32 vcpu_id = args->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vcpu_state *state = vcpu_states.lookup(&vcpu_id);
    if (state && state->last_run_ns > 0) {
        u64 duration = now - state->last_run_ns;
        state->total_run_ns += duration;
        
        u32 event_id = get_next_event_id();
        struct vcpu_event event = {};
        event.pid = pid;
        event.vcpu_id = vcpu_id;
        event.timestamp = now;
        event.event_type = 1; // ENTRY
        event.duration_ns = duration;
        events.update(&event_id, &event);
    }
    
    return 0;
}
