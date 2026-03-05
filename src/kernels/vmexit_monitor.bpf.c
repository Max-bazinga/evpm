/*
 * eBPF VM Performance Monitor - VM Exit Monitor (Pure BCC)
 * 
 * Monitors VM Exit events: count, reasons, duration
 * NO includes needed - BCC provides everything
 */

/* Basic types */

/* SEC macro for section attributes */
#define SEC(NAME) __attribute__((section(NAME), used))typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;

#define MAX_EXIT_REASONS 256
#define MAX_VCPUS 256

/* VM Exit event */
struct vmexit_event {
    u32 pid;
    u32 vcpu_id;
    u64 timestamp;
    u32 exit_reason;
    u64 exit_qualification;
    u64 guest_rip;
    u64 duration_ns;
};

/* Per-vCPU VM Exit state */
struct vmexit_state {
    u64 exit_ts;
    u32 exit_reason;
    u64 guest_rip;
};

/* Statistics per exit reason */
struct vmexit_stat {
    u64 count;
    u64 total_duration_ns;
    u64 max_duration_ns;
    u64 min_duration_ns;
};

/* Maps - BCC style */
BPF_RINGBUF_OUTPUT(vmexit_events, 512 * 1024);
BPF_HASH(vmexit_states, u32, struct vmexit_state, MAX_VCPUS);
BPF_HASH(vmexit_stats, u32, struct vmexit_stat, MAX_EXIT_REASONS);
BPF_HASH(duration_hist, u32, u64, 20);

/* Pre-defined duration buckets (in microseconds) */
static const u64 DURATION_BUCKETS[] = {
    1, 5, 10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000
};

static __always_inline void update_duration_hist(u64 duration_ns)
{
    u64 duration_us = duration_ns / 1000;
    u32 bucket = 0;
    
    #pragma unroll
    for (int i = 0; i < 13; i++) {
        if (duration_us <= DURATION_BUCKETS[i]) {
            bucket = i;
            break;
        }
    }
    if (bucket == 0 && duration_us > 1000000)
        bucket = 19;
    
    u64 *count = duration_hist.lookup(&bucket);
    if (count) {
        (*count)++;
    } else {
        u64 init = 1;
        duration_hist.update(&bucket, &init);
    }
}

/* Tracepoint: kvm_exit */
TRACEPOINT_PROBE(kvm, kvm_exit) {
    u32 vcpu_id = args->vcpu_id;
    u32 exit_reason = args->exit_reason;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    /* Store exit state */
    struct vmexit_state state = {};
    state.exit_ts = now;
    state.exit_reason = exit_reason;
    vmexit_states.update(&vcpu_id, &state);
    
    /* Update statistics */
    struct vmexit_stat *stat = vmexit_stats.lookup(&exit_reason);
    if (stat) {
        stat->count++;
    } else {
        struct vmexit_stat new_stat = {};
        new_stat.count = 1;
        new_stat.min_duration_ns = ~0ULL;
        vmexit_stats.update(&exit_reason, &new_stat);
    }
    
    return 0;
}

/* Tracepoint: kvm_entry */
TRACEPOINT_PROBE(kvm, kvm_entry) {
    u32 vcpu_id = args->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vmexit_state *state = vmexit_states.lookup(&vcpu_id);
    if (!state || state->exit_ts == 0)
        return 0;
    
    u64 duration = now - state->exit_ts;
    u32 exit_reason = state->exit_reason;
    
    /* Update statistics */
    struct vmexit_stat *stat = vmexit_stats.lookup(&exit_reason);
    if (stat) {
        stat->total_duration_ns += duration;
        if (duration > stat->max_duration_ns)
            stat->max_duration_ns = duration;
        if (duration < stat->min_duration_ns)
            stat->min_duration_ns = duration;
    }
    
    /* Update histogram */
    update_duration_hist(duration);
    
    /* Send event */
    struct vmexit_event event = {};
    event.pid = pid;
    event.vcpu_id = vcpu_id;
    event.timestamp = now;
    event.exit_reason = exit_reason;
    event.exit_qualification = 0;
    event.guest_rip = state->guest_rip;
    event.duration_ns = duration;
    vmexit_events.ringbuf_output(&event, sizeof(event), 0);
    
    /* Clear state */
    state->exit_ts = 0;
    
    return 0;
}
