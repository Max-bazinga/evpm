/*
 * eBPF VM Performance Monitor - Scheduling Latency Monitor (Pure BCC)
 * 
 * Monitors scheduling latency for vCPU threads
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

#define TASK_COMM_LEN 16
#define MAX_PIDS 1024
#define LATENCY_BUCKETS 20

/* Scheduling event */
struct sched_event {
    u32 pid;
    u32 vcpu_id;
    u64 enqueue_ts;
    u64 dequeue_ts;
    u64 latency_ns;
    char comm[TASK_COMM_LEN];
};

/* Per-task scheduling state */
struct evpm_sched_state {
    u64 enqueue_ts;
    u32 vcpu_id;
};

/* Maps - BCC style */
BPF_RINGBUF_OUTPUT(sched_events, 256 * 1024);
BPF_HASH(evpm_sched_states, u32, struct evpm_sched_state, MAX_PIDS);
BPF_HASH(latency_hist, u32, u64, LATENCY_BUCKETS);
BPF_HASH(latency_threshold, u32, u64, 1);

/* Helper: Check if task is QEMU/KVM process */
static __always_inline bool is_qemu_task(char *comm)
{
    /* Check for qemu-system-*, qemu-kvm, or kvms */
    if (comm[0] == 'q' && comm[1] == 'e' && comm[2] == 'm' && comm[3] == 'u')
        return true;
    if (comm[0] == 'k' && comm[1] == 'v' && comm[2] == 'm')
        return true;
    return false;
}

/* Tracepoint: sched_switch - Context switch */
TRACEPOINT_PROBE(sched, sched_switch) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    
    if (!is_qemu_task(comm))
        return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 now = bpf_ktime_get_ns();
    
    /* For simplicity, just track the enqueue time */
    struct evpm_sched_state *state = evpm_sched_states.lookup(&pid);
    if (state && state->enqueue_ts > 0) {
        u64 latency = now - state->enqueue_ts;
        
        /* Log2 bucketing */
        u64 latency_us = latency / 1000;
        u32 bucket = 0;
        #pragma unroll
        for (int i = 0; i < LATENCY_BUCKETS; i++) {
            if (latency_us < (1ULL << i)) {
                bucket = i;
                break;
            }
        }
        if (bucket >= LATENCY_BUCKETS)
            bucket = LATENCY_BUCKETS - 1;
        
        u64 *count = latency_hist.lookup(&bucket);
        if (count) {
            (*count)++;
        } else {
            u64 init = 1;
            latency_hist.update(&bucket, &init);
        }
        
        /* Send event if high latency (> 10ms) */
        if (latency > 10000000ULL) {
            struct sched_event event = {};
            event.pid = pid;
            event.vcpu_id = state->vcpu_id;
            event.enqueue_ts = state->enqueue_ts;
            event.dequeue_ts = now;
            event.latency_ns = latency;
            bpf_get_current_comm(event.comm, sizeof(event.comm));
            sched_events.ringbuf_output(&event, sizeof(event), 0);
        }
        
        /* Clear state */
        state->enqueue_ts = 0;
    }
    
    return 0;
}

/* Kprobe: enqueue_task_fair - Task is enqueued */
int trace_enqueue_task_fair(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 now = bpf_ktime_get_ns();
    
    struct evpm_sched_state state = {};
    state.enqueue_ts = now;
    state.vcpu_id = pid; /* Use PID as vCPU ID for now */
    evpm_sched_states.update(&pid, &state);
    
    return 0;
}
