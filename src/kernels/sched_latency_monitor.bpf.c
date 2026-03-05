/*
 * eBPF VM Performance Monitor - Scheduling Latency Monitor
 * 
 * Monitors scheduling latency for vCPU threads
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_PIDS 1024
#define LATENCY_BUCKETS 20

/* Scheduling event */
struct sched_event {
    __u32 pid;
    __u32 vcpu_id;
    __u64 enqueue_ts;
    __u64 dequeue_ts;
    __u64 latency_ns;
    char comm[TASK_COMM_LEN];
};

/* Per-task scheduling state */
struct evpm_evpm_sched_state {
    __u64 enqueue_ts;
    __u32 vcpu_id;
};

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} sched_events SEC("maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, __u32);
    __type(value, struct evpm_evpm_sched_state);
} evpm_sched_states SEC("maps");

/* Latency histogram (in microseconds) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, LATENCY_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} latency_hist SEC("maps");

/* Configuration: threshold for high latency events (default: 10ms) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} latency_threshold SEC("maps");

/* Helper: Check if task is QEMU/KVM process */
static __always_inline bool is_qemu_task(struct task_struct *task)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    
    /* Check for qemu-system-*, qemu-kvm, or kvms */
    if (comm[0] == 'q' && comm[1] == 'e' && comm[2] == 'm' && comm[3] == 'u')
        return true;
    if (comm[0] == 'k' && comm[1] == 'v' && comm[2] == 'm')
        return true;
    
    return false;
}

/* Helper: Get vCPU ID from task comm (e.g., "qemu-system-86_64" -> extract CPU num) */
static __always_inline __u32 extract_vcpu_id(struct task_struct *task)
{
    /* For now, use PID as vCPU ID mapping.  The provided task pointer is unused. */
    return bpf_get_current_pid_tgid() >> 32;
}

/* Kprobe: enqueue_task_fair - Task is enqueued to run queue */
SEC("kprobe/enqueue_task_fair")
int BPF_KPROBE(trace_enqueue_task, struct rq *rq, struct task_struct *p, int flags)
{
    if (!is_qemu_task(p))
        return 0;
    
    /* retrieve PID without dereferencing task_struct */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();
    
    struct evpm_evpm_sched_state state = {};
    state.enqueue_ts = now;
    state.vcpu_id = extract_vcpu_id(p);
    
    bpf_map_update_elem(&evpm_sched_states, &pid, &state, BPF_ANY);
    
    return 0;
}

/* Kprobe: dequeue_task_fair - Task is dequeued from run queue */
SEC("kprobe/dequeue_task_fair")
int BPF_KPROBE(trace_dequeue_task, struct rq *rq, struct task_struct *p, int flags)
{
    if (!is_qemu_task(p))
        return 0;
    
    /* retrieve PID without dereferencing task_struct */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct evpm_evpm_sched_state *state = bpf_map_lookup_elem(&evpm_sched_states, &pid);
    
    if (!state || state->enqueue_ts == 0)
        return 0;
    
    __u64 now = bpf_ktime_get_ns();
    __u64 latency = now - state->enqueue_ts;
    
    /* Update histogram */
    __u64 latency_us = latency / 1000;
    __u32 bucket = 0;
    
    /* Log2 bucketing: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288 */
    #pragma unroll
    for (int i = 0; i < LATENCY_BUCKETS; i++) {
        if (latency_us < (1ULL << i)) {
            bucket = i;
            break;
        }
    }
    if (bucket >= LATENCY_BUCKETS)
        bucket = LATENCY_BUCKETS - 1;
    
    __u64 *count = bpf_map_lookup_elem(&latency_hist, &bucket);
    if (count) {
        (*count)++;
    }
    
    /* Send event if latency is high (> 10ms default) */
    __u32 thresh_key = 0;
    __u64 *threshold = bpf_map_lookup_elem(&latency_threshold, &thresh_key);
    __u64 thresh_ns = threshold ? *threshold : 10000000ULL; /* 10ms default */
    
    if (latency > thresh_ns) {
        struct sched_event *event = bpf_ringbuf_reserve(&sched_events, sizeof(*event), 0);
        if (event) {
            event->pid = pid;
            event->vcpu_id = state->vcpu_id;
            event->enqueue_ts = state->enqueue_ts;
            event->dequeue_ts = now;
            event->latency_ns = latency;
            bpf_get_current_comm(event->comm, sizeof(event->comm));
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    /* Clear state */
    state->enqueue_ts = 0;
    
    return 0;
}

/* Kprobe: finish_task_switch - Context switch completed */
SEC("kprobe/finish_task_switch")
int BPF_KPROBE(trace_finish_task_switch, struct task_struct *prev)
{
    /* we can use current task without dereferencing fields */
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    
    if (!is_qemu_task(current))
        return 0;
    
    /* Track when vCPU starts running */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();
    
    /* Could add more tracking here if needed */
    
    return 0;
}

/* Tracepoint: sched_switch handler removed to simplify compilation */
/*
SEC("tp/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    return 0;
}
*/

char LICENSE[] SEC("license") = "GPL";
