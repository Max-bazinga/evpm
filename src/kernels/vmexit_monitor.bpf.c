/*
 * eBPF VM Performance Monitor - VM Exit Monitor
 * 
 * Monitors VM Exit events: count, reasons, duration
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} vmexit_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VCPUS);
    __type(key, u32);
    __type(value, struct vmexit_state);
} vmexit_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EXIT_REASONS);
    __type(key, u32);
    __type(value, struct vmexit_stat);
} vmexit_stats SEC(".maps");

/* Histogram for exit duration */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20);
    __type(key, u32);
    __type(value, u64);
} duration_hist SEC(".maps");

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
    
    u64 *count = bpf_map_lookup_elem(&duration_hist, &bucket);
    if (count) {
        (*count)++;
    } else {
        u64 init = 1;
        bpf_map_update_elem(&duration_hist, &bucket, &init, BPF_ANY);
    }
}

/* Tracepoint: kvm_exit */
SEC("tp/kvm/kvm_exit")
int trace_kvm_exit(struct trace_event_raw_kvm_exit *ctx)
{
    u32 vcpu_id = ctx->vcpu_id;
    u32 exit_reason = ctx->exit_reason;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    /* Store exit state */
    struct vmexit_state state = {};
    state.exit_ts = now;
    state.exit_reason = exit_reason;
    bpf_map_update_elem(&vmexit_states, &vcpu_id, &state, BPF_ANY);
    
    /* Update statistics */
    struct vmexit_stat *stat = bpf_map_lookup_elem(&vmexit_stats, &exit_reason);
    if (stat) {
        stat->count++;
    } else {
        struct vmexit_stat new_stat = {};
        new_stat.count = 1;
        new_stat.min_duration_ns = ~0ULL;
        bpf_map_update_elem(&vmexit_stats, &exit_reason, &new_stat, BPF_ANY);
    }
    
    return 0;
}

/* Tracepoint: kvm_entry */
SEC("tp/kvm/kvm_entry")
int trace_kvm_entry(struct trace_event_raw_kvm_entry *ctx)
{
    u32 vcpu_id = ctx->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vmexit_state *state = bpf_map_lookup_elem(
        &vmexit_states, &vcpu_id);
    if (!state || state->exit_ts == 0)
        return 0;
    
    u64 duration = now - state->exit_ts;
    u32 exit_reason = state->exit_reason;
    
    /* Update statistics */
    struct vmexit_stat *stat = bpf_map_lookup_elem(
        &vmexit_stats, &exit_reason);
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
    struct vmexit_event *event = bpf_ringbuf_reserve(
        &vmexit_events, sizeof(*event), 0);
    if (event) {
        event->pid = pid;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->exit_reason = exit_reason;
        event->exit_qualification = 0;
        event->guest_rip = state->guest_rip;
        event->duration_ns = duration;
        bpf_ringbuf_submit(event, 0);
    }
    
    /* Clear state */
    state->exit_ts = 0;
    
    return 0;
}

/* Kprobe: handle_exit (for additional exit handling analysis) */
SEC("kprobe/kvm_x86_ops->handle_exit")
int BPF_KPROBE(trace_handle_exit, struct kvm_vcpu *vcpu)
{
    u32 vcpu_id = BPF_CORE_READ(vcpu, vcpu_id);
    u64 now = bpf_ktime_get_ns();
    
    /* Just for tracking exit handling start time */
    struct vmexit_state *state = bpf_map_lookup_elem(
        &vmexit_states, &vcpu_id);
    if (state) {
        state->guest_rip = now;
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
