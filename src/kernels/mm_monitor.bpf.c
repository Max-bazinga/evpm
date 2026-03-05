/*
 * eBPF VM Performance Monitor - Memory Virtualization Monitor
 * 
 * Monitors EPT/NPT page faults, TLB misses, and memory access patterns
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* minimal kernel type stubs to satisfy compilation without full vmlinux.h */
typedef __u64 gpa_t;
struct kvm_vcpu { __u32 vcpu_id; };
struct kvm_page_fault { };

struct trace_event_raw_kvm_page_fault {
    __u32 vcpu_id;
    __u64 gpa;
    __u64 gva;
    __u32 error_code;
};
struct trace_event_raw_kvm_mmu_page_zoom { };
struct trace_event_raw_kvm_mmio {
    __u32 vcpu_id;
    __u64 phys_addr;
    __u32 len;
};

#define MAX_VCPUS 256
#define MAX_FAULT_REASONS 16

/* Memory event types */
enum mm_event_type {
    MM_EPT_VIOLATION = 1,
    MM_PAGE_FAULT,
    MM_TLB_MISS,
    MM_MMIO_ACCESS,
};

/* Memory event */
struct mm_event {
    u32 pid;
    u32 vcpu_id;
    u64 timestamp;
    u32 event_type;
    u64 guest_pa;
    u64 guest_va;
    u32 error_code;
    u64 handle_duration_ns;
};

/* Per-vCPU memory statistics */
struct mm_stat {
    u64 page_fault_count;
    u64 ept_violation_count;
    u64 mmio_count;
    u64 total_handle_ns;
    u64 max_handle_ns;
};

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} mm_events SEC("maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VCPUS);
    __type(key, u32);
    __type(value, struct mm_stat);
} mm_stats SEC("maps");

/* Page fault handling state */
struct pf_state {
    u64 start_ts;
    u64 guest_pa;
    u64 guest_va;
    u32 error_code;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VCPUS);
    __type(key, u32);
    __type(value, struct pf_state);
} pf_states SEC("maps");

/* Error code flags */
#define PFERR_PRESENT_BIT 0
#define PFERR_WRITE_BIT 1
#define PFERR_USER_BIT 2
#define PFERR_RSVD_BIT 3
#define PFERR_FETCH_BIT 4
#define PFERR_PK_BIT 5
#define PFERR_SGX_BIT 15

/* Helper: Get human-readable error code description */
static __always_inline u32 decode_error_code(u32 error_code)
{
    return error_code; /* Pass through for user space decoding */
}

/* Tracepoint: kvm_page_fault - EPT/NPT page fault */
SEC("tp/kvm/kvm_page_fault")
int trace_kvm_page_fault(struct trace_event_raw_kvm_page_fault *ctx)
{
    u32 vcpu_id = ctx->vcpu_id;
    u64 guest_pa = ctx->gpa;
    u64 guest_va = ctx->gva;
    u32 error_code = ctx->error_code;
    u64 now = bpf_ktime_get_ns();
    
    /* Update statistics */
    struct mm_stat *stat = bpf_map_lookup_elem(&mm_stats, &vcpu_id);
    if (!stat) {
        struct mm_stat new_stat = {};
        new_stat.page_fault_count = 1;
        bpf_map_update_elem(&mm_stats, &vcpu_id, &new_stat, BPF_ANY);
    } else {
        stat->page_fault_count++;
    }
    
    /* Store state for duration tracking */
    struct pf_state new_state = {};
    new_state.start_ts = now;
    new_state.guest_pa = guest_pa;
    new_state.guest_va = guest_va;
    new_state.error_code = error_code;
    bpf_map_update_elem(&pf_states, &vcpu_id, &new_state, BPF_ANY);
    
    /* Send event */
    struct mm_event *event = bpf_ringbuf_reserve(&mm_events, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = MM_PAGE_FAULT;
        event->guest_pa = guest_pa;
        event->guest_va = guest_va;
        event->error_code = error_code;
        event->handle_duration_ns = 0;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Tracepoint: kvm_mmu_page_zoom - MMU page zoom (huge page) */
SEC("tp/kvm/kvm_mmu_page_zoom")
int trace_mmu_page_zoom(struct trace_event_raw_kvm_mmu_page_zoom *ctx)
{
    /* Track huge page usage */
    return 0;
}

/* Kprobe: handle_ept_violation - EPT violation handler entry */
SEC("kprobe/kvm_x86_ops->handle_ept_violation")
int BPF_KPROBE(trace_ept_violation_entry, struct kvm_vcpu *vcpu, 
               gpa_t gpa, u64 error_code)
{
    u32 vcpu_id = vcpu->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    
    struct mm_stat *stat = bpf_map_lookup_elem(&mm_stats, &vcpu_id);
    if (stat) {
        stat->ept_violation_count++;
    }
    
    /* Update state */
    struct pf_state *state = bpf_map_lookup_elem(&pf_states, &vcpu_id);
    if (state) {
        state->start_ts = now;
    }
    
    return 0;
}

/* Kprobe: tdp_page_fault - TDP (Two-Dimensional Paging) fault handler */
SEC("kprobe/tdp_page_fault")
int BPF_KPROBE(trace_tdp_page_fault, struct kvm_vcpu *vcpu, 
               struct kvm_page_fault *fault)
{
    u32 vcpu_id = vcpu->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    
    struct pf_state *state = bpf_map_lookup_elem(&pf_states, &vcpu_id);
    if (state && state->start_ts > 0) {
        u64 duration = now - state->start_ts;
        
        struct mm_stat *stat = bpf_map_lookup_elem(&mm_stats, &vcpu_id);
        if (stat) {
            stat->total_handle_ns += duration;
            if (duration > stat->max_handle_ns)
                stat->max_handle_ns = duration;
        }
        
        /* Send completion event */
        struct mm_event *event = bpf_ringbuf_reserve(
            &mm_events, sizeof(*event), 0);
        if (event) {
            event->pid = bpf_get_current_pid_tgid() >> 32;
            event->vcpu_id = vcpu_id;
            event->timestamp = now;
            event->event_type = MM_EPT_VIOLATION;
            event->guest_pa = state->guest_pa;
            event->guest_va = state->guest_va;
            event->error_code = state->error_code;
            event->handle_duration_ns = duration;
            bpf_ringbuf_submit(event, 0);
        }
        
        state->start_ts = 0;
    }
    
    return 0;
}

/* Kprobe: kvm_arch_vcpu_load - vCPU load (TLB flush tracking) */
SEC("kprobe/kvm_arch_vcpu_load")
int BPF_KPROBE(trace_vcpu_load, struct kvm_vcpu *vcpu, int cpu)
{
    /* Track vCPU migration between physical CPUs (TLB implications) */
    u32 vcpu_id = vcpu->vcpu_id;
    u32 new_cpu = cpu;
    
    /* Could track vCPU pinning/migration patterns */
    
    return 0;
}

/* Tracepoint: kvm_mmio - MMIO access */
SEC("tp/kvm/kvm_mmio")
int trace_kvm_mmio(struct trace_event_raw_kvm_mmio *ctx)
{
    u32 vcpu_id = ctx->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    
    struct mm_stat *stat = bpf_map_lookup_elem(&mm_stats, &vcpu_id);
    if (stat) {
        stat->mmio_count++;
    }
    
    struct mm_event *event = bpf_ringbuf_reserve(
        &mm_events, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = MM_MMIO_ACCESS;
        event->guest_pa = ctx->phys_addr;
        event->guest_va = 0;
        event->error_code = ctx->len;
        event->handle_duration_ns = 0;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
