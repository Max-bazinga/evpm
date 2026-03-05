/*
 * eBPF VM Performance Monitor - Memory Virtualization Monitor
 * 
 * Monitors EPT/NPT page faults, TLB misses, and memory access patterns
 * Compatible version without BPF_KPROBE
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Forward declarations - use void* to avoid kernel struct definitions */
typedef __u64 gpa_t;

struct mm_event {
    u32 pid;
    u32 vcpu_id;
    u64 timestamp;
    u32 event_type;
    u64 gpa;
    u64 gva;
    u32 error_code;
    u64 duration_ns;
};

#define MAX_VCPUS 256
#define MAX_FAULT_REASONS 16

/* Event types */
enum mm_event_type {
    MM_PAGE_FAULT = 1,
    MM_EPT_VIOLATION,
    MM_TLB_MISS,
    MM_MMU_ZOOM,
    MM_MMIO_ACCESS,
    MM_VCPU_LOAD,
};

/* Per-vCPU MM statistics */
struct mm_stat {
    u64 page_fault_count;
    u64 ept_violation_count;
    u64 mmio_count;
    u64 tlb_miss_count;
    u64 total_fault_ns;
    u64 max_fault_ns;
};

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} mm_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VCPUS);
    __type(key, u32);
    __type(value, struct mm_stat);
} mm_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VCPUS);
    __type(key, u32);
    __type(value, u64);
} fault_start_ts SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

/* Helper: update MM stats */
static __always_inline void update_mm_stats(u32 vcpu_id, u32 event_type, u64 duration)
{
    struct mm_stat *stat = bpf_map_lookup_elem(&mm_stats, &vcpu_id);
    if (!stat) {
        struct mm_stat new_stat = {};
        if (event_type == MM_PAGE_FAULT)
            new_stat.page_fault_count = 1;
        else if (event_type == MM_EPT_VIOLATION)
            new_stat.ept_violation_count = 1;
        else if (event_type == MM_MMIO_ACCESS)
            new_stat.mmio_count = 1;
        else if (event_type == MM_TLB_MISS)
            new_stat.tlb_miss_count = 1;
        bpf_map_update_elem(&mm_stats, &vcpu_id, &new_stat, BPF_ANY);
    } else {
        if (event_type == MM_PAGE_FAULT)
            stat->page_fault_count++;
        else if (event_type == MM_EPT_VIOLATION)
            stat->ept_violation_count++;
        else if (event_type == MM_MMIO_ACCESS)
            stat->mmio_count++;
        else if (event_type == MM_TLB_MISS)
            stat->tlb_miss_count++;
        stat->total_fault_ns += duration;
        if (duration > stat->max_fault_ns)
            stat->max_fault_ns = duration;
    }
}

/* Tracepoint: kvm_page_fault - EPT/NPT page fault */
/* Layout: trace_entry (8) + vcpu_id (4) + gpa (8) + gva (8) + error_code (4) */
SEC("tp/kvm/kvm_page_fault")
int trace_kvm_page_fault(void *ctx)
{
    u32 vcpu_id = 0;
    u64 gpa = 0, gva = 0;
    u32 error_code = 0;
    
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    bpf_probe_read_kernel(&gpa, sizeof(gpa), ctx + 16);
    bpf_probe_read_kernel(&gva, sizeof(gva), ctx + 24);
    bpf_probe_read_kernel(&error_code, sizeof(error_code), ctx + 32);
    
    u64 now = bpf_ktime_get_ns();
    
    /* Record fault start time for duration calculation */
    bpf_map_update_elem(&fault_start_ts, &vcpu_id, &now, BPF_ANY);
    
    struct mm_event *event = bpf_ringbuf_reserve(
        &mm_events, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = MM_PAGE_FAULT;
        event->gpa = gpa;
        event->gva = gva;
        event->error_code = error_code;
        event->duration_ns = 0;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Kprobe: kvm_mmu_page_fault entry - TDP page fault start */
SEC("kprobe/kvm_mmu_page_fault")
int trace_mmu_page_fault_entry(void *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 vcpu_id = 0; /* Could extract from vcpu pointer at offset */
    
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    bpf_map_update_elem(&fault_start_ts, &vcpu_id, &now, BPF_ANY);
    
    return 0;
}

/* Kprobe: kvm_mmu_page_fault exit - TDP page fault end */
SEC("kprobe/kvm_mmu_page_fault")
int trace_mmu_page_fault_exit(void *ctx)
{
    u32 vcpu_id = 0;
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    
    u64 now = bpf_ktime_get_ns();
    u64 *start = bpf_map_lookup_elem(&fault_start_ts, &vcpu_id);
    
    if (start) {
        u64 duration = now - *start;
        update_mm_stats(vcpu_id, MM_PAGE_FAULT, duration);
        
        struct mm_event *event = bpf_ringbuf_reserve(
            &mm_events, sizeof(*event), 0);
        if (event) {
            event->pid = bpf_get_current_pid_tgid() >> 32;
            event->vcpu_id = vcpu_id;
            event->timestamp = now;
            event->event_type = MM_EPT_VIOLATION;
            event->gpa = 0;
            event->gva = 0;
            event->error_code = 0;
            event->duration_ns = duration;
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return 0;
}

/* Tracepoint: kvm_mmio - MMIO access */
/* Layout: trace_entry (8) + vcpu_id (4) + phys_addr (8) + len (4) */
SEC("tp/kvm/kvm_mmio")
int trace_kvm_mmio(void *ctx)
{
    u32 vcpu_id = 0;
    u64 phys_addr = 0;
    u32 len = 0;
    
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    bpf_probe_read_kernel(&phys_addr, sizeof(phys_addr), ctx + 16);
    bpf_probe_read_kernel(&len, sizeof(len), ctx + 24);
    
    u64 now = bpf_ktime_get_ns();
    update_mm_stats(vcpu_id, MM_MMIO_ACCESS, 0);
    
    struct mm_event *event = bpf_ringbuf_reserve(
        &mm_events, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = MM_MMIO_ACCESS;
        event->gpa = phys_addr;
        event->gva = 0;
        event->error_code = len;
        event->duration_ns = 0;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Kprobe: vcpu_load - vCPU memory context load */
SEC("kprobe/vcpu_load")
int trace_vcpu_load(void *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 vcpu_id = 0;
    
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    
    struct mm_event *event = bpf_ringbuf_reserve(
        &mm_events, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = MM_VCPU_LOAD;
        event->gpa = 0;
        event->gva = 0;
        event->error_code = 0;
        event->duration_ns = 0;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}
