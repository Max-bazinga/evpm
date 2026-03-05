/*
 * eBPF VM Performance Monitor - Memory Virtualization Monitor (Pure BCC)
 * 
 * Monitors EPT/NPT page faults, TLB misses, and memory access patterns
 * NO includes needed - BCC provides everything
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

/* MM event */
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

/* Per-vCPU MM statistics */
struct mm_stat {
    u64 page_fault_count;
    u64 ept_violation_count;
    u64 mmio_count;
    u64 tlb_miss_count;
    u64 total_fault_ns;
    u64 max_fault_ns;
};

/* Maps - BCC style */
BPF_RINGBUF_OUTPUT(mm_events, 512 * 1024);
BPF_HASH(mm_stats, u32, struct mm_stat, MAX_VCPUS);
BPF_HASH(fault_start_ts, u32, u64, MAX_VCPUS);

/* Helper: update MM stats */
static __always_inline void update_mm_stats(u32 vcpu_id, u32 event_type, u64 duration)
{
    struct mm_stat *stat = mm_stats.lookup(&vcpu_id);
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
        mm_stats.update(&vcpu_id, &new_stat);
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
TRACEPOINT_PROBE(kvm, kvm_page_fault) {
    u32 vcpu_id = args->vcpu_id;
    u64 gpa = args->gpa;
    u64 gva = args->gva;
    u32 error_code = args->error_code;
    u64 now = bpf_ktime_get_ns();
    
    /* Record fault start time */
    fault_start_ts.update(&vcpu_id, &now);
    
    struct mm_event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.vcpu_id = vcpu_id;
    event.timestamp = now;
    event.event_type = MM_PAGE_FAULT;
    event.gpa = gpa;
    event.gva = gva;
    event.error_code = error_code;
    mm_events.ringbuf_output(&event, sizeof(event), 0);
    
    return 0;
}

/* Tracepoint: kvm_mmio - MMIO access */
TRACEPOINT_PROBE(kvm, kvm_mmio) {
    u32 vcpu_id = args->vcpu_id;
    u64 phys_addr = args->phys_addr;
    u32 len = args->len;
    u64 now = bpf_ktime_get_ns();
    
    update_mm_stats(vcpu_id, MM_MMIO_ACCESS, 0);
    
    struct mm_event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.vcpu_id = vcpu_id;
    event.timestamp = now;
    event.event_type = MM_MMIO_ACCESS;
    event.gpa = phys_addr;
    event.error_code = len;
    mm_events.ringbuf_output(&event, sizeof(event), 0);
    
    return 0;
}
