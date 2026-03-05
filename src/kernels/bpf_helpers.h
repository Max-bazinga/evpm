/*
 * Minimal BPF helper definitions for eVPM eBPF programs
 * This header is included by all .bpf.c files to provide
 * common type aliases, map definitions, and macros.
 */

#ifndef EVPM_BPF_HELPERS_H
#define EVPM_BPF_HELPERS_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <stdbool.h>

/* common type aliases (u32, u64, etc.) */
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

/* helper macros normally supplied by bpf/bpf_helpers.h */
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif
#ifndef BPF_KPROBE
#define BPF_KPROBE(NAME, ...) NAME(__VA_ARGS__)
#endif

/* map type constants (fallback values) */
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY 2
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
#ifndef BPF_MAP_TYPE_PERF_EVENT_ARRAY
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#endif

#ifndef BPF_ANY
#define BPF_ANY 0
#endif


/* Stub for trace_event_raw_kvm_io */
struct trace_event_raw_kvm_io {
    u32 vcpu_id;
    u32 type; /* 0 = read, 1 = write */
    u32 port;
    u32 len;
    u64 val;
};

/* Stub for trace_event_raw_kvm_mmio */
struct trace_event_raw_kvm_mmio {
    u32 vcpu_id;
    u32 type; /* 0 = read, 1 = write */
    u64 phys_addr;
    u32 len;
    u64 val;
};

/* Stub for trace_event_raw_kvm_vmexit */
struct trace_event_raw_kvm_vmexit {
    u32 vcpu_id;
    u32 exit_reason;
    u64 rip;
    u64 guest_rip;
    u32 isa;
    u32 info1;
    u32 info2;
    u32 intr_info;
    u32 error_code;
    u32 vector;
    u32 flags;
    u64 pad;
};

/* Stub for trace_event_raw_sched_switch */
struct trace_event_raw_sched_switch {
    char prev_comm[16];
    u32 prev_pid;
    u32 prev_prio;
    u64 prev_state;
    char next_comm[16];
    u32 next_pid;
    u32 next_prio;
};
static __inline void *bpf_map_lookup_elem(void *map, const void *key) { return (void *)0; }
static __inline int bpf_map_update_elem(void *map, const void *key,
                                       const void *value, u64 flags) { return 0; }
static __inline void *bpf_ringbuf_reserve(void *map, u32 size, u64 flags) { return (void *)0; }
static __inline int bpf_ringbuf_submit(void *event, u64 flags) { return 0; }
static __inline u64 bpf_ktime_get_ns(void) { return 0; }
static __inline u64 bpf_get_current_pid_tgid(void) { return 0; }
static __inline int bpf_get_current_comm(char *buf, u32 size) { return 0; }

#endif /* EVPM_BPF_HELPERS_H */
