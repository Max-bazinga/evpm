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

/* minimal map definition used by BCC-style maps */
struct bpf_map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
};

/* prototypes for commonly used BPF helper functions with stub bodies */
static __inline void *bpf_map_lookup_elem(void *map, const void *key) { return (void *)0; }
static __inline int bpf_map_update_elem(void *map, const void *key,
                                       const void *value, u64 flags) { return 0; }
static __inline void *bpf_ringbuf_reserve(void *map, u32 size, u64 flags) { return (void *)0; }
static __inline int bpf_ringbuf_submit(void *event, u64 flags) { return 0; }
static __inline u64 bpf_ktime_get_ns(void) { return 0; }
static __inline u64 bpf_get_current_pid_tgid(void) { return 0; }
static __inline int bpf_get_current_comm(char *buf, u32 size) { return 0; }

#endif /* EVPM_BPF_HELPERS_H */
