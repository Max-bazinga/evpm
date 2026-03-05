/*
 * eBPF VM Performance Monitor - I/O Virtualization Monitor
 * 
 * Monitors Virtio, MMIO, PIO, and interrupt handling
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* dummy types for IRQ probes */
struct kvm_kernel_irq_routing_entry { };

#define MAX_VCPUS 256
#define MAX_VQS 256

/* I/O event types */
enum io_event_type {
    IO_VIRTIO_NOTIFY = 1,
    IO_MMIO_READ,
    IO_MMIO_WRITE,
    IO_PIO_READ,
    IO_PIO_WRITE,
    IO_IRQ_INJECT,
    IO_IRQ_ACK,
};

/* Per-device I/O statistics */
struct io_stat {
    u64 notify_count;
    u64 irq_count;
    u64 total_handle_ns;
    u64 max_handle_ns;
};

/* Virtqueue state */
struct vq_state {
    u64 notify_ts;
    u32 device_id;
    u16 vq_index;
};

/* I/O event for ring buffer - renamed to avoid conflict with vmlinux.h */
struct evpm_io_event {
    u32 pid;
    u32 vcpu_id;
    u64 timestamp;
    u32 event_type;
    u32 device_id;
    u16 vq_id;
    u64 duration_ns;
    u32 data_len;
};

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} io_events SEC("maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VQS);
    __type(key, u32);
    __type(value, struct vq_state);
} vq_states SEC("maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, u32);
    __type(value, struct io_stat);
} io_stats SEC("maps");

/* Counter for generating unique vq IDs */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} vq_id_counter SEC("maps");

/* Tracepoint: kvm_io - Port I/O
 * Use probe_read to handle missing BTF definitions
 */
SEC("tp/kvm/kvm_io")
int trace_kvm_io(void *ctx)
{
    /* 
     * trace_event_raw_kvm_io layout (may vary by kernel version):
     * struct trace_entry ent;  // 8 bytes
     * unsigned int vcpu_id;    // offset 8, size 4
     * u32 type;                // offset 12, size 4
     * u32 port;                // offset 16, size 4
     * u32 len;                 // offset 20, size 4
     */
    u32 vcpu_id = 0, type = 0, port = 0, len = 0;
    
    /* Use bpf_probe_read_kernel to safely access fields */
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    bpf_probe_read_kernel(&type, sizeof(type), ctx + 12);
    bpf_probe_read_kernel(&port, sizeof(port), ctx + 16);
    bpf_probe_read_kernel(&len, sizeof(len), ctx + 20);
    
    u64 now = bpf_ktime_get_ns();
    
    struct evpm_io_event *event = bpf_ringbuf_reserve(
        &io_events, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = (type == 0) ? IO_PIO_READ : IO_PIO_WRITE;
        event->device_id = port;
        event->vq_id = 0;
        event->duration_ns = 0;
        event->data_len = len;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Tracepoint: virtio_device_ready */
SEC("tp/virtio/virtio_device_ready")
int trace_virtio_device_ready(void *ctx)
{
    /* Track device initialization */
    return 0;
}

/* Tracepoint: virtio_queue_notify
 * Layout: trace_entry (8) + vcpu_id (4) + queue_id (4) + ...
 */
SEC("tp/virtio/virtio_queue_notify")
int trace_virtio_queue_notify(void *ctx)
{
    u32 vcpu_id = 0, queue_id = 0;
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    bpf_probe_read_kernel(&queue_id, sizeof(queue_id), ctx + 12);
    
    u64 now = bpf_ktime_get_ns();
    
    /* Generate unique vq ID */
    u32 counter_key = 0;
    u32 *counter = bpf_map_lookup_elem(&vq_id_counter, &counter_key);
    u32 vq_id = 0;
    if (counter) {
        vq_id = *counter;
        (*counter)++;
    }
    
    /* Store notify timestamp */
    struct vq_state state = {};
    state.notify_ts = now;
    state.device_id = 0;
    state.vq_index = queue_id;
    bpf_map_update_elem(&vq_states, &vq_id, &state, BPF_ANY);
    
    /* Update stats */
    struct io_stat *stat = bpf_map_lookup_elem(&io_stats, &state.device_id);
    if (stat) {
        stat->notify_count++;
    }
    
    struct evpm_io_event *event = bpf_ringbuf_reserve(
        &io_events, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = IO_VIRTIO_NOTIFY;
        event->device_id = state.device_id;
        event->vq_id = queue_id;  /* Use already read value */
        event->duration_ns = 0;
        event->data_len = 0;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}
/* (removed duplicate trace_kvm_io) */
/* Tracepoint: kvm_ack_irq - IRQ acknowledgment
 * Layout: trace_entry (8) + vcpu_id (4) + irq (4) + ...
 */
SEC("tp/kvm/kvm_ack_irq")
int trace_kvm_ack_irq(void *ctx)
{
    u32 vcpu_id = 0, irq = 0;
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu_id), ctx + 8);
    bpf_probe_read_kernel(&irq, sizeof(irq), ctx + 12);
    
    u64 now = bpf_ktime_get_ns();
    
    struct evpm_io_event *event = bpf_ringbuf_reserve(
        &io_events, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = IO_IRQ_ACK;
        event->device_id = irq;
        event->vq_id = 0;
        event->duration_ns = 0;
        event->data_len = 0;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Kprobe: ioeventfd_write - IO eventfd write (fast path notification) */
SEC("kprobe/ioeventfd_write")
int BPF_KPROBE(trace_ioeventfd_write, void *fd, struct kvm_vcpu *vcpu)
{
    /* Track ioeventfd-based notifications (fast I/O path) */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
