/*
 * eBPF VM Performance Monitor - I/O Virtualization Monitor (Pure BCC)
 * 
 * Monitors Virtio, MMIO, PIO, and interrupt handling
 * NO includes needed - BCC provides everything
 */

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

/* I/O event for ring buffer */
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

/* Maps - BCC style */
BPF_RINGBUF_OUTPUT(io_events, 512 * 1024);
BPF_HASH(vq_states, u32, struct vq_state, MAX_VQS);
BPF_HASH(io_stats, u32, struct io_stat, 32);

/* Tracepoint: kvm_io - Port I/O */
TRACEPOINT_PROBE(kvm, kvm_io) {
    u32 vcpu_id = args->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 type = args->type; /* 0 = read, 1 = write */
    u32 port = args->port;
    u32 len = args->len;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct evpm_io_event event = {};
    event.pid = pid;
    event.vcpu_id = vcpu_id;
    event.timestamp = now;
    event.event_type = (type == 0) ? IO_PIO_READ : IO_PIO_WRITE;
    event.device_id = port;
    event.vq_id = 0;
    event.duration_ns = 0;
    event.data_len = len;
    io_events.ringbuf_output(&event, sizeof(event), 0);
    
    return 0;
}

/* Tracepoint: virtio_device_ready */
TRACEPOINT_PROBE(virtio, virtio_device_ready) {
    /* Track device initialization */
    return 0;
}

/* Tracepoint: virtio_queue_notify */
TRACEPOINT_PROBE(virtio, virtio_queue_notify) {
    u32 vq_index = args->vq;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct evpm_io_event event = {};
    event.pid = pid;
    event.vcpu_id = 0;
    event.timestamp = now;
    event.event_type = IO_VIRTIO_NOTIFY;
    event.device_id = 0;
    event.vq_id = (u16)vq_index;
    io_events.ringbuf_output(&event, sizeof(event), 0);
    
    return 0;
}

/* Kprobe: ioeventfd_write - IO eventfd write (fast path notification) */
int trace_ioeventfd_write(void *ctx) {
    /* Track ioeventfd-based notifications (fast I/O path) */
    return 0;
}

/* Tracepoint: kvm_ack_irq - IRQ acknowledgment */
TRACEPOINT_PROBE(kvm, kvm_ack_irq) {
    u32 vcpu_id = args->vcpu_id;
    u32 irq = args->irq;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct evpm_io_event event = {};
    event.pid = pid;
    event.vcpu_id = vcpu_id;
    event.timestamp = now;
    event.event_type = IO_IRQ_ACK;
    event.device_id = irq;
    event.data_len = 0;
    io_events.ringbuf_output(&event, sizeof(event), 0);
    
    return 0;
}

/* Tracepoint: kvm_mmio - MMIO access */
TRACEPOINT_PROBE(kvm, kvm_mmio) {
    u32 vcpu_id = args->vcpu_id;
    u64 phys_addr = args->phys_addr;
    u32 len = args->len;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct evpm_io_event event = {};
    event.pid = pid;
    event.vcpu_id = vcpu_id;
    event.timestamp = now;
    event.event_type = IO_MMIO_WRITE; /* Assume write for now */
    event.device_id = (u32)(phys_addr >> 12); /* Device ID from page */
    event.data_len = len;
    io_events.ringbuf_output(&event, sizeof(event), 0);
    
    return 0;
}
