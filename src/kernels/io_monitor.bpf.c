/*
 * eBPF VM Performance Monitor - I/O Virtualization Monitor
 * 
 * Monitors Virtio, MMIO, PIO, and interrupt handling
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

/* I/O event */
struct io_event {
    u32 pid;
    u32 vcpu_id;
    u64 timestamp;
    u32 event_type;
    u32 device_id;
    u32 vq_id;
    u64 duration_ns;
    u32 data_len;
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

/* Maps */
struct bpf_map_def SEC("maps") 
     .type = BPF_MAP_TYPE_RINGBUF);
     .max_entries = 512 * 1024);
}; io_events SEC(".maps");

struct bpf_map_def SEC("maps") 
     .type = BPF_MAP_TYPE_HASH);
     .max_entries = MAX_VQS);
     .key_size = sizeof(u32); /* vq unique ID */
     .value_size = sizeof(struct vq_state);
}; vq_states SEC(".maps");

struct bpf_map_def SEC("maps") 
     .type = BPF_MAP_TYPE_HASH);
     .max_entries = 32);
     .key_size = sizeof(u32); /* device ID */
     .value_size = sizeof(struct io_stat);
}; io_stats SEC(".maps");

/* Counter for generating unique vq IDs */
struct bpf_map_def SEC("maps") 
     .type = BPF_MAP_TYPE_ARRAY);
     .max_entries = 1);
     .key_size = sizeof(u32);
     .value_size = sizeof(u32);
}; vq_id_counter SEC(".maps");

/* Tracepoint: kvm_io - Port I/O */
SEC("tp/kvm/kvm_io")
int trace_kvm_io(struct trace_event_raw_kvm_io *ctx)
{
    u32 vcpu_id = ctx->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 type = ctx->type; /* 0 = read, 1 = write */
    u32 port = ctx->port;
    u32 len = ctx->len;
    
    struct io_event *event = bpf_ringbuf_reserve(
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
int trace_virtio_device_ready(struct trace_event_raw_virtio_device *ctx)
{
    /* Track device initialization */
    return 0;
}

/* Tracepoint: virtio_queue_notify */
SEC("tp/virtio/virtio_queue_notify")
int trace_virtio_queue_notify(struct trace_event_raw_virtio_queue *ctx)
{
    u32 vcpu_id = ctx->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    
    /* Generate unique vq ID */
    u32 counter_key = 0;
    u32 *counter = bpf_map_lookup_elem(&vq_id_counter, &counter_key);
    u32 vq_id = 0;
    if (counter) {
        vq_id = __sync_fetch_and_add(counter, 1);
    }
    
    /* Store notify timestamp */
    struct vq_state state = {};
    state.notify_ts = now;
    state.device_id = 0; /* Could extract from context */
    state.vq_index = ctx->queue_id;
    bpf_map_update_elem(&vq_states, &vq_id, &state, BPF_ANY);
    
    /* Update stats */
    struct io_stat *stat = bpf_map_lookup_elem(&io_stats, &state.device_id);
    if (stat) {
        stat->notify_count++;
    }
    
    struct io_event *event = bpf_ringbuf_reserve(
        &io_events, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = IO_VIRTIO_NOTIFY;
        event->device_id = state.device_id;
        event->vq_id = ctx->queue_id;
        event->duration_ns = 0;
        event->data_len = 0;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Kprobe: kvm_set_irq - IRQ injection */
SEC("kprobe/kvm_set_irq")
int BPF_KPROBE(trace_kvm_set_irq, struct kvm_kernel_irq_routing_entry *e,
               struct kvm *kvm, int irq_source_id, int level, bool line_status)
{
    u32 vcpu_id = 0; /* Could extract from kvm */
    u64 now = bpf_ktime_get_ns();
    
    struct io_event *event = bpf_ringbuf_reserve(
        &io_events, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = IO_IRQ_INJECT;
        event->device_id = irq_source_id;
        event->vq_id = 0;
        event->duration_ns = 0;
        event->data_len = level;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Kprobe: kvm_ioapic_set_irq - IOAPIC IRQ handling */
SEC("kprobe/kvm_ioapic_set_irq")
int BPF_KPROBE(trace_ioapic_set_irq, void *ioapic, int irq, int level)
{
    /* Track IOAPIC interrupts */
    return 0;
}

/* Tracepoint: kvm_ack_irq - IRQ acknowledgment */
SEC("tp/kvm/kvm_ack_irq")
int trace_kvm_ack_irq(struct trace_event_raw_kvm_ack_irq *ctx)
{
    u32 vcpu_id = ctx->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 irq = ctx->irq;
    
    struct io_event *event = bpf_ringbuf_reserve(
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
