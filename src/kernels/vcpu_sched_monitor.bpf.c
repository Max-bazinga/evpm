/*
 * eBPF VM Performance Monitor - vCPU Scheduling Monitor
 * 
 * Monitors vCPU lifecycle: run, halt, wakeup, schedule latency
 * 
 * Note: BCC provides all helper functions automatically, no includes needed
 */

#define TASK_COMM_LEN 16
#define MAX_VCPUS 256

/* Event types */
enum vcpu_event_type {
    VCPU_RUN_BEGIN = 1,
    VCPU_RUN_END,
    VCPU_HALT,
    VCPU_WAKEUP,
};

/* vCPU scheduling event */
struct vcpu_sched_event {
    u32 pid;
    u32 vcpu_id;
    u64 timestamp;
    u32 event_type;
    u64 duration_ns;
    char comm[TASK_COMM_LEN];
};

/* Per-vCPU state */
struct vcpu_state {
    u64 last_run_ns;
    u64 last_halt_ns;
    u64 total_run_ns;
    u64 total_halt_ns;
    u32 schedule_count;
    u32 pid;
};

/* Maps - BCC style (not libbpf style) */
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 1024,
};

struct bpf_map_def SEC("maps") vcpu_states = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct vcpu_state),
    .max_entries = MAX_VCPUS,
};

struct bpf_map_def SEC("maps") sched_latencies = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};

/* Helper: check if process is QEMU/KVM */
static __always_inline bool is_qemu_process(struct task_struct *task)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    
    /* Check for qemu-system-* or qemu-kvm */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (comm[i] != "qemu"[i])
            return false;
    }
    return true;
}

/* Tracepoint: kvm_vcpu_run_begin */
SEC("tp/kvm/kvm_vcpu_run_begin")
int trace_vcpu_run_begin(struct trace_event_raw_kvm_vcpu *ctx)
{
    u32 vcpu_id = ctx->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    /* Update vCPU state */
    struct vcpu_state *state = bpf_map_lookup_elem(&vcpu_states, &vcpu_id);
    if (!state) {
        struct vcpu_state new_state = {};
        new_state.last_run_ns = now;
        new_state.pid = pid;
        bpf_map_update_elem(&vcpu_states, &vcpu_id, &new_state, BPF_ANY);
    } else {
        state->last_run_ns = now;
        state->pid = pid;
        state->schedule_count++;
    }
    
    /* Send event */
    struct vcpu_sched_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->pid = pid;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = VCPU_RUN_BEGIN;
        event->duration_ns = 0;
        bpf_get_current_comm(event->comm, sizeof(event->comm));
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Tracepoint: kvm_vcpu_run_end */
SEC("tp/kvm/kvm_vcpu_run_end")
int trace_vcpu_run_end(struct trace_event_raw_kvm_vcpu *ctx)
{
    u32 vcpu_id = ctx->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vcpu_state *state = bpf_map_lookup_elem(&vcpu_states, &vcpu_id);
    if (state && state->last_run_ns > 0) {
        u64 duration = now - state->last_run_ns;
        state->total_run_ns += duration;
        
        /* Send event with duration */
        struct vcpu_sched_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            event->pid = pid;
            event->vcpu_id = vcpu_id;
            event->timestamp = now;
            event->event_type = VCPU_RUN_END;
            event->duration_ns = duration;
            bpf_get_current_comm(event->comm, sizeof(event->comm));
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return 0;
}

/* Tracepoint: kvm_vcpu_halt */
SEC("tp/kvm/kvm_vcpu_halt")
int trace_vcpu_halt(struct trace_event_raw_kvm_vcpu *ctx)
{
    u32 vcpu_id = ctx->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vcpu_state *state = bpf_map_lookup_elem(&vcpu_states, &vcpu_id);
    if (state) {
        state->last_halt_ns = now;
    }
    
    struct vcpu_sched_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->pid = pid;
        event->vcpu_id = vcpu_id;
        event->timestamp = now;
        event->event_type = VCPU_HALT;
        event->duration_ns = 0;
        bpf_get_current_comm(event->comm, sizeof(event->comm));
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Tracepoint: kvm_vcpu_wakeup */
SEC("tp/kvm/kvm_vcpu_wakeup")
int trace_vcpu_wakeup(struct trace_event_raw_kvm_vcpu *ctx)
{
    u32 vcpu_id = ctx->vcpu_id;
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct vcpu_state *state = bpf_map_lookup_elem(&vcpu_states, &vcpu_id);
    if (state && state->last_halt_ns > 0) {
        u64 halt_duration = now - state->last_halt_ns;
        state->total_halt_ns += halt_duration;
        
        struct vcpu_sched_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            event->pid = pid;
            event->vcpu_id = vcpu_id;
            event->timestamp = now;
            event->event_type = VCPU_WAKEUP;
            event->duration_ns = halt_duration;
            bpf_get_current_comm(event->comm, sizeof(event->comm));
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return 0;
}

/* Kprobe: schedule - for measuring scheduling latency */
SEC("kprobe/finish_task_switch")
int BPF_KPROBE(trace_finish_task_switch, struct task_struct *prev)
{
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    
    /* Check if current task is QEMU */
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    
    bool is_qemu = false;
    #pragma unroll
    for (int i = 0; i < 4 && i < TASK_COMM_LEN - 1; i++) {
        if (comm[i] != "qemu"[i]) {
            is_qemu = false;
            break;
        }
        if (i == 3) is_qemu = true;
    }
    
    if (!is_qemu)
        return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 now = bpf_ktime_get_ns();
    
    /* Store timestamp for this PID */
    bpf_map_update_elem(&sched_latencies, &pid, &now, BPF_ANY);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
