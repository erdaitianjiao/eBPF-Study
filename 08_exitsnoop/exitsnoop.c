#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "exitsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {

    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);

} rb SEC(".maps");

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx) {

    struct task_struct *task;
    struct event *e;
    pid_t pid, tid;
    u64 id, ts, *start_ts, start_time = 0;

    // get PID and TID of exiting thread/process
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    // ignore thread exits
    if (pid != tid) return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    // fill out sample with data
    task = (struct task_struct *)bpf_get_current_task();
    start_time = BPF_CORE_READ(task, start_time);


    e->duration_ns = bpf_ktime_get_ns() - start_time;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // debug
    // e->comm[0] = 't';
    // e->comm[1] = 'e';
    // e->comm[2] = 's';
    // e->comm[3] = 't';
    // e->comm[4] = '\n';
    // e->comm[4] = 0;
    // bpf_printk("%s\n", e->comm);

    bpf_ringbuf_submit(e, 0);

    return 0;

}

