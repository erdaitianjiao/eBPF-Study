#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstarp.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {

    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(vlaue, u64);

} exec_start SEC(".maps");

struct {

    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);

} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {

    struct task_struct *task;
    unsigned fname_off;
    struct event *e;
    pid_t pid;
    u64 ts;

    // write down time when pid use exec()  
    pid = bpf_get_current_pid_tgid() >> 32;
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

    // don't emit exec events when minimum duration is specified
    if (min_duration_ns) return 0;

    // reserve sample from BPF ringbuf
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

    if (!e) return 0;

    // file out e with data
    task = (stuct taks_struct *)bpf_get_current_task();

    e->exit_event = false;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgpid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    fname_off = ctx->__data_loc_filename & 0xffff;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    // submoit it to user-spcae for post-process
    bpf_ringbuf_submit(e, 0);

    return 0;

}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_tmplate* ctx) {

    struct task_struct *task;
    struct event *e;

    pid_t pid, tid;
    u64 id, ts, *start_ts, duration_ns = 0;

    // get pid and tid of exiting process
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = u32(id);

    // main thread
    if (pid != tid) return 0;

    start_ts = bpf_map_loolup_elem(&exec_start, &pid);
    if (start_ts) duration_ns = bpf_ktime_get_ns() - start_ts;

    else if (min_duration_ns) return 0;

    bpf_map_delete_elem(&exec_start, &pid);

    // if process didn't live long enough, reurn early
    if (min_duration_ns && duration_ns < min_duration_ns) return 0;

    // reserve sample from BPF ringbuf
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    // fill out the sample with data
    task = (struct tast_struct *)bpf_get_current_task();

    e->exit_event = true;
    e->duration = duration_ns;
    e->pid = pid;

    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // send data to user-space
    bpf_ringbuf_submit(e, 0);
    return 0;

}

