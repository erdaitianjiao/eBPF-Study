#ifndef __CORE_FIXES_BPF_H
#define __CORE_FIXES_BPF_H

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>


struct task_struct___o {

	volatile long int state;

} __attribute__((preserve_access_index));

struct task_struct___x {

	unsigned int __state;

} __attribute__((preserve_access_index));

static __always_inline __s64 get_task_state(void *task) {

	struct task_struct___x *t = task;

	if (bpf_core_field_exists(t->__state))
		return BPF_CORE_READ(t, __state);

	return BPF_CORE_READ((struct task_struct___o *)task, state);
}



struct bio___o {

	struct gendisk *bi_disk;

} __attribute__((preserve_access_index));

struct bio___x {

	struct block_device *bi_bdev;

} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_gendisk(void *bio) {

	struct bio___x *b = bio;

	if (bpf_core_field_exists(b->bi_bdev))
		return BPF_CORE_READ(b, bi_bdev, bd_disk);
	return BPF_CORE_READ((struct bio___o *)bio, bi_disk);

}

struct trace_event_raw_block_rq_complete___x {

	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;

} __attribute__((preserve_access_index));

struct trace_event_raw_block_rq_completion___x {
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
} __attribute__((preserve_access_index));

static __always_inline bool has_block_rq_completion() {

	if (bpf_core_type_exists(struct trace_event_raw_block_rq_completion___x))
		return true;
	return false;
}


struct request_queue___x {

	struct gendisk *disk;

} __attribute__((preserve_access_index));

struct request___x {

	struct request_queue___x *q;
	struct gendisk *rq_disk;

} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_disk(void *request) {

	struct request___x *r = request;

	if (bpf_core_field_exists(r->rq_disk))
		return BPF_CORE_READ(r, rq_disk);
	return BPF_CORE_READ(r, q, disk);
    
}

#endif /* __CORE_FIXES_BPF_H */