// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/* Adapted by yanniszark in 2024 */

// All linux kernel type definitions are in vmlinux.h
#include "vmlinux.h"
#include "iolatency.h"
// BPF helpers
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct issue_time_queue {
	u64 out,in,count;
	u64 val[50];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100);
	__type(key, int);
	__type(value, struct issue_time_queue);
} issue_time_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
    __type(value, u32);
    __uint(max_entries, 18);
} latency_hist SEC(".maps");

const int tab32[32] = {
     0,  9,  1, 10, 13, 21,  2, 29,
    11, 14, 16, 18, 22, 25,  3, 30,
     8, 12, 20, 28, 15, 17, 24,  7,
    19, 27, 23,  6, 26,  5,  4, 31};

// SEC name is important! libbpf infers program type from it.
// See: https://docs.kernel.org/bpf/libbpf/program_types.html#program-types-and-elf
SEC("tracepoint/block_rq_issue")
int handle_block_rq_issue(struct request *rq)
{
	u64 issue_time = bpf_ktime_get_ns();
	int tag=rq->tag;
	struct issue_time_queue *q;

	q=bpf_map_lookup_elem(&issue_time_map,&tag);
	if(q){
		if(q->count>=50)
			return 0;

		u64 in = q->in;
		if(in>49)
			in=0;
		q->val[in]=issue_time;
		__sync_fetch_and_add(&q->count,1);
		__sync_fetch_and_add(&q->in,1);
		bpf_printk("Issue in %d count %d",q->in,q->count);
		bpf_map_update_elem(&issue_time_map, &tag, q, BPF_ANY);
	}
	else{
		struct issue_time_queue new_q={
			.out=0,
			.in=0,
			.count=0
		};
		new_q.out=0;
		new_q.in=0;
		new_q.count=0;
		q=&new_q;

		u64 in = q->in;
		if(in>49)
			in=0;
		q->val[in]=issue_time;
		__sync_fetch_and_add(&q->count,1);
		__sync_fetch_and_add(&q->in,1);
		bpf_printk("Issue in %d count %d",q->in,q->count);
		bpf_map_update_elem(&issue_time_map, &tag, q, BPF_ANY);
	}

	bpf_printk("Issue rq->tag %lu\n",rq->tag);

	return 0;
}
SEC("tracepoint/block_rq_complete")
int handle_block_rq_complete(struct request *rq, blk_status_t error, unsigned int nr_bytes)
{
	u64 complete_time = bpf_ktime_get_ns();
	u64 latency;
	int tag=rq->tag;
	struct issue_time_queue *q;

	int index=0;
	int *count;

	bpf_printk("Complete rq->tag %d", rq->tag);

	q = bpf_map_lookup_elem(&issue_time_map,&tag);
	if(!q)
		return 0;

	if(q->count<=0)
		return 0;

	u64 out = q->out;
	if(out>49)
		out=0;
	latency = q->val[out];
	__sync_fetch_and_add(&q->out,1);
	__sync_fetch_and_sub(&q->count,1);
	bpf_printk("Complete out %d count %d",q->out,q->count);
	bpf_map_update_elem(&issue_time_map, &tag, q, BPF_ANY);

	latency=(complete_time-latency)/1000;

	// Calculate index
	if(!latency)
		latency=1;
	latency |= latency >> 1;
	latency |= latency >> 2;
	latency |= latency >> 4;
	latency |= latency >> 8;
	latency |= latency >> 16;
	index = tab32[(uint32_t)(latency*0x07C4ACDD) >> 27];

	bpf_printk("latency %llu index %d\n", latency, index);

	count = bpf_map_lookup_elem(&latency_hist, &index);
	if(count)
		__sync_fetch_and_add(count,1);

	return 0;
}