#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <stdbool.h>

#include "common_kern_user.h"

#define CLOCK_MONOTONIC 1

struct netem_config netem_cfg;

struct pifo_queue {
	__uint(type, BPF_MAP_TYPE_PIFO_XDP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, __u32);
	__array(values, struct pifo_queue);
} queue_array SEC(".maps");

struct queue_meta {
	__uint(type, BPF_MAP_TYPE_PIFO_GENERIC);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct meta));
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, __u32);
	__array(values, struct queue_meta);
} meta_array SEC(".maps");

struct queue_state {
	struct bpf_timer timer;

	bool timer_init;

	__u64 base_priority;
	__u64 base_time;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct queue_state);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cpu_queue_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct netem_state);
	__uint(max_entries, 1);
} netem_state_map SEC(".maps");

static __always_inline
bool loss_gilb_ell(struct clgstate *clg)
{
	__u32 rnd1 = bpf_get_prandom_u32();
	__u32 rnd2 = bpf_get_prandom_u32();

	switch (clg->state) {
	case GOOD_STATE:
		if (rnd1 < clg->a1)
			clg->state = BAD_STATE;
		if (rnd2 < clg->a4)
			return true;
		break;
	case BAD_STATE:
		if (rnd1 < clg->a2)
			clg->state = GOOD_STATE;
		if (rnd2 > clg->a3)
			return true;
	}

	return false;
}

static __always_inline
bool loss_4state(struct clgstate *clg)
{
	__u32 rnd = bpf_get_prandom_u32();

	switch (clg->state) {
	case TX_IN_GAP_PERIOD:
		if (rnd < clg->a4) {
			clg->state = LOST_IN_GAP_PERIOD;
			return true;
		} else if (clg->a4 < rnd && rnd < clg->a1 + clg->a4) {
			clg->state = LOST_IN_BURST_PERIOD;
			return true;
		} else if (clg->a1 + clg->a4 < rnd) {
			clg->state = TX_IN_GAP_PERIOD;
		}
		break;
	case TX_IN_BURST_PERIOD:
		if (rnd < clg->a5) {
			clg->state = LOST_IN_BURST_PERIOD;
			return true;
		} else {
			clg->state = TX_IN_BURST_PERIOD;
		}
		break;
	case LOST_IN_BURST_PERIOD:
		if (rnd < clg->a3)
			clg->state = TX_IN_BURST_PERIOD;
		else if (clg->a3 < rnd && rnd < clg->a2 + clg->a3) {
			clg->state = TX_IN_GAP_PERIOD;
		} else if (clg->a2 + clg->a3 < rnd) {
			clg->state = LOST_IN_BURST_PERIOD;
			return true;
		}
		break;
	case LOST_IN_GAP_PERIOD:
		clg->state = TX_IN_GAP_PERIOD;
		break;
	}

	return false;
}

static __always_inline
bool loss_event(enum loss_model model, __u32 loss)
{
	struct netem_state *netem_st;
	__u32 key = 0;

	switch (model) {
	case CLG_RANDOM:
		return loss && loss >= bpf_get_prandom_u32();

	case CLG_4_STATES:
	case CLG_GILB_ELL:
		netem_st = bpf_map_lookup_elem(&netem_state_map, &key);
		if (!netem_st) {
			bpf_printk("ERROR: Unable to get netem state");
			return false;
		}

		if (model == CLG_4_STATES)
			return loss_4state(&netem_st->clg);
		else
			return loss_gilb_ell(&netem_st->clg);
	}

	return false;
}

static __always_inline
__s64 tabledist(__s64 mu, __s32 sigma)
{
	__u32 rnd;

	if (sigma == 0)
		return mu;

	rnd = bpf_get_prandom_u32();

	return ((rnd % (2 * (__u32)sigma)) + mu) - sigma;
}

struct bpf_map;

extern struct xdp_frame *xdp_packet_dequeue(struct bpf_map *map, __u64 flags,
					    __u64 *rank) __ksym;
extern int xdp_packet_send(struct xdp_frame *pkt, int ifindex,
			   __u64 flags) __ksym;
extern int xdp_packet_flush(void) __ksym;

struct callback_ctx {
	struct bpf_map *pifo_queue;
};

static long loop_cb(__u32 index, void *_ctx)
{
	struct xdp_frame *pkt;
	struct callback_ctx *ctx = (struct callback_ctx *)_ctx;
	__u64 prio = 0;
	__u64 ret;

	pkt = xdp_packet_dequeue(ctx->pifo_queue, 0, &prio);
	if (!pkt) {
		bpf_printk("ERROR: Unable to dequeue next packet");
		return 1;
	}

	ret = xdp_packet_send(pkt, netem_cfg.redir_iface_index, 0);
	if (ret != 0) {
		bpf_printk("ERROR: Packet has not been sent (%lu)", ret);
		return 1;
	}

	return 0;
}

static __always_inline
int dequeue(struct bpf_map *queue_meta_m, struct bpf_map *pifo_queue, struct queue_state *q_state, struct meta *next_sched_metatada) {
	struct meta metadata;

	bpf_map_pop_elem(queue_meta_m, &metadata);

	__u32 *count = bpf_map_lookup_elem(pifo_queue, &metadata.prio);
	if (!count) {
		bpf_printk("ERROR: Unable to get count for prio %lu in dequeue", metadata.prio);
		return -2;
	}

	struct callback_ctx ctx = {.pifo_queue = pifo_queue};
	int ret = bpf_loop(*count, loop_cb, &ctx, 0);
	if (ret < 0) {
		bpf_printk("ERROR: Unable to loop through all the packets for prio %lu in dequeue", metadata.prio);
		return -2;
	}

	xdp_packet_flush();

	if (bpf_map_peek_elem(queue_meta_m, next_sched_metatada)) {
		q_state->base_priority = metadata.prio & ~(netem_cfg.range - 1);
		q_state->base_time = 0;

		next_sched_metatada->time_to_send = 0;
		next_sched_metatada->prio = 0;

		return -1;
	}

	return 0;
}

static int xdp_timer_cb(void *map, __u32 *key, struct queue_state *q_state)
{
	struct meta next_sched_metadata;

	__u32 cpu = bpf_get_smp_processor_id();

	struct bpf_map *queue_meta_m = bpf_map_lookup_elem(&meta_array, &cpu);
	if (!queue_meta_m) {
		bpf_printk("ERROR: Unable to find queue metadata for current CPU in timer callback");
		return 0;
	}

	struct bpf_map *pifo_queue = bpf_map_lookup_elem(&queue_array, &cpu);
	if (!pifo_queue) {
		bpf_printk("ERROR: Unable to find queue for current CPU in timer callback");
		return 0;
	}

	int ret = dequeue(queue_meta_m, pifo_queue, q_state, &next_sched_metadata);
	if (!ret) {
		if (bpf_timer_start(&q_state->timer, next_sched_metadata.time_to_send * 1000, BPF_F_TIMER_CPU_PIN | BPF_F_TIMER_ABS)) {
			bpf_printk("ERROR: Unable to start timer after dequeue");
		}
	}

	return 0;
}

SEC("xdp")
int xdp_netem(struct xdp_md *ctx)
{
	if (loss_event(netem_cfg.loss_model, netem_cfg.loss)) {
		return XDP_DROP;
	}

	if (netem_cfg.corrupt && netem_cfg.corrupt >= bpf_get_prandom_u32()) {
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		__u32 pkt_size = data_end - data;
		__u64 pktbits = pkt_size * 8;
		__u16 pos = bpf_get_prandom_u32() % pktbits;
		__u16 byte_offset = (pos >> 3);

		__u8 *byte = data + byte_offset;

		if (byte + 1 >= data_end) {
			return XDP_ABORTED;
		}

		*byte ^= (__u8)(1u << (pos & 7));
	}


	if (netem_cfg.latency) {
		__u64 now = bpf_ktime_get_ns() / 1000;

		__u32 cpu = bpf_get_smp_processor_id();

		struct queue_state *q_state = bpf_map_lookup_elem(&cpu_queue_state_map, &cpu);
		if (!q_state) {
			bpf_printk("ERROR: Unable to find queue state for current CPU");
			return XDP_ABORTED;
		}

		if (!q_state->timer_init) {
			bpf_timer_init(&q_state->timer, &cpu_queue_state_map, CLOCK_MONOTONIC);
			bpf_timer_set_callback(&q_state->timer, xdp_timer_cb);

			q_state->timer_init = true;

			q_state->base_priority = 0;
			q_state->base_time = 0;
		}

		__s64 delay = tabledist(netem_cfg.latency, netem_cfg.jitter);

		if (!delay) {
			return bpf_redirect(netem_cfg.redir_iface_index, 0);
		}

		__u64 time_to_send = now + delay;

		struct bpf_map *queue_meta_m = bpf_map_lookup_elem(&meta_array, &cpu);
		if (!queue_meta_m) {
			bpf_printk("ERROR: Unable to find queue metadata for current CPU");
			return XDP_ABORTED;
		}

		struct bpf_map *pifo_queue = bpf_map_lookup_elem(&queue_array, &cpu);
		if (!pifo_queue) {
			bpf_printk("ERROR: Unable to find queue for current CPU");
			return XDP_ABORTED;
		}

		struct meta curr_sched_metadata;

		int ret = bpf_map_peek_elem(queue_meta_m, &curr_sched_metadata);
		if (ret || time_to_send < curr_sched_metadata.time_to_send) {
			if (bpf_timer_start(&q_state->timer, time_to_send * 1000, BPF_F_TIMER_CPU_PIN | BPF_F_TIMER_ABS)) {
				bpf_printk("ERROR: Unable to start timer");
				return XDP_ABORTED;
			}
		}

		if (!q_state->base_time) {
			q_state->base_time = now + netem_cfg.latency - netem_cfg.jitter;
		}

		__u64 prio = time_to_send - q_state->base_time + q_state->base_priority;

		__u32 *count = bpf_map_lookup_elem(pifo_queue, &prio);
		if (!count) {
			return XDP_DROP;
		} 

		if (!*count) {
			struct meta metadata = {
				.time_to_send = time_to_send,
				.prio = prio
			};

			if (bpf_map_push_elem(queue_meta_m, &metadata, prio)) {
				bpf_printk("ERROR: Unable to push metadata wiht prio %lu", prio);
				return XDP_ABORTED;
			}
		}

		return bpf_redirect_map(pifo_queue, prio, 0);
	}

	return bpf_redirect(netem_cfg.redir_iface_index, 0);
}

char _license[] SEC("license") = "GPL";
