#ifndef COMMON_KERN_USER_H
#define COMMON_KERN_USER_H

enum loss_model {
	CLG_RANDOM = 1,
	CLG_4_STATES,
	CLG_GILB_ELL,
};

enum _4_state_model {
	TX_IN_GAP_PERIOD = 1,
	TX_IN_BURST_PERIOD,
	LOST_IN_GAP_PERIOD,
	LOST_IN_BURST_PERIOD,
};

enum GE_state_model {
	GOOD_STATE = 1,
	BAD_STATE,
};

struct netem_config {
	__u32 loss;
	__u32 corrupt;
	__u64 latency; // ns
	__u64 jitter; // ns

	__u64 max_packets;
	__u64 range;

	enum loss_model loss_model;

	int redir_iface_index;
};

struct netem_state {
	/* Correlated Loss Generation models */
	struct clgstate {
		/* state of the Markov chain */
		__u8 state;

		/* 4-states and Gilbert-Elliot models */
		__u32 a1; /* p13 for 4-states or p for GE */
		__u32 a2; /* p31 for 4-states or r for GE */
		__u32 a3; /* p32 for 4-states or h for GE */
		__u32 a4; /* p23 for 4-states or 1-k for GE */
		__u32 a5; /* p14 used only in 4-states */
	} clg;
};

struct meta {
	__u64 time_to_send;
	__u64 prio;
};

#endif
