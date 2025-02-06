#include <math.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>

#include <xdp/libxdp.h>

#include "params.h"
#include "util.h"
#include "logging.h"
#include "xdp_sample.h"

#include "common_kern_user.h"

#include "xdp_netem.skel.h"

#define PROG_NAME "xdp-netem"

static int queue_array_fd;
static int meta_array_fd;

int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: xdp-netem COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       load        - load xdp-netem on an interface\n"
		"       unload      - load xdp-netem on an interface\n"
		"       help        - show this help message\n"
		"\n"
		"Use 'xdp-netem COMMAND --help' to see options for each command\n");
	return -1;
}

static __u32 next_pow2(__u32 value)
{
	value--;

	value |= value >> 1;
	value |= value >> 2;
	value |= value >> 4;
	value |= value >> 8;
	value |= value >> 16;

	value++;

	return value;
}

static int create_cpu_emulation_queue_entry(__u32 cpu, __u32 qsize, __u32 range)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_extra = range);
	char name[BPF_OBJ_NAME_LEN];
	int ret, fd;

	snprintf(name, sizeof(name), "pq_%d", cpu);

	fd = bpf_map_create(BPF_MAP_TYPE_PIFO_XDP, name,
						sizeof(__u32), sizeof(__u32), qsize, &opts);
	if (fd < 0) {
		pr_warn("Create queue entry failed: %s\n", strerror(errno));
		return fd;
	}

	ret = bpf_map_update_elem(queue_array_fd, &cpu, &fd, 0);
	if (ret < 0) {
		pr_warn("Update queue entry failed: %s\n", strerror(errno));
		return ret;
	}

	memset(name, 0, sizeof(name));

	snprintf(name, sizeof(name), "pq_meta_%d", cpu);

	fd = bpf_map_create(BPF_MAP_TYPE_PIFO_GENERIC, name,
						sizeof(__u32), sizeof(struct meta), qsize, &opts);
	if (fd < 0) {
		pr_warn("Create queue entry failed: %s\n", strerror(errno));
		return fd;
	}

	ret = bpf_map_update_elem(meta_array_fd, &cpu, &fd, 0);
	if (ret < 0) {
		pr_warn("Update queue metadata entry failed: %s\n", strerror(errno));
		return ret;
	}

	pr_debug("Add new queue entry for CPU: %u qsize: %d range: %d\n", cpu, qsize, range);

	return 0;
}

static int parse_percent(double *val, __u32 per)
{
	*val = per / 100.0;
	if (*val > 1.0 || *val < 0.0) {
		return -1;
	}

	return 0;
}

static void set_percent(__u32 *percent, double per)
{
	*percent = rint(per * UINT32_MAX);
}

static int get_percent(__u32 *percent, __u32 val)
{
	double per;

	if (parse_percent(&per, val))
		return -1;

	set_percent(percent, per);

	return 0;
}

struct emulation_opts {
	int loss_model;
	struct u32_multi loss_probabilities;
	__u32 corrupt_prob;
	__u32 latency;
	__u32 jitter;
	__u32 qsize_emulation;
};

static int set_emulation_runtime_config(struct xdp_netem *skel, const struct emulation_opts *opts, const struct iface *redir_iface, __u32 range)
{
	int ret;

	switch (opts->loss_model) {
	case CLG_RANDOM:
		skel->bss->netem_cfg.loss_model = CLG_RANDOM;
		ret = get_percent(&skel->bss->netem_cfg.loss, opts->loss_probabilities.vals[0]); 
		if (ret < 0) {
			pr_warn("Failed to parse loss probability");
			return ret;
		}
		break;
	case CLG_GILB_ELL:
		skel->bss->netem_cfg.loss_model = CLG_GILB_ELL;
		break;
	case CLG_4_STATES:
		skel->bss->netem_cfg.loss_model = CLG_4_STATES;
		break;
	default:
		skel->bss->netem_cfg.loss_model = CLG_RANDOM;
	}

	ret = get_percent(&skel->bss->netem_cfg.corrupt, opts->corrupt_prob);
	if (ret < 0) {
		pr_warn("Failed to parse corrupt probability");
		return ret;
	}

	if (opts->latency < opts->jitter) {
		pr_warn("Jitter cannot be greater than latency");
		return EXIT_FAIL_OPTION;
	}

	skel->bss->netem_cfg.latency = opts->latency;
	skel->bss->netem_cfg.jitter = opts->jitter;
	skel->bss->netem_cfg.redir_iface_index = redir_iface->ifindex;
	skel->bss->netem_cfg.max_packets = opts->qsize_emulation;
	skel->bss->netem_cfg.range = range;

	return 0;
}

static int set_emulation_runtime_state(struct xdp_netem *skel, int loss_model, const struct u32_multi *loss_probabilities)
{
	int ret;
	__u32 key = 0;
	struct netem_state state;

	switch (loss_model) {
	case CLG_GILB_ELL:
		state.clg.state = GOOD_STATE;
		ret = get_percent(&state.clg.a1, loss_probabilities->vals[0]); 
		if (ret < 0) {
			pr_warn("Failed to parse a1 gilbert-elliot model loss probability");
			return ret;
		}

		set_percent(&state.clg.a2, 1. - state.clg.a1);
		set_percent(&state.clg.a3, 0);
		set_percent(&state.clg.a4, 0);

		if (loss_probabilities->num_vals > 1) {
			ret = get_percent(&state.clg.a2, loss_probabilities->vals[1]); 
			if (ret < 0) {
				pr_warn("Failed to parse a2 gilbert-elliot model loss probability");
				return ret;
			}
		}
		if (loss_probabilities->num_vals > 2) {
			ret = get_percent(&state.clg.a3, loss_probabilities->vals[2]);
			if (ret < 0) {
				pr_warn("Failed to parse a3 gilbert-elliot model loss probability");
				return ret;
			}
		}

		state.clg.a3 = UINT32_MAX - state.clg.a3;

		if (loss_probabilities->num_vals > 3) {
			int ret = get_percent(&state.clg.a4, loss_probabilities->vals[3]);
			if (ret < 0) {
				pr_warn("Failed to parse a4 gilbert-elliot model loss probability");
				return ret;
			}
		}
		break;
	case CLG_4_STATES:
		loss_model = CLG_4_STATES;
		state.clg.state = TX_IN_GAP_PERIOD;
		ret = get_percent(&state.clg.a1, loss_probabilities->vals[0]);
		if (ret < 0) {
			pr_warn("Failed to parse a1 4-state markov chain model loss probability");
			return ret;
		}

		set_percent(&state.clg.a2, 1. - state.clg.a1); // p31
		set_percent(&state.clg.a3, 0); // p32
		set_percent(&state.clg.a4, 1.); // p23
		set_percent(&state.clg.a5, 0); // p14

		if (loss_probabilities->num_vals > 1) {
			int ret = get_percent(&state.clg.a2, loss_probabilities->vals[1]);
			if (ret < 0) {
				pr_warn("Failed to parse a2 4-state markov chain model loss probability");
				return ret;
			}
		}
		if (loss_probabilities->num_vals > 2) {
			int ret = get_percent(&state.clg.a3, loss_probabilities->vals[2]);
			if (ret < 0) {
				pr_warn("Failed to parse a3 4-state markov chain model loss probability");
				return ret;
			}
		}

		if (loss_probabilities->num_vals > 3) {
			int ret = get_percent(&state.clg.a4, loss_probabilities->vals[3]);
			if (ret < 0) {
				pr_warn("Failed to parse a4 4-state markov chain model loss probability");
				return ret;
			}
		}

		if (loss_probabilities->num_vals > 4) {
			int ret = get_percent(&state.clg.a5, loss_probabilities->vals[4]);
			if (ret < 0) {
				pr_warn("Failed to parse a5 4-state markov chain model loss probability");
				return ret;
			}
		}
		break;
	}

	ret = bpf_map_update_elem(bpf_map__fd(skel->maps.netem_state_map), &key, &state, 0);
	if (ret < 0) {
		pr_warn("Create netem state entry failed: %s\n", strerror(errno));
		return ret;
	}

	return 0;
}

struct enum_val loss_modes[] = { { "random", CLG_RANDOM },
				 { "state", CLG_4_STATES },
				 { "gemodel", CLG_GILB_ELL },
				 { NULL, 0 } };

static const struct load_opts {
	struct iface iface_in;
	__u32 ncpus;
	struct iface redir_iface;
	struct emulation_opts emulation;
} defaults_load = {
	.emulation = {
		.qsize_emulation = 65536,
	},
};

static struct prog_option load_options[] = {
	DEFINE_OPTION("ncpus", OPT_U32, struct load_opts, ncpus,
		      .short_opt = 'c',
		      .metavar = "<ncpus>",
		      .help = "Number of CPUs that will be used (By default, max number of CPUs"),
	DEFINE_OPTION("loss-mode", OPT_ENUM, struct load_opts, emulation.loss_model,
			.metavar = "<mode>", .typearg = loss_modes,
			.help = "Drop packets based on a loss model; Default disabled."),
	DEFINE_OPTION("loss-prob", OPT_U32_MULTI, struct load_opts,
		      emulation.loss_probabilities, .metavar = "<probabilities>",
		      .min_num = 1, .max_num = 5, .help = "Loss probabilities"),
	DEFINE_OPTION("corrupt-prob", OPT_U32, struct load_opts, emulation.corrupt_prob,
		      .metavar = "<percent>",
		      .help = "Corruption probability; Default 0."),
	DEFINE_OPTION("latency", OPT_U32, struct load_opts, emulation.latency,
		      .metavar = "<latency>", .help = "Latency in microseconds; Default 0."),
	DEFINE_OPTION("jitter", OPT_U32, struct load_opts, emulation.jitter,
		      .metavar = "<jitter>", .help = "Jitter in microseconds; Default 0."),
	DEFINE_OPTION("qsize_emulation", OPT_U32, struct load_opts, emulation.qsize_emulation,
		      .metavar = "<packets>", .help = "Emulation queue size; Default 65536."),
	DEFINE_OPTION("dev", OPT_IFNAME, struct load_opts, iface_in,
		      .positional = true, .metavar = "<ifname>",
		      .required = true, .help = "Load on device <ifname>"),
	DEFINE_OPTION("redirect_device", OPT_IFNAME, struct load_opts, redir_iface,
		      .metavar = "<ifname>",
		      .required = true, .help = "Redirect packets to <ifname>"),
	END_OPTIONS
};

int do_load(const void *cfg, const char *pin_root_path)
{
	const struct load_opts *opt = cfg;

	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct xdp_program *xdp_prog = NULL;
	struct xdp_netem *skel;
	struct bpf_program *prog = NULL;
	int ret = EXIT_FAIL_OPTION;
	int fd;
	size_t i, ncpus;
	int lock_fd;
	__u32 range;

	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0) {
		pr_warn("Failed to acquire lock on pin_root_path: %d\n", lock_fd);
		return EXIT_FAIL;
	}

	ret = get_pinned_program(&opt->iface_in, pin_root_path, NULL, &xdp_prog);
	if (!ret) {
		pr_warn("xdp-netem is already loaded on %s\n",
			opt->iface_in.ifname);
		xdp_program__close(xdp_prog);
		ret = EXIT_FAIL;
		goto end;
	}

	skel = xdp_netem__open();
	if (!skel) {
		pr_warn("Failed to xdp_netem__open: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	ncpus = libbpf_num_possible_cpus();
	if (opt->ncpus) {
		ncpus = opt->ncpus;
	}

	range = next_pow2(2 * (opt->emulation.latency + opt->emulation.jitter));
	if (range < 256) {
		range = 256;
	}

	LIBBPF_OPTS(bpf_map_create_opts, map_opts, .map_extra = range);

	fd = bpf_map_create(BPF_MAP_TYPE_PIFO_XDP, NULL,
						sizeof(__u32), sizeof(__u32), opt->emulation.qsize_emulation, &map_opts);
	if (fd < 0) {
		pr_warn("Failed to create template for BPF_MAP_TYPE_PIFO_XDP map: %s", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	if (bpf_map__set_inner_map_fd(skel->maps.queue_array, fd) < 0) {
		pr_warn("Failed to set inner map for queue_array");
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	if (bpf_map__set_max_entries(skel->maps.queue_array, ncpus) < 0) {
		pr_warn("Failed to set max entries for queue_array map: %s",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	fd = bpf_map_create(BPF_MAP_TYPE_PIFO_GENERIC, NULL,
						sizeof(__u32), sizeof(struct meta), opt->emulation.qsize_emulation, &map_opts);
	if (fd < 0) {
		pr_warn("Failed to create template for BPF_MAP_TYPE_PIFO_GENERIC map: %s", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	if (bpf_map__set_inner_map_fd(skel->maps.meta_array, fd) < 0) {
		pr_warn("Failed to set inner map for meta_array");
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	if (bpf_map__set_max_entries(skel->maps.meta_array, ncpus) < 0) {
		pr_warn("Failed to set max entries for meta_array map: %s",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	if (bpf_map__set_max_entries(skel->maps.cpu_queue_state_map, ncpus) < 0) {
		pr_warn("Failed to set max entries for cpu_queue_state_map map: %s",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	prog = bpf_object__find_program_by_name(skel->obj, "xdp_netem");
	if (!prog) {
		pr_warn("Failed to find program xdp_netem\n");
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = EXIT_FAIL_OPTION;

	if (set_emulation_runtime_config(skel, &opt->emulation, &opt->redir_iface, range) < 0) {
		pr_warn("Cannot init emulation runtime config parameters, exiting\n");
		goto end_destroy;
	}

	opts.obj = skel->obj;
	opts.prog_name = bpf_program__name(prog);
	xdp_prog = xdp_program__create(&opts);
	if (!xdp_prog) {
		ret = -errno;
		pr_warn("Couldn't open XDP program: %s\n",
			strerror(-ret));
		goto end_destroy;
	}

	ret = attach_xdp_program(xdp_prog, &opt->iface_in, XDP_MODE_NATIVE, pin_root_path);
	if (ret < 0) {
		pr_warn("Failed to attach XDP program: %s\n",
			strerror(-ret));
		goto end_destroy;
	}

	queue_array_fd = bpf_map__fd(skel->maps.queue_array);
	meta_array_fd = bpf_map__fd(skel->maps.meta_array);

	for (i = 0; i < ncpus; i++) {
		if (create_cpu_emulation_queue_entry(i, opt->emulation.qsize_emulation, range) < 0) {
			pr_warn("Cannot init emulation queue, exiting\n");
			ret = EXIT_FAIL;
			goto end_detach;
		}
	}

	if (set_emulation_runtime_state(skel, opt->emulation.loss_model, &opt->emulation.loss_probabilities) < 0) {
		pr_warn("Cannot init emulation runtime state parameters, exiting\n");
		ret = EXIT_FAIL;
		goto end_detach;
	}

	ret = EXIT_OK;
	goto end_destroy;

end_detach:
	xdp_program__detach(xdp_prog, opt->iface_in.ifindex, XDP_MODE_NATIVE, 0);
end_destroy:
	xdp_program__close(xdp_prog);
	xdp_netem__destroy(skel);
end:
	prog_lock_release(lock_fd);
	return ret;
}

static int remove_unused_maps(const char *pin_root_path)
{
	int dir_fd, err = 0;

	dir_fd = open(pin_root_path, O_DIRECTORY);
	if (dir_fd < 0) {
		if (errno == ENOENT)
			return 0;
		err = -errno;
		pr_warn("Unable to open pin directory %s: %s\n", pin_root_path,
			strerror(-err));
		goto out;
	}

	err = unlink_pinned_map(dir_fd, "cpu_queue_state_map");
	if (err)
		goto out;

out:
	if (dir_fd >= 0)
		close(dir_fd);

	return err;
}

static const struct unload_opts {
	struct iface iface;
} defaults_unload = {
};

static struct prog_option unload_options[] = {
	DEFINE_OPTION("dev", OPT_IFNAME, struct unload_opts, iface,
		      .positional = true, .metavar = "<ifname>",
		      .required = true, .help = "Unload from device <ifname>"),
	END_OPTIONS
};

int do_unload(const void *cfg, const char *pin_root_path)
{
	const struct unload_opts *opt = cfg;

	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct xdp_program *xdp_prog = NULL;
	enum xdp_attach_mode mode;
	int ret = EXIT_FAIL_OPTION;
	int lock_fd;


	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0) {
		pr_warn("Failed to acquire lock on pin_root_path: %d\n", lock_fd);
		return EXIT_FAIL;
	}

	ret = get_pinned_program(&opt->iface, pin_root_path, &mode, &xdp_prog);
	if (ret) {
		pr_warn("xdp-netem is not loaded on %s\n", opt->iface.ifname);
		xdp_program__close(xdp_prog);
		ret = EXIT_FAIL;
		goto end;
	}

	ret = detach_xdp_program(xdp_prog, &opt->iface, mode, pin_root_path);
	if (ret) {
		pr_warn("Removing XDP program on iface %s failed (%d): %s\n",
			opt->iface.ifname, -ret, strerror(-ret));
		goto end;
	}

	ret = remove_unused_maps("/sys/fs/bpf");
	if (ret) {
		pr_warn("Removing XDP pinned maps on iface %s failed (%d): %s\n",
			opt->iface.ifname, -ret, strerror(-ret));
		ret = EXIT_FAIL;
		goto end;
	}

	ret = EXIT_OK;

end:
	prog_lock_release(lock_fd);
	return ret;
}

static const struct prog_command cmds[] = {
	DEFINE_COMMAND(load, "Load xdp-netem on an interface"),
	DEFINE_COMMAND(unload, "Unload xdp-netem from an interface"),
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

union all_opts {
	struct load_opts load;
	struct unload_opts unload;
};

int main(__unused int argc, char **argv __attribute__((unused)))
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME,
					 true);

	return do_help(NULL, NULL);
}
