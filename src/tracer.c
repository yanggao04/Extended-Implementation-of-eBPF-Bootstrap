#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "tracer.h"
#include "tracer.skel.h"

// In user space, the fd(file descriptor) to visit the map(perf buffer) is by skel->maps.[mapname] (skel=bpf_load/open)
struct tracer_bpf *skel;
static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "tracer 0.0";
const char *argp_program_bug_address = "<tbd>";
const char argp_program_doc[] = "BPF tracer application.\n"
					"\n"
					"It traces process start and exits and shows associated \n"
					"information (filename, process duration, PID and PPID, etc).\n"
					"\n"
					"USAGE: ./tracer [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0){
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default: 
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool existing = false;

static void sig_handler(int sig)
{
	existing = true;
}

static int handle_event_constr(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	struct event_time *et;
	et = (struct event_time *)malloc(sizeof(struct event_time));
	struct tm *tm;
	const int pid = e->pid;
	char ts[32];
	time_t t;
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	const struct bpf_map *map = skel->maps.exec_start_time;
	int err;

	if (e->exit_event) {
		err = bpf_map__lookup_elem(map, &pid, sizeof(pid), et, sizeof(*et), BPF_ANY);
		if (err){
			printf("Error extracting from map: %d\n", err);
			return 0;
		}
		printf("%-8s %-5s %-16s %-7d %-7d %s\n", et->ts, "EXEC", e->comm, pid, 
				e->ppid, et->filename);
		printf("%-8s %-5s %-16s %-7d %-7d [%u] (%llums)\n",ts, "EXIT", e->comm, pid, 
				e->ppid, e->exit_code, e->duration_ns / 1000000);
		bpf_map__delete_elem(map, &pid, sizeof(pid), BPF_ANY);
	}
	else {
		strcpy(et->filename, e->filename);
		strcpy(et->ts, ts);
		bpf_map__update_elem(map, &pid, sizeof(pid), et, sizeof(*et), BPF_ANY);
	}
	free(et);
	return 0;
	

	////////////

	/*	

	if (e->exit_event) {
		printf("%-8s %-5s %-16s %-7d %-7d [%u]",ts, "EXIT", e->comm, e->pid, 
				e->ppid, e->exit_code);
		if (e->duration_ns)
			printf(" (%llums)", e->duration_ns / 1000000);
		printf("\n");
	}
	else {
		printf("%-8s %-5s %-16s %-7d %-7d %s\n", ts, "EXEC", e->comm, e->pid, 
				e->ppid, e->filename);
	}

	return 0;
	*/
}

static int handle_event_no_constr(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (e->exit_event) {
		printf("%-8s %-5s %-16s %-7d %-7d [%u]",ts, "EXIT", e->comm, e->pid, 
				e->ppid, e->exit_code);
		if (e->duration_ns)
			printf(" (%llums)", e->duration_ns / 1000000);
		printf("\n");
	}
	else {
		printf("%-8s %-5s %-16s %-7d %-7d %s\n", ts, "EXEC", e->comm, e->pid, 
				e->ppid, e->filename);
	}

	return 0;

}


int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	//struct tracer_bpf *skel;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL); 
	//https://www.gnu.org/software/libc/manual/html_node/Argp.html
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = tracer_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	//change minimum duaration time if demanded
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	err = tracer_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = tracer_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (env.min_duration_ms)
		rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_constr, NULL, NULL);
	else
		rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_no_constr, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	

	printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID",
			 "PPID", "FILENAME/EXIT CODE");
	while (!existing) {
		err = ring_buffer__poll(rb, 100); //run handle_event when receiving data
		//Ctrl-C will cause -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	cleanup:
		ring_buffer__free(rb);
		tracer_bpf__destroy(skel);

		return err < 0 ? -err : 0;
}

