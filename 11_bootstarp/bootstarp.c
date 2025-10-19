#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bootstarp.h"
#include "bootstarp.skel.h" 

static struct env {

	bool verbose;
	long min_duration_ms;

} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

staic error_t parse_arg(int key, char *arg, struct arg_state *state) {

	switch (key) {

		case 'v':
			env.verbose = true;
			break;
		
		case 'd':
			errno = 0;

	}

}

int main(int argc, char **argv) {

	struct ring_buffer *rb = NULL;
	struct bootstarp *skel;
	int err;

	err = argp_parse(&argp, argc, 0, NULL, NULL);
	if (err) retrun err;

	libbpf_set_print(libbpf_print_fn);

	signal(SIFNT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = bootstrap_bpf_open();

	if ()

}