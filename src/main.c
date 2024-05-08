/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libsap.h"
#include "strtoi_generic.h"

static struct sap_ctx *p_sap_ctx = NULL;
static int term = 0;

void signal_handler_shutdown(int signum)
{
	printf("~~~ %s:%i: start\n", __func__, __LINE__);
	//sap_stop(p_sap_ctx);
	sap_term(p_sap_ctx);
}

void setup_signal_handler(struct sap_ctx *ctx)
{
	struct sigaction new_action, old_action;
	
	p_sap_ctx = ctx;

	new_action.sa_handler = &signal_handler_shutdown;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;

	sigaction(SIGINT, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGINT, &new_action, NULL);

	sigaction(SIGHUP, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGHUP, &new_action, NULL);

	sigaction(SIGTERM, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGTERM, &new_action, NULL);

//	sigaction(SIGUSR1, NULL, &old_action);
//	if (old_action.sa_handler != SIG_IGN) {
//		new_action.sa_handler = &signal_handler_status;
//		sigaction(SIGUSR1, &new_action, NULL);
//	}
}

static void usage(char *prog)
{
	printf("Usage: %s [<options> ...]\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("    -4                                  IPv4-only mode\n");
	printf("    -6                                  IPv6-only mode\n");
	printf("    -d <address|hostname>               Payload's destination (default: from c= in SDP payload)\n");
	printf("    -p <file|->                         Payload file (default: -)\n");
	printf("    -h                                  This help page\n");
	printf("\n");
	printf("Debug options: (typ. not RFC compliant)\n");
	printf("    -t <type>                           Payload type (default: \"application/sdp\")\n");
	printf("    -T <announce|terminate>             Message type, sets debug mode (default: standard/daemon mode)\n");
	printf("    -I <msg-id-hash>                    Message ID hash (default: random)\n");
	printf("    -i <interval>                       Interval override in seconds (default: 300)\n");
	printf("    -J                                  Disable interval jitter\n");
	printf("    -c <count>                          Number of messages to send\n");
	printf("    -b <bw-limit>                       Total bits/s for all sessions in an SAP group (default: 4000)\n");
// TODOs:
//	printf("    -D                                  Disable duplicate announcement check\n");
//	printf("    -m <bytes>                          Packet MTU (default: min(1000, iface-MTU))\n");
}

char *getopt_args_fmt = "46d:p:t:T:I:i:Jc:b:m:h";

static unsigned int get_num_dests(int argc, char *argv[])
{
	unsigned int num_dests = 0;
	int opt;

	while ((opt = getopt(argc, argv, getopt_args_fmt)) != -1) {
		switch (opt) {
		case 'd':
			num_dests++;
			break;
		}
	}

	optind = 1;

	return num_dests;
}

static void get_args(int argc, char *argv[], int *addr_family, char ***dests, unsigned int num_dests, char **payload_filename, char **payload_type, int *msg_type, uint16_t **p_msg_id_hash, unsigned int *interval, int *no_jitter, unsigned long *count, long *bw_limit)
{
	int msg_id_hash_found = 0;
	int dests_idx = 0;
//	char **my_dests;
	unsigned long num;
	int opt, ret;

	if (argc < 1) {
		fprintf(stderr, "Error: no own program name?\n");
		usage("<program>");
		exit(1);
	}

	if (num_dests) {
		//*dests = malloc(sizeof(*dests) * (num_dests+1));
		// one more element with NULL to point to the end
		*dests = calloc(num_dests + 1, sizeof(*dests));
		if (!*dests) {
			fprintf(stderr, "Error: Could not allocate destinations\n");
			usage(argv[0]);
			exit(1);
		}
	}

	printf("~~~ %s:%i: here\n", __func__, __LINE__);
	while ((opt = getopt(argc, argv, getopt_args_fmt)) != -1) {
	printf("~~~ %s:%i: here\n", __func__, __LINE__);
		switch (opt) {
		case '4':
			if (*addr_family != AF_UNSPEC)
				*addr_family = -EINVAL;
			else
				*addr_family = AF_INET;
			break;
		case '6':
			if (*addr_family != AF_UNSPEC)
				*addr_family = -EINVAL;
			else
				*addr_family = AF_INET6;
			break;
		/* TODO: allow multiple "-d" options */
		case 'd':
			printf("~~~ %s:%i: -d: %s (num_dests: %u, idx: %i\n", __func__, __LINE__, optarg, num_dests, dests_idx);
			(*dests)[dests_idx++] = optarg;
			break;
		case 'p':
	printf("~~~ %s:%i: here\n", __func__, __LINE__);
			if (!strcmp("-", optarg))
				break;
			*payload_filename = optarg;
			break;
		case 't':
			*payload_type = optarg;
			break;
		case 'T':
			if (!strcmp("announce", optarg)) {
				*msg_type = 0;
			} else if (!strcmp("terminate", optarg)) {
				*msg_type = 1;
			} else {
				fprintf(stderr, "Error: unknown message type '%s'\n\n", optarg);
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'I':
			ret = strtoi_generic(optarg, *p_msg_id_hash);
			if (ret < 0) {
				fprintf(stderr, "Error: invalid message hash id '%s'\n\n", optarg);
				usage(argv[0]);
				exit(1);
			}
			msg_id_hash_found = 1;
			break;
		case 'J':
			*no_jitter = 1;
			break;
		case 'i':
			ret = strtoi_generic(optarg, interval);
			if (ret < 0) {
				fprintf(stderr, "Error: invalid interval '%s'\n\n", optarg);
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'c':
			ret = strtoi_generic(optarg, count);
			if (ret < 0) {
				fprintf(stderr, "Error: invalid count '%s'\n\n", optarg);
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'b':
			ret = strtoi_generic(optarg, bw_limit);
			if (ret < 0) {
				fprintf(stderr, "Error: invalid bandwidth limit '%s'\n\n", optarg);
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'm':
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		}
	}

	if (*addr_family == -EINVAL) {
		fprintf(stderr, "Error: '-4' and '-6' are mutually exclusive\n\n");
		usage(argv[0]);
		exit(1);
	}

	if (!msg_id_hash_found)
		*p_msg_id_hash = NULL;
}

int main(int argc, char *argv[])
{
	unsigned int num_dests = get_num_dests(argc, argv);
	char **dests = NULL;
	int addr_family = AF_UNSPEC;
	char *payload_type = NULL;
	char *payload_filename = NULL;
	struct sap_ctx *ctx;
	int msg_type = -1;
	uint16_t msg_id_hash;
	uint16_t *p_msg_id_hash = &msg_id_hash;
	int ret;
	unsigned int interval = 0;
	int no_jitter = 0;
	unsigned long count = 0;
	long bw_limit = 0;

	get_args(argc, argv, &addr_family, &dests, num_dests, &payload_filename, &payload_type, &msg_type, &p_msg_id_hash, &interval, &no_jitter, &count, &bw_limit);

	ctx = sap_init_custom(dests, addr_family, payload_filename, payload_type,
			      msg_type, p_msg_id_hash, interval, no_jitter, count, bw_limit);
	if (!ctx) {
		usage(argv[0]);
		exit(1);
	}

	setup_signal_handler(ctx);

//	sap_run(&ctx);
	printf("~~~ %s:%i: starting thread\n", __func__, __LINE__);
//	sap_start(ctx);
	sap_run(ctx);
//	printf("~~~ %s:%i: waiting 15 seconds\n", __func__, __LINE__);
//	sleep(300);
//	printf("~~~ %s:%i: stopping thread\n", __func__, __LINE__);
//	sap_stop(ctx);
//	printf("~~~ %s:%i: freeing thread\n", __func__, __LINE__);

	sap_free(ctx);
	printf("~~~ %s:%i: free'd thread, returning\n", __func__, __LINE__);
//	sleep(10);
	printf("~~~ %s:%i: exit'ing\n", __func__, __LINE__);

	return 0;
}
