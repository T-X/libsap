/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <config.h>

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

void signal_handler_shutdown(int signum)
{
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
}

static void usage(char *prog)
{
	printf("Usage: %s [<options> ...]\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("    -4                                  IPv4-only mode\n");
	printf("    -6                                  IPv6-only mode\n");
	printf("    -d <address|hostname>               Payload's destination (default: from c= in SDP payload)\n");
	printf("    -p <file|fifo|->                    Payload file (default: -)\n");
	printf("    -b <bw-limit>                       Total bits/s for all sessions in an SAP group (default: 4000)\n");
#ifdef HAVE_ZLIB_H
	printf("    -C                                  Disable compression\n");
#endif
	printf("    -h                                  This help page\n");
	printf("\n");
	printf("Debug options: (typ. not RFC compliant)\n");
	printf("    -D                                  Disable payload destination from SDP detection\n");
	printf("    -S <address|hostname>               SAP destination (default: from payload destinations only)\n");
	printf("    -t <type>                           Payload type (default: \"application/sdp\")\n");
	printf("    -T <announce|terminate>             Message type, sets debug mode (default: standard/daemon mode)\n");
	printf("    -I <msg-id-hash>                    Message ID hash (default: random)\n");
	printf("    -i <interval>                       Interval override in seconds (default: 300)\n");
	printf("    -J                                  Disable interval jitter\n");
	printf("    -c <count>                          Number of messages to send\n");
// TODOs:
//	printf("    -D                                  Disable duplicate announcement check\n");
//	printf("    -m <bytes>                          Packet MTU (default: min(1000, iface-MTU))\n");
}

char *getopt_args_fmt = "46d:S:Dp:t:T:I:i:Jc:b:Cm:h";

static unsigned int get_num_dests(int argc, char *argv[], char type)
{
	unsigned int num_dests = 0;
	int opt;

	while ((opt = getopt(argc, argv, getopt_args_fmt)) != -1) {
		if (opt == type)
			num_dests++;
	}

	optind = 1;

	return num_dests;
}

static void get_args(int argc,
		     char *argv[],
		     int *addr_family,
		     char ***payload_dests,
		     unsigned int num_payload_dests,
		     char ***sap_dests,
		     unsigned int num_sap_dests,
		     int *disable_dests_from_sdp,
		     char **payload_filename,
		     char **payload_type,
		     int *enable_compression,
		     int *msg_type,
		     uint16_t **p_msg_id_hash,
		     unsigned int *interval,
		     int *no_jitter,
		     unsigned long *count,
		     long *bw_limit)
{
	int msg_id_hash_found = 0;
	int payload_dests_idx = 0;
	int sap_dests_idx = 0;
	int opt, ret;

	if (argc < 1) {
		fprintf(stderr, "Error: no own program name?\n");
		usage("<program>");
		exit(1);
	}

	if (num_payload_dests) {
		/* one more element with NULL to point to the end */
		*payload_dests = calloc(num_payload_dests + 1,
					sizeof(*payload_dests));
		if (!*payload_dests) {
			fprintf(stderr,
				"Error: Could not allocate payload destinations\n");
			usage(argv[0]);
			exit(1);
		}
	}

	if (num_sap_dests) {
		/* one more element with NULL to point to the end */
		*sap_dests = calloc(num_sap_dests + 1, sizeof(*sap_dests));
		if (!*sap_dests) {
			fprintf(stderr,
				"Error: Could not allocate SAP destinations\n");
			usage(argv[0]);
			exit(1);
		}
	}

	while ((opt = getopt(argc, argv, getopt_args_fmt)) != -1) {
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
		case 'd':
			(*payload_dests)[payload_dests_idx++] = optarg;
			break;
		case 'S':
			(*sap_dests)[sap_dests_idx++] = optarg;
			break;
		case 'D':
			*disable_dests_from_sdp = 1;
			break;
		case 'p':
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
				fprintf(stderr,
					"Error: unknown message type '%s'\n\n",
					optarg);
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'I':
			ret = strtoi_generic(optarg, *p_msg_id_hash);
			if (ret < 0) {
				fprintf(stderr,
					"Error: invalid message hash id '%s'\n\n",
					optarg);
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
				fprintf(stderr,
					"Error: invalid interval '%s'\n\n",
					optarg);
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'c':
			ret = strtoi_generic(optarg, count);
			if (ret < 0) {
				fprintf(stderr, "Error: invalid count '%s'\n\n",
					optarg);
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'b':
			ret = strtoi_generic(optarg, bw_limit);
			if (ret < 0) {
				fprintf(stderr,
					"Error: invalid bandwidth limit '%s'\n\n",
					optarg);
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'C':
#ifdef HAVE_ZLIB_H
			*enable_compression = -1;
#endif
			break;
		case 'm':
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		}
	}

	if (*addr_family == -EINVAL) {
		fprintf(stderr,
			"Error: '-4' and '-6' are mutually exclusive\n\n");
		usage(argv[0]);
		exit(1);
	}

	if (!msg_id_hash_found)
		*p_msg_id_hash = NULL;
}

int main(int argc, char *argv[])
{
	int num_payload_dests = get_num_dests(argc, argv, 'd');
	int num_sap_dests = get_num_dests(argc, argv, 'S');
	char **payload_dests = NULL;
	char **sap_dests = NULL;
	int disable_dests_from_sdp = 0;
	int addr_family = AF_UNSPEC;
	char *payload_type = NULL;
	char *payload_filename = NULL;
	struct sap_ctx *ctx;
	int msg_type = -1;
	uint16_t msg_id_hash;
	uint16_t *p_msg_id_hash = &msg_id_hash;
	unsigned int interval = 0;
	int no_jitter = 0;
	unsigned long count = 0;
	long bw_limit = 0;
	int enable_compression = 0;

	get_args(argc, argv, &addr_family, &payload_dests, num_payload_dests,
		 &sap_dests, num_sap_dests, &disable_dests_from_sdp,
		 &payload_filename, &payload_type, &enable_compression,
		 &msg_type, &p_msg_id_hash, &interval, &no_jitter, &count,
		 &bw_limit);

	ctx = sap_init_custom(payload_dests, sap_dests, disable_dests_from_sdp,
			      addr_family, payload_filename, payload_type,
			      enable_compression, msg_type, p_msg_id_hash,
			      interval, no_jitter, count, bw_limit);
	if (!ctx) {
		usage(argv[0]);
		exit(1);
	}

	setup_signal_handler(ctx);

	sap_run(ctx);

	/* alternative to blocking sap_run(), run threaded: */
//	sap_start(ctx);
	/* do stuff here */
//	sap_stop(ctx);

	sap_free(ctx);

	return 0;
}
