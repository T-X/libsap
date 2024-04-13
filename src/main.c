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
	printf("Usage: %s [<options> ...]\n\n", prog);
	printf("Options:\n");
	printf("    -4                                  IPv4-only mode\n");
	printf("    -6                                  IPv6-only mode\n");
	printf("    -d <address|hostname>               Payload's destination (default: from c= in SDP payload)\n");
	printf("    -p <file|->                         Payload file (default: -)\n");
	printf("    -t <type>                           Payload type (default: application/sdp)\n");
	printf("    -T <announce|terminate>             Message type, sets one-shot mode (default: daemon mode)\n");
	printf("    -I <msg-id-hash>                    Message ID hash (default: random)\n");
	printf("    -i <interval>                       Interval override in seconds (default: 300)\n");
// TODOs:
//	printf("    -S                                  Disable interval jitter\n");
//	printf("    -D                                  Disable duplicate announcement check\n");
//	printf("    -m <bytes>                          Packet MTU (default: min(1000, iface-MTU))\n");
	printf("    -h                                  help page\n");
}

static void get_args(int argc, char *argv[], int *addr_family, char **dest, char **payload_filename, char **payload_type, int *msg_type, uint16_t **p_msg_id_hash, unsigned int *interval)
{
	int msg_id_hash_found = 0;
	unsigned long num;
	char *endptr;
	int opt;

	if (argc < 1) {
		fprintf(stderr, "Error: no own program name?\n");
		usage("<program>");
		exit(1);
	}

	while ((opt = getopt(argc, argv, "46d:p:t:T:I:i:m:h")) != -1) {
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
			printf("~~~ %s:%i: -d: %s\n", __func__, __LINE__, optarg);
			*dest = optarg;
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
				fprintf(stderr, "Error: unknown message type '%s'\n\n", optarg);
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'I':
			errno = 0;
			num = strtoul(optarg, &endptr, 0);
			if (optarg == endptr || *endptr != '\0' ||
			    errno < 0 || num > UINT16_MAX) {
				fprintf(stderr, "Error: invalid message hash id '%s'\n\n", optarg);
				usage(argv[0]);
				exit(1);
			}
			**p_msg_id_hash = (uint16_t)num;
			msg_id_hash_found = 1;
			break;
		case 'i':
			errno = 0;
			num = strtoul(optarg, &endptr, 0);
			if (optarg == endptr || *endptr != '\0' ||
			    errno < 0 || num > UINT_MAX) {
				fprintf(stderr, "Error: invalid message hash id '%s'\n\n", optarg);
				usage(argv[0]);
				exit(1);
			}
			*interval = num;
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
	int addr_family = AF_UNSPEC;
	char *payload_type = NULL;
	char *dest = NULL;
	char *payload_filename = NULL;
	struct sap_ctx ctx;
	int msg_type = -1;
	uint16_t msg_id_hash;
	uint16_t *p_msg_id_hash = &msg_id_hash;
	int ret;
	unsigned int interval = 0;

	get_args(argc, argv, &addr_family, &dest, &payload_filename, &payload_type, &msg_type, &p_msg_id_hash, &interval);

	ret = sap_init(&ctx, dest, addr_family, payload_filename, payload_type,
		       msg_type, p_msg_id_hash, interval);
	if (ret < 0) {
		usage(argv[0]);
		exit(1);
	}

	setup_signal_handler(&ctx);

//	sap_run(&ctx);
	printf("~~~ %s:%i: starting thread\n", __func__, __LINE__);
	sap_start(&ctx);
	printf("~~~ %s:%i: waiting 15 seconds\n", __func__, __LINE__);
	sleep(15);
	printf("~~~ %s:%i: stopping thread\n", __func__, __LINE__);
	sap_stop(&ctx);
	printf("~~~ %s:%i: freeing thread\n", __func__, __LINE__);

	sap_free(&ctx);
	printf("~~~ %s:%i: free'd thread, returning\n", __func__, __LINE__);
	sleep(10);
	printf("~~~ %s:%i: exit'ing\n", __func__, __LINE__);

	return 0;
}
