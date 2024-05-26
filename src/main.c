/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <config.h>

#include <arpa/inet.h>
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

/*static int status_dump_cb_header(struct sap_status_entry *entry)
{
	if (entry->type == SAP_STATUS_OWN)
		printf("Own session:\n");
	else if (entry->type == SAP_STATUS_NORMAL)
		printf("Session entries:\n");
	else if (entry->type == SAP_STATUS_HA)
		printf("High availability session entries:\n");

	return 0;
}

static const char *inet_ntop_46(const union sap_sockaddr_union *src, char *dst,
				socklen_t dst_size)
{
	switch (src->s.sa_family) {
	case AF_INET:
		return inet_ntop(AF_INET, &src->in.sin_addr, dst, dst_size);
	case AF_INET6:
		return inet_ntop(AF_INET6, &src->in6.sin6_addr, dst, dst_size);
	}

	return NULL;
}*/

/*static int status_dump_cb(struct sap_status_entry *entry, void *data, int first)
{
	char dest[INET6_ADDRSTRLEN];
	char src[INET6_ADDRSTRLEN];

	if (!entry) {
		printf("\n");
		return 0;
	}

	if (entry->first)
		status_dump_cb_header(entry);

//	inet_ntop_46(&entry->dest);
	inet_ntop_46(&entry->dest, dest, sizeof(dest));
	inet_ntop_46(&entry->src, src, sizeof(src));
//	inet_ntop_46(AF_INET6, &entry->src.in6.sin6_addr, src, sizeof(src));

	printf("\tdest: %s, %ssrc: %s, msg_id_hash: 0x%04x\n",
	       dest, entry->type == SAP_STATUS_HA ? "" : "orig-", src,
	       entry->msg_id_hash);

	return 0;
}*/

void signal_handler_status(int signum)
{
//	sap_status_dump(p_sap_ctx, status_dump_cb, NULL);
	sap_status_dump_json(p_sap_ctx, STDOUT_FILENO);
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

	new_action.sa_handler = &signal_handler_status;
	sigaction(SIGUSR1, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGUSR1, &new_action, NULL);
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
#ifdef HAVE_ZLIB
	printf("    -C                                  Disable compression\n");
#endif
#ifdef HAVE_BLAKE2
	printf("    -r                                  Use a random message ID hash (default: BLAKE2 over SAP packet)\n");
#endif
	printf("    -h                                  This help page\n");
	printf("\n");
	printf("Debug options: (typ. not RFC compliant)\n");
	printf("    -D                                  Disable payload destination from SDP detection\n");
	printf("    -S <address|hostname>               SAP destination (default: from payload destinations only)\n");
	printf("    -t <type>                           Payload type (default: \"application/sdp\")\n");
	printf("    -T <announce|terminate>             Message type, sets debug mode (default: standard/daemon mode)\n");
#ifdef HAVE_BLAKE2
	printf("    -I <msg-id-hash>                    Message ID hash (default: BLAKE2 over full SAP packet)\n");
#else
	printf("    -I <msg-id-hash>                    Message ID hash (default: random)\n");
#endif
	printf("    -O <ipv4-address|ipv6-address>      Orig source (default: from IP source address)\n");
	printf("    -i <interval>                       Interval override in seconds (default: 300)\n");
	printf("    -J                                  Disable interval jitter\n");
	printf("    -c <count>                          Number of messages to send\n");
// TODOs:
//	printf("    -D                                  Disable duplicate announcement check\n");
//	printf("    -m <bytes>                          Packet MTU (default: min(1000, iface-MTU))\n");
}

char *getopt_args_fmt = "46d:S:Dp:t:T:I:O:i:Jc:b:Crm:h";

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
		     int *enable_rand_msg_id_hash,
		     int *msg_type,
		     uint16_t **msg_id_hash,
		     char **orig_src,
		     unsigned int *interval,
		     int *no_jitter,
		     unsigned long *count,
		     long *bw_limit)
{
	int msg_id_hash_found = 0;
	int payload_dests_idx = 0;
	int orig_src_found = 0;
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
			ret = strtoi_generic(optarg, *msg_id_hash);
			if (ret < 0) {
				fprintf(stderr,
					"Error: invalid message hash id '%s'\n\n",
					optarg);
				usage(argv[0]);
				exit(1);
			}
			msg_id_hash_found = 1;
			break;
		case 'O':
			*orig_src = optarg;
			orig_src_found = 1;
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
#ifdef HAVE_ZLIB
			*enable_compression = -1;
#endif
			break;
		case 'r':
			*enable_rand_msg_id_hash = 1;
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
		*msg_id_hash = NULL;
	if (!orig_src_found)
		*orig_src = NULL;
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
	char *orig_src = NULL;
	uint16_t msg_id_hash_store;
	uint16_t *msg_id_hash = &msg_id_hash_store;
	unsigned int interval = 0;
	int no_jitter = 0;
	unsigned long count = 0;
	long bw_limit = 0;
	int enable_compression = 0;
	int enable_rand_msg_id_hash = 0;
	int ret;

	get_args(argc, argv, &addr_family, &payload_dests, num_payload_dests,
		 &sap_dests, num_sap_dests, &disable_dests_from_sdp,
		 &payload_filename, &payload_type, &enable_compression,
		 &enable_rand_msg_id_hash, &msg_type, &msg_id_hash, &orig_src,
		 &interval, &no_jitter, &count, &bw_limit);

	ctx = sap_init_custom(payload_dests, sap_dests, disable_dests_from_sdp,
			      addr_family, payload_filename, payload_type,
			      enable_compression, enable_rand_msg_id_hash,
			      msg_type, msg_id_hash, orig_src, interval,
			      no_jitter, count, bw_limit);
	if (!ctx) {
		usage(argv[0]);
		exit(1);
	}

	setup_signal_handler(ctx);

//	sap_run(ctx);

	/* alternative to blocking sap_run(), run threaded: */
	sap_start(ctx);
	/* do stuff here */
	while (1) {
		ret = sap_status_dump_json(ctx, STDOUT_FILENO);
		if (ret < 0)
			break;
		sleep(5);
	}
	//for (int i = 0; i < 6; i++) {
/*	while (1) {
		ret = sap_status_dump(ctx, my_dump_cb, NULL);
		if (ret < 0)
			break;
		sleep(5);
	}*/
	sap_stop(ctx);

	sap_free(ctx);

	return 0;
}
