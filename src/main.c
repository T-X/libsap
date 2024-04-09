/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libsap.h"

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
	printf("    -i <interval>                       Interval override (default: see RFC2974)\n");
	printf("    -h                                  help page\n");
}

static void get_args(int argc, char *argv[], int *addr_family, char **dest, char **payload_filename, char **payload_type, int *msg_type, uint16_t **p_msg_id_hash)
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

	while ((opt = getopt(argc, argv, "46d:p:t:T:I:i:h")) != -1) {
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

	get_args(argc, argv, &addr_family, &dest, &payload_filename, &payload_type, &msg_type, &p_msg_id_hash);

	ret = sap_init(&ctx, dest, addr_family, payload_filename, payload_type,
		       msg_type, p_msg_id_hash);
	if (ret < 0) {
		usage(argv[0]);
		exit(1);
	}

	sap_send(&ctx);

	sap_free(&ctx);

	return 0;
}
