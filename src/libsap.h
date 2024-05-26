/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __LIBSAP_H__
#define __LIBSAP_H__

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

enum sap_status_event_type {
	SAP_STATUS_ADD,
	SAP_STATUS_DEL,
};

enum sap_status_type {
	SAP_STATUS_OWN,
	SAP_STATUS_NORMAL,
	SAP_STATUS_HA,
};

union sap_sockaddr_union {
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
	struct sockaddr s;
};

struct sap_status_entry {
	union sap_sockaddr_union dest;
	union sap_sockaddr_union src;
	union sap_sockaddr_union orig_src;
	uint16_t msg_id_hash;
	enum sap_status_event_type status;
	enum sap_status_type type;
	int first;
	int last;
};

struct sap_ctx *sap_init_custom(char *payload_dests[],
				char *sap_dests[],
				int disable_dests_from_sdp,
				int payload_dest_af,
				char *payload_filename,
				char *payload_type,
				int enable_compression,
				int msg_type,
				uint16_t *msg_id_hash,
				char *orig_src,
				unsigned int interval,
				int no_jitter,
				unsigned long count,
				long bw_limit);
struct sap_ctx *sap_init_fast(char *payload_filename);
struct sap_ctx *sap_init(char *payload_filename);

int sap_run(struct sap_ctx *ctx);
int sap_start(struct sap_ctx *ctx);
void sap_stop(struct sap_ctx *ctx);
void sap_term(struct sap_ctx *ctx);

void sap_free(struct sap_ctx *ctx);

int sap_status_dump(struct sap_ctx *ctx,
		    int (*callback)(struct sap_status_entry *entry, void *data),
		    void *cb_data);
int sap_status_dump_json(struct sap_ctx *ctx, int fd);

#endif /* __LIBSAP_H__ */
