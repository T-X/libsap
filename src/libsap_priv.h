/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __LIBSAP_PRIV_H__
#define __LIBSAP_PRIV_H__

#include <netinet/in.h>
#include <sys/socket.h>

#include "libsap.h"

#define BIT(n) (1 << n)
#define SAP_FLAG_TYPE (BIT(2))
#define SAP_FLAG_TERMINATE SAP_FLAG_TYPE
#define SAP_FLAG_ADDRESS (BIT(4))
#define SAP_FLAG_IPV6 SAP_FLAG_ADDRESS
#define SAP_FLAG_VERSION (BIT(5))

#define SAP_INTERVAL_SEC 300

struct sap_packet {
	uint8_t flags;
	uint8_t auth_len;
	uint16_t msg_id_hash;
} __attribute__ ((__packed__));

enum sap_msg_type {
	SAP_ANNOUNCE = 0,
	SAP_TERMINATE = 1,
};

union sap_sockaddr_union {
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
	struct sockaddr s;
};

struct sap_ctx_dest {
	struct sap_ctx *ctx;
	enum sap_epoll_ctx_type epoll_ctx_tx;
	enum sap_epoll_ctx_type epoll_ctx_rx;
	int sd_tx;
	int sd_rx;
	int timer_fd;
	union sap_sockaddr_union dest;
	union sap_sockaddr_union src;
	char *message;
	size_t msg_len;
	struct hlist_node node;
	size_t total_msg_lens;
	size_t num_sessions;
	/* TODO: maybe convert to hash map? */
	struct hlist_head sessions_list;
};

static inline unsigned int sap_ip_hdrlen(union sap_sockaddr_union *addr)
{
	switch (addr->s.sa_family) {
	case AF_INET:
		return 20;
	case AF_INET6:
	default:
		return 40;
	}
}

static inline uint16_t sap_get_rand_uint16(struct sap_ctx *ctx)
{
	int32_t res;

	random_r(&ctx->rand.rd, &res);

	return res % (UINT16_MAX + 1);
}

#endif /* __LIBSAP_PRIV_H__ */
