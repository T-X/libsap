/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __LIBSAP_PRIV_H__
#define __LIBSAP_PRIV_H__

#include <netinet/in.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <threads.h>
#include <unistd.h>

#include "list.h"
#include "libsap.h"

#define SAP_EPOLL_MAX_EVENTS 32

#define BIT(n) (1 << n)
#define SAP_FLAG_COMPRESSED (BIT(0))
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

enum sap_epoll_ctx_type {
	SAP_EPOLL_CTX_TYPE_NONE = 0,
	SAP_EPOLL_CTX_TYPE_RX,
	SAP_EPOLL_CTX_TYPE_TX,
};

struct sap_ctx {
	struct hlist_head dest_list;
	unsigned int num_dests;
	int msg_type;
	unsigned int interval;
	int no_jitter;
	unsigned long count;
	unsigned long count_max;
	unsigned long bw_limit;
	int term;
	enum sap_epoll_ctx_type epoll_ctx_none;
	struct {
		struct random_data rd;
		char rs[256];
	} rand;
	struct {
		struct epoll_event events[SAP_EPOLL_MAX_EVENTS];
		int epoll_fd;
		struct timespec epoll_timeout;
	} epoll;
	struct {
		thrd_t *tid;
		thrd_t tid_store;
		mtx_t ctrl_lock;
		int pipefd[2];
	} thread;
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
	size_t num_ha_sessions;
	/* TODO: maybe convert to hash map? */
	struct hlist_head sessions_list;
	struct hlist_head ha_sessions_list;
};

static inline unsigned int sap_ipeth_hdrlen(union sap_sockaddr_union *addr)
{
	/* UDP + IP + ETH */
	switch (addr->s.sa_family) {
	case AF_INET:
		return 8 + 20 + 14;
	case AF_INET6:
	default:
		return 8 + 40 + 14;
	}
}

static inline uint16_t sap_get_rand_uint16(struct sap_ctx *ctx)
{
	int32_t res;

	random_r(&ctx->rand.rd, &res);

	return res % (UINT16_MAX + 1);
}

#endif /* __LIBSAP_PRIV_H__ */
