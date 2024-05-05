/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __LIBSAP_H__
#define __LIBSAP_H__

#include <stdlib.h>
#include <sys/epoll.h>
#include <threads.h>
#include <unistd.h>

#include "list.h"

#define SAP_EPOLL_MAX_EVENTS 32

//struct sap_epoll_ctx {
//	enum sap_epoll_data_type type;
//	void *ctx;
//};

enum sap_epoll_ctx_type {
	SAP_EPOLL_CTX_TYPE_NONE = 0,
	SAP_EPOLL_CTX_TYPE_RX,
	SAP_EPOLL_CTX_TYPE_TX,
};

/*struct sap_epoll_ctx_fd {
	enum sap_epoll_ctx_type type;
	int fd;
}*/

struct sap_ctx {
	struct hlist_head dest_list;
	int msg_type;
	unsigned int interval;
	int no_jitter;
	unsigned long count;
	int term;
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
		enum sap_epoll_ctx_type epoll_ctx;
	} thread;
};

struct sap_ctx *sap_init_custom(char *payload_dests[],
				int payload_dest_af,
				char *payload_filename,
				char *payload_type,
				int msg_type,
				uint16_t *msg_id_hash,
				unsigned int interval,
				int no_jitter,
				unsigned long count);
struct sap_ctx *sap_init(char *payload_filename);

int sap_run(struct sap_ctx *ctx);
int sap_start(struct sap_ctx *ctx);
void sap_stop(struct sap_ctx *ctx);
void sap_term(struct sap_ctx *ctx);

void sap_free(struct sap_ctx *ctx);

#endif /* __LIBSAP_H__ */
