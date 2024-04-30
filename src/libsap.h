/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __LIBSAP_H__
#define __LIBSAP_H__

#include <stdlib.h>
#include <sys/epoll.h>
#include <threads.h>
#include <unistd.h>

#define SAP_EPOLL_MAX_EVENTS 32

struct sap_ctx {
	int sd;
	char *message;
	size_t msg_len;
	int msg_type;
	unsigned int interval;
	int no_jitter;
	unsigned long count;
	struct {
		struct random_data rd;
		char rs[256];
	} rand_state;
	int term;
	struct epoll_event events[SAP_EPOLL_MAX_EVENTS];
	int epoll_fd;
	struct timespec epoll_timeout;
	struct {
		thrd_t *tid;
		thrd_t tid_store;
		int pipefd[2];
		mtx_t ctrl_lock;
	} thread_state;
};

struct sap_ctx *sap_init_custom(char *payload_dest,
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
