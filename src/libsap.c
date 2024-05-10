/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

#include <errno.h>
#include <arpa/inet.h> // inet_ntop()

#include "libsap.h"
#include "libsap_priv.h"
#include "times.h"

#ifdef __STDC_NO_THREADS__
#error I need threads to build this program!
#endif

#define SAP_MAX(a, b)	((a) > (b) ? (a) : (b))

#define SAP_TIMEOUT_TIMES 10
#define SAP_TIMEOUT_SEC (60*60)

struct sap_session_entry {
	const union sap_sockaddr_union orig_src;
	const uint16_t msg_id_hash;
	const size_t msg_len;
	short missed;
	struct timespec last_seen;
	struct hlist_node node;
};

#define sap_container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

static int sap_send(struct sap_ctx_dest *ctx_dest)
{
//	return sendto(ctx_dest->sd, ctx_dest->message, ctx_dest->msg_len, 0, (struct sockaddr *)&ctx_dest->dest, sizeof(ctx_dest->dest));
	return send(ctx_dest->sd_tx, ctx_dest->message, ctx_dest->msg_len, 0);
}

/* in milliseconds */
static unsigned int sap_get_interval(struct sap_ctx_dest *ctx_dest)
{
//	unsigned int interval = SAP_INTERVAL_SEC * 1000;
	struct sap_ctx *ctx = ctx_dest->ctx;
	unsigned int interval;
       	unsigned long bw_used = 0;
	int offset;

	if (ctx->bw_limit)
		bw_used = 8 * ctx_dest->total_msg_lens / ctx->bw_limit;
	printf("~~~ %s:%i: : ctx->interval: %u, bw_used: %lu, total: %zu, bw_limit: %lu\n", __func__, __LINE__, ctx->interval, bw_used, ctx_dest->total_msg_lens, ctx->bw_limit);

	interval = SAP_MAX(ctx->interval, bw_used) * 1000;

	if (ctx->no_jitter)
		return interval;

	offset = sap_get_rand_uint16(ctx) % (interval * 2 / 3);
	offset -= interval / 3;

	printf("~~~ %s:%i: interval: %u, offset: %i\n", __func__, __LINE__, interval, offset);
	/* should not happen */
	if (interval + offset < 0)
		return interval;

	return interval + offset;
}

static struct itimerspec sap_get_timeout_next(struct sap_ctx_dest *ctx_dest)
{
	unsigned int interval = sap_get_interval(ctx_dest);
	struct itimerspec timer = {
		.it_interval = { 0 },
		.it_value = {
			.tv_sec = interval / 1000,
			.tv_nsec = (interval % 1000) * (1000*1000)
		}
	};

	return timer;
}

static void sap_set_timer_next(struct sap_ctx_dest *ctx_dest)
{
	struct itimerspec timer;

	timer = sap_get_timeout_next(ctx_dest);
	timerfd_settime(ctx_dest->timer_fd, 0, &timer, NULL);
}

static void sap_set_timers_next(struct sap_ctx *ctx)
{
	struct sap_ctx_dest *ctx_dest;

	hlist_for_each_entry(ctx_dest, &ctx->dest_list, node)
		sap_set_timer_next(ctx_dest);
}

static void sap_set_msg_type(struct sap_ctx_dest *ctx_dest, int msg_type)
{
	struct sap_packet *packet = (struct sap_packet *)ctx_dest->message;

	/* SAP_TERMINATE */
	if (msg_type)
		packet->flags |= SAP_FLAG_TYPE;
	/* SAP_ANNOUNCE */
	else
		packet->flags &= ~SAP_FLAG_TYPE;
}

static int sap_is_my_source(struct sap_ctx_dest *ctx_dest, union sap_sockaddr_union *addr)
{
	union sap_sockaddr_union *src = &ctx_dest->src;

	/* TODO: maybe check for our other SAP destinations, too,
	 * maybe this looped back? */

	if (src->s.sa_family != addr->s.sa_family)
		return 0;

	switch (src->s.sa_family) {
	case AF_INET:
		return !memcmp(&src->in.sin_addr,
			       &addr->in.sin_addr,
			       sizeof(src->in.sin_addr));
	case AF_INET6:
		return !memcmp(&src->in6.sin6_addr,
			       &addr->in6.sin6_addr,
			       sizeof(src->in6.sin6_addr));
	}

	return 0;
}

static int sap_get_orig_source(char *buffer, int buf_len, union sap_sockaddr_union *orig_src)
{
	struct sap_packet *packet = (struct sap_packet *)buffer;

	if (packet->flags & SAP_FLAG_IPV6) {
		struct in6_addr *addr6 = (struct in6_addr *)(buffer +
							     sizeof(*packet));

		if (buf_len < sizeof(*packet) + sizeof(struct in6_addr))
			return -EINVAL;

		orig_src->in6.sin6_family = AF_INET6;
		orig_src->in6.sin6_addr = *addr6;
	} else {
		struct in_addr *addr4 = (struct in_addr *)(buffer +
							   sizeof(*packet));

		if (buf_len < sizeof(*packet) + sizeof(struct in_addr))
			return -EINVAL;

		orig_src->in.sin_family = AF_INET;
		orig_src->in.sin_addr = *addr4;
	}

	return 0;
}

static int sap_is_zero_address(union sap_sockaddr_union *addr)
{
	union sap_sockaddr_union zero = { 0 };

	switch(addr->s.sa_family) {
	case AF_INET6:
		return !memcmp(&addr->in6.sin6_addr, &zero.in6.sin6_addr,
			       sizeof(zero.in6.sin6_addr));
	case AF_INET:
		return !memcmp(&addr->in.sin_addr, &zero.in.sin_addr,
			       sizeof(zero.in.sin_addr));
	}

	return 0;
}

static int sap_session_cmp(struct sap_session_entry *session, union sap_sockaddr_union *orig_src, uint16_t msg_id_hash)
{
	int ret;

	printf("~~~ %s:%i: start\n", __func__, __LINE__);
	if (session->orig_src.s.sa_family < orig_src->s.sa_family)
		return -1;
	else if (session->orig_src.s.sa_family > orig_src->s.sa_family)
		return 1;

	printf("~~~ %s:%i: here\n", __func__, __LINE__);
	ret = memcmp(&session->orig_src, orig_src, sizeof(*orig_src));
	if (ret < 0)
		return -1;
	else if (ret > 0)
		return 0;
	
	printf("~~~ %s:%i: here, session->msg_id_hash: %hu (0x%04x), msg_id_hash: %hu (0x%04x\n", __func__, __LINE__, session->msg_id_hash, session->msg_id_hash, msg_id_hash, msg_id_hash);
	if (session->msg_id_hash < msg_id_hash)
		return -1;
	else if (session->msg_id_hash > msg_id_hash)
		return 1;

	printf("~~~ %s:%i: end\n", __func__, __LINE__);
	return 0;
}

static struct sap_session_entry *
sap_session_get(struct sap_ctx_dest *ctx_dest, union sap_sockaddr_union *orig_src, uint16_t msg_id_hash)
{
	char dest[INET6_ADDRSTRLEN];
	struct sap_session_entry *session = NULL, *prev = NULL;
	int ret;

	hlist_for_each_entry(session, &ctx_dest->sessions_list, node) {
	inet_ntop(AF_INET6, &session->orig_src.in6.sin6_addr, dest, sizeof(dest));
		ret = sap_session_cmp(session, orig_src, msg_id_hash);
	printf("~~~ %s:%i: checking with: %s, %i, %04x -> ret: %i\n", __func__, __LINE__, dest, session->orig_src.s.sa_family, msg_id_hash, ret);
		/* found */
		if (!ret)
			return session;

		if (ret > 0)
			return prev;

		prev = session;
	}

	return session;
}

static struct sap_session_entry *
sap_session_create(struct sap_ctx_dest *ctx_dest, union sap_sockaddr_union *orig_src, uint16_t msg_id_hash, ssize_t msg_len)
{
	unsigned short ipeth_hdrlen = sap_ipeth_hdrlen(orig_src);
	struct sap_session_entry *session;
	struct sap_session_entry prepare = {
		.orig_src = *orig_src,
		.msg_id_hash = msg_id_hash,
		.msg_len = msg_len + ipeth_hdrlen,
		.missed = 0,
		.last_seen = { 0 },
	};

	/* TODO: Limit number of maximum sessions to create, to avoid being DoS'd
	 * with an OOM? -> a session entry is 80 bytes right now
	 */
	session = malloc(sizeof(*session));
	if (!session)
		return NULL;

	memcpy(session, &prepare, sizeof(*session));
	return session;
}

static struct sap_session_entry *
sap_session_get_or_add(struct sap_ctx_dest *ctx_dest, union sap_sockaddr_union *orig_src, uint16_t msg_id_hash, ssize_t msg_len)
{
	char dest[INET6_ADDRSTRLEN];
	struct sap_session_entry *session = sap_session_get(ctx_dest, orig_src, msg_id_hash);
	struct sap_session_entry *new_session;

	inet_ntop(AF_INET6, &orig_src->in6.sin6_addr, dest, sizeof(dest));
	printf("~~~ %s:%i: searching: %s, %i, %04x\n", __func__, __LINE__, dest, orig_src->s.sa_family, msg_id_hash);

	/* found */
	if (session && !sap_session_cmp(session, orig_src, msg_id_hash))
		return session;

	new_session = sap_session_create(ctx_dest, orig_src, msg_id_hash, msg_len);
	if (!new_session)
		return NULL;

	/* check for overflows */
	if (ctx_dest->total_msg_lens + msg_len < ctx_dest->total_msg_lens ||
	    ctx_dest->num_sessions + 1 < ctx_dest->num_sessions) {
		free(new_session);
		return NULL;
	}

	ctx_dest->total_msg_lens += new_session->msg_len;
	ctx_dest->num_sessions++;

	if (!session)
		hlist_add_head(&new_session->node, &ctx_dest->sessions_list);
	else
		hlist_add_behind(&new_session->node, &session->node);

	return new_session;
}

static int sap_session_del(struct sap_ctx_dest *ctx_dest, struct sap_session_entry *session)
{
	int ret = -EPROTO;

	/* assertions, should not happen */
	if (ctx_dest->num_sessions <= 1 ||
	    ctx_dest->total_msg_lens <= session->msg_len)
		goto err;

	ret = 0;
	ctx_dest->num_sessions--;
	ctx_dest->total_msg_lens -= session->msg_len;
err:
	hlist_del(&session->node);
	free(session);
	return ret;

}

static int sap_session_terminate(struct sap_ctx_dest *ctx_dest, union sap_sockaddr_union *orig_src, uint16_t msg_id_hash)
{
	struct sap_session_entry *session = sap_session_get(ctx_dest, orig_src, msg_id_hash);

	/* ignore unknown SAP terminations, maybe we just started */
	if (!session) {
		printf("~~~ %s:%i: can't terminate unknown session\n", __func__, __LINE__);
		return 0;
	}

	return sap_session_del(ctx_dest, session);
}

static int sap_session_update(struct sap_ctx_dest *ctx_dest, union sap_sockaddr_union *orig_src, uint16_t msg_id_hash, ssize_t msg_len)
{
	struct sap_session_entry *session;
       
	session = sap_session_get_or_add(ctx_dest, orig_src, msg_id_hash, msg_len);
	if (!session)
		return -ENOMEM;

	session->missed = 0;
	clock_gettime(CLOCK_MONOTONIC, &session->last_seen);
	return 0;
}

static int sap_epoll_rx_handler(struct sap_ctx_dest *ctx_dest)
{
	char buffer[sizeof(struct sap_packet) + sizeof(struct in6_addr)];
	struct sap_packet *packet;
	union sap_sockaddr_union src = { 0 };
	union sap_sockaddr_union orig_src;
	socklen_t addr_len = sizeof(src);
	ssize_t msg_len, ret;

//	printf("~~~ %s:%i: start\n", __func__, __LINE__);
	printf("~~~ %s:%i: old: total_msg_lens: %lu, num_sessions: %lu\n", __func__, __LINE__, ctx_dest->total_msg_lens, ctx_dest->num_sessions);

	ret = recvfrom(ctx_dest->sd_rx, buffer, sizeof(buffer), MSG_PEEK, &src.s, &addr_len);
	if (ret < sizeof(*packet))
		goto out;

	if (sap_is_my_source(ctx_dest, &src)) {
	printf("~~~ %s:%i: got own IP source\n", __func__, __LINE__);
		goto out;
	}

	packet = (struct sap_packet *)buffer;

	/* RFC2974 says:
	 * "SAP listeners MAY silently discard messages if the message
	 *  identifier hash is set to zero."
	 * Let's do this, as we don't check the payload for unique sessions.
	 */
	if (!ntohs(packet->msg_id_hash))
		goto out;

	ret = sap_get_orig_source(buffer, ret, &orig_src);
	if (ret < 0)
		goto out;

	if (sap_is_my_source(ctx_dest, &orig_src)) {
		/* TODO: should be a high-availability, redundant sender,
		 * we should scale back our transmissions accordingly
		 * (adjust our interval - or just reset our next transmission
		 * timer?)
		 */
	printf("~~~ %s:%i: got own SAP orig source\n", __func__, __LINE__);
		goto out;
	}

	/* RFC2974 says:
	 * "SAP listeners MAY silently discard packets with the originating
	 *  source set to zero."
	 */
	if (sap_is_zero_address(&orig_src)) {
	printf("~~~ %s:%i: got zero SAP orig source\n", __func__, __LINE__);
		goto out;
	}

	printf("~~~ %s:%i: got foreign SAP!\n", __func__, __LINE__);
	msg_len = recv(ctx_dest->sd_rx, buffer, 0, MSG_PEEK | MSG_TRUNC);
	if (msg_len < sizeof(*packet))
		goto out;

	if (packet->flags & SAP_FLAG_TERMINATE)
		ret = sap_session_terminate(ctx_dest, &orig_src, ntohs(packet->msg_id_hash));
	else
		ret = sap_session_update(ctx_dest, &orig_src, ntohs(packet->msg_id_hash), msg_len);

	if (ret < 0)
		goto out;

	printf("~~~ %s:%i: new: total_msg_lens: %lu, num_sessions: %lu\n", __func__, __LINE__, ctx_dest->total_msg_lens, ctx_dest->num_sessions);

	ret = 0;
out:
	/* flush */
	ret = recv(ctx_dest->sd_rx, buffer, 0, 0);
	if (ret < 0)
		return ret;

	return 0;
}

static int sap_session_timeouted(struct sap_session_entry *session, struct timespec *now)
{
	int64_t diff;
	struct timespec sum;
	struct timespec add = {
		.tv_sec = SAP_TIMEOUT_SEC,
		.tv_nsec = 0,
	};

	sum = timespec_sum(session->last_seen, add);

	diff = timespec_diffus(*now, sum);
	if (diff < 0) {
	printf("~~~ %s:%i: timeouted, going to delete\n", __func__, __LINE__);
		return 1;
	}

	return 0;
}

static int sap_session_outcounted(struct sap_ctx *ctx, struct sap_session_entry *session)
{
	/* if we have a non-standard, lower interval, increase
	 * the missed packet limit accordingly, to avoid
	 * kicking out SAP announcers with a standard interval
	 * too early
	 * TODO: maybe try to estimate an SAP announcers interval?
	 * (though there is no counter in the SAP announcement
	 * packet unfortunately)
	 */
	int max_missed = SAP_TIMEOUT_TIMES;

	if (ctx->interval < SAP_INTERVAL_SEC)
		max_missed = max_missed * SAP_INTERVAL_SEC / ctx->interval;

	if (session->missed >= max_missed) {
	printf("~~~ %s:%i: missed %hu packets, going to delete\n", __func__, __LINE__, session->missed);
		return 1;
	}

	return 0;
}

static void sap_sessions_timeout(struct sap_ctx_dest *ctx_dest)
{
	struct sap_session_entry *session;
	struct hlist_node *tmp;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	hlist_for_each_entry_safe(session, tmp, &ctx_dest->sessions_list, node) {
		if (sap_session_timeouted(session, &now) ||
		    sap_session_outcounted(ctx_dest->ctx, session))
			sap_session_del(ctx_dest, session);

		session->missed++;
	}
}

static int sap_count_reached(struct sap_ctx *ctx)
{
	return ctx->count_max && ctx->count >= ctx->count_max;
}

static int sap_epoll_tx_handler(struct sap_ctx_dest *ctx_dest)
{
	struct sap_ctx *ctx = ctx_dest->ctx;
	char dest[INET_ADDRSTRLEN];
	uint64_t res;

	printf("~~~ %s:%i: start\n", __func__, __LINE__);

	if (ctx_dest->dest.s.sa_family == AF_INET6)
		inet_ntop(ctx_dest->dest.s.sa_family, &ctx_dest->dest.in6.sin6_addr, dest, sizeof(dest));

	read(ctx_dest->timer_fd, &res, sizeof(res));
	printf("~~~ %s:%i: res: %lu, dest: %s\n", __func__, __LINE__, res, dest);

	sap_sessions_timeout(ctx_dest);

	if (sap_count_reached(ctx)) {
		ctx->term = 1;
		return 0;
	}

	sap_send(ctx_dest);
	ctx_dest->ctx->count++;
	sap_set_timer_next(ctx_dest);

	/* don't wait for another interval if we have an explicit
	 * message type -> "debug mode" */
	if (ctx->msg_type >= 0 && sap_count_reached(ctx))
		ctx->term = 1;

	return 0;
}

static int sap_epoll_event_handler(struct epoll_event *event)
{
	enum sap_epoll_ctx_type *type = event->data.ptr;
	struct sap_ctx_dest *ctx_dest;

	printf("~~~ %s:%i: start, type: %i\n", __func__, __LINE__, *type);
	switch (*type) {
	case SAP_EPOLL_CTX_TYPE_NONE:
		return 0;
	case SAP_EPOLL_CTX_TYPE_RX:
		ctx_dest = sap_container_of(type, struct sap_ctx_dest, epoll_ctx_rx);
		return sap_epoll_rx_handler(ctx_dest);
	case SAP_EPOLL_CTX_TYPE_TX:
		ctx_dest = sap_container_of(type, struct sap_ctx_dest, epoll_ctx_tx);
		return sap_epoll_tx_handler(ctx_dest);
	}

	return -EINVAL;
}

static int sap_terminate_dest(struct sap_ctx_dest *ctx_dest)
{
	sap_set_msg_type(ctx_dest, SAP_TERMINATE);
	/* TODO: update payload, RFC2974, section 6:
	 * "If the payload format is `application/sdp'
	 *  the deletion message is a single SDP line consisting of the origin
	 *  field of the announcement to be deleted."
	 */
	return sap_send(ctx_dest);
}

static void sap_terminate_all(struct sap_ctx *ctx)
{
	struct sap_ctx_dest *ctx_dest;

	hlist_for_each_entry(ctx_dest, &ctx->dest_list, node)
		sap_terminate_dest(ctx_dest);
}

int sap_run(struct sap_ctx *ctx)
{
	int ret;

	int timeout = -1, ev_count = -1;

	sap_set_timers_next(ctx);

	/* Without an explicit interval and with a specific
	 * message type we will just send a single one-shot
	 * packet of this type.
	 */
/*	if (!ctx->interval && ctx->msg_type >= 0) {
		ret = sap_send(ctx);
		goto out;
	}*/

	/* for standard RFC2974 operation, we should not send immediately,
	 * but instead wait and listen first (see section 3.1.1)
	 */
//	if (ctx->msg_type == -1)
//		sap_set_timeout_next(ctx);
	/* when msg_type is set explicitly then we assume the user is
	 * using this for debugging and needs more immediate
	 * responsiveness
	 */
//	else
//		sap_set_timeout_now(ctx);


	printf("~~~ %s:%i: here1\n", __func__, __LINE__);

	while(!ctx->term) {
		printf("~~~ %s:%i: calling: epoll_wait(), timeout: %i  (ctx->term: %i)\n", __func__, __LINE__, timeout, ctx->term);
		ev_count = epoll_wait(ctx->epoll.epoll_fd, ctx->epoll.events, SAP_EPOLL_MAX_EVENTS, -1);

		printf("~~~ %s:%i: epoll_wait() returned, ev_count: %i (ctx->term: %i)\n", __func__, __LINE__, ev_count, ctx->term);
		for(int i = 0; i < ev_count; i++) {
			ret = sap_epoll_event_handler(&ctx->epoll.events[i]);
			if (ret < 0)
				goto out;

			printf("~~~ %s:%i: epoll_wait(), ev: %i, fd: %i (ctx->term: %i)\n", __func__, __LINE__, i, ctx->epoll.events[i].data.fd, ctx->term);
		}

	printf("~~~ %s:%i: here1, %u\n", __func__, __LINE__, timeout);
	}

	if (ctx->msg_type < 0)
		sap_terminate_all(ctx);

	ret = 0;
out:
	ctx->term = 0;
	return ret;
}

static int sap_run_thread(void *arg)
{
	struct sap_ctx *ctx = arg;

	return sap_run(ctx);
}

int sap_start(struct sap_ctx *ctx)
{
	thrd_t tid;
	int ret;

	mtx_lock(&ctx->thread.ctrl_lock);
	/* already running */
	if (ctx->thread.tid)
		goto err1;

	sigset_t mask, old_mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGTERM);

	if (pthread_sigmask(SIG_BLOCK, &mask, &old_mask) == -1) {
		ret = -EINVAL;
		goto err1;
	}

	ret = thrd_create(&tid, sap_run_thread, ctx);
	if (ret != thrd_success) {
		ret = -EPERM;
		goto err2;
	}

	ctx->thread.tid_store = tid;
	ctx->thread.tid = &ctx->thread.tid_store;
err2:
	pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
err1:
	mtx_unlock(&ctx->thread.ctrl_lock);
	return ret;
}

void sap_term(struct sap_ctx *ctx)
{
	printf("~~~ %s:%i: start\n", __func__, __LINE__);
	ctx->term = 1;
	/* memory barrier needed against reordering? */
	char c = '\0';
	write(ctx->thread.pipefd[1], &c, sizeof(c));


	printf("~~~ %s:%i: term = 1 set\n", __func__, __LINE__);
}

void sap_stop(struct sap_ctx *ctx)
{
	sap_term(ctx);
	printf("~~~ %s:%i: start\n", __func__, __LINE__);

	mtx_lock(&ctx->thread.ctrl_lock);

	if (ctx->thread.tid) {
	printf("~~~ %s:%i: calling thrd_join()\n", __func__, __LINE__);
		thrd_join(*ctx->thread.tid, NULL);
	printf("~~~ %s:%i: thrd_join() returned\n", __func__, __LINE__);
		ctx->thread.tid = NULL;
		ctx->thread.tid_store = 0;
	}

	mtx_unlock(&ctx->thread.ctrl_lock);
}
