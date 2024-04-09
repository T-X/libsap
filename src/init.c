/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/timerfd.h>

#include <arpa/inet.h> // inet_ntop()

#include "libsap.h"
#include "libsap_priv.h"

#ifdef __STDC_NO_THREADS__
#error I need threads to build this program!
#endif

#ifndef __GNUC__
#define IN6_IS_ADDR_MULTICAST(a) (((const uint8_t *) (a))[0] == 0xff)
#define IN6_IS_ADDR_LINKLOCAL(a) \
	((((const uint32_t *) (a))[0] & htonl (0xffc00000))		\
	 == htonl (0xfe800000))
#endif /* __GNUC__ */

#define IN_MC_LINK_LOCAL(a) ((((in_addr_t)(a)) & 0xffffff00) == 0xe0000000)
#define IN_MC_LOCAL(a) ((((in_addr_t)(a)) & 0xffff0000) == 0xefff0000)
#define IN_MC_ORG_LOCAL(a) ((((in_addr_t)(a)) & 0xfffc0000) == 0xefc00000)
#define IN_MC_ADMIN(a) ((((in_addr_t)(a)) & 0xff000000) == 0xef000000)
#define IN_MC_GLOBAL(a) (IN_MULTICAST(a) && !IN_MC_ADMIN(a) && !IN_MC_LINK_LOCAL(a))

#define IN_MC_SAP_LINK_LOCAL ((in_addr_t) 0xe00000ff)
#define IN_MC_SAP_LOCAL ((in_addr_t) 0xefffffff)
#define IN_MC_SAP_ORG_LOCAL ((in_addr_t) 0xefc3ffff)
#define IN_MC_SAP_GLOBAL ((in_addr_t) 0xe0027ffe)

#define SAP_PORT 9875
#define SAP_PAYLOAD_TYPE_SDP "application/sdp"
#define SAP_BANDWIDTH_LIMIT 4000 /* bits/s */

static int sap_init_random_add_seed(struct random_data *rd, unsigned int seed)
{
	int32_t rand = 0;
	int ret;

	ret = random_r(rd, &rand);
	if (ret < 0)
		return ret;

	return srandom_r(seed ^ rand, rd);
}

static int sap_init_random(struct sap_ctx *sap_ctx)
{
	struct random_data *rd = &sap_ctx->rand.rd;
	pid_t pid = getpid();
	thrd_t tid = thrd_current();
	struct timespec uptime, time;
	int ret;

	/* We don't need crypto quality random numbers. But we want to:
	 * a) avoid messing with the global states of (s)rand()/(s)random()
	 * as we are a library
	 * b) avoid collisions on embedded systems which often boot
	 * into the same uptime state and don't have a persistent RTC
	 * c) be MT safe
	 */

	memset(rd, 0, sizeof(*rd));
	ret = initstate_r((unsigned int)pid, sap_ctx->rand.rs,
			  sizeof(sap_ctx->rand.rs), rd);
	if (ret < 0)
		return ret;

	ret = sap_init_random_add_seed(rd, (unsigned int)tid);
	if (ret < 0)
		return ret;

	/* uptime */
	ret = clock_gettime(CLOCK_MONOTONIC, &uptime);
	if (ret < 0)
		return ret;

	ret = sap_init_random_add_seed(rd, (unsigned int)uptime.tv_sec);
	ret |= sap_init_random_add_seed(rd, (unsigned int)uptime.tv_nsec);
	if (ret < 0)
		return ret;

	/* system clock */
	ret = clock_gettime(CLOCK_REALTIME, &time);
	if (ret < 0)
		return ret;

	ret = sap_init_random_add_seed(rd, (unsigned int)time.tv_sec);
	ret |= sap_init_random_add_seed(rd, (unsigned int)time.tv_nsec);
	if (ret < 0)
		return ret;

	return 0;
}

static int sap_init_mod_epoll(int fd, struct sap_ctx *ctx,
			      enum sap_epoll_ctx_type *type, int op)
{
	struct epoll_event event;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = type;

	return epoll_ctl(ctx->epoll.epoll_fd, EPOLL_CTL_ADD, fd, &event);
}

static int sap_init_add_epoll(int fd, struct sap_ctx *ctx,
			      enum sap_epoll_ctx_type *type)
{
	return sap_init_mod_epoll(fd, ctx, type, EPOLL_CTL_ADD);
}

static int sap_init_del_epoll(int fd, struct sap_ctx *ctx)
{
	enum sap_epoll_ctx_type type = SAP_EPOLL_CTX_TYPE_NONE;

	return sap_init_mod_epoll(fd, ctx, &type, EPOLL_CTL_DEL);
}

static uint16_t sap_get_msg_id_hash(struct sap_ctx *ctx, uint16_t *msg_id_hash)
{
	if (!msg_id_hash)
		return sap_get_rand_uint16(ctx);
	else
		return htons(*msg_id_hash);
}

static int sap_init_epoll(struct sap_ctx *ctx)
{
	int ret = -EINVAL;

	ctx->epoll.epoll_fd = epoll_create1(0);
	if (ctx->epoll.epoll_fd < 0)
		goto err1;

	ret = pipe(ctx->thread.pipefd);
	if (ret < 0) {
		goto err2;
	}

	/* no action needed, only to wake up epoll_wait() to check ctx->term */
	ret = sap_init_add_epoll(ctx->thread.pipefd[0], ctx,
				 &ctx->epoll_ctx_none);
	if (ret < 0)
		goto err3;

	return 0;
err3:
	close(ctx->thread.pipefd[0]);
	close(ctx->thread.pipefd[1]);
err2:
	close(ctx->epoll.epoll_fd);
err1:
	return ret;
}

static void sap_free_epoll(struct sap_ctx *ctx)
{
	close(ctx->thread.pipefd[0]);
	close(ctx->thread.pipefd[1]);
	close(ctx->epoll.epoll_fd);
}

static char *sap_get_payload(char *payload_filename)
{
	char *payload = NULL;
	FILE *file;
	long size;
	int ret;

	if (!payload_filename || !strcmp("-", payload_filename))
		file = stdin;
	else
		file = fopen(payload_filename, "r");

	if (!file)
		goto err;

	ret = fseek(file, 0, SEEK_END);
	size = ftell(file);
	ret = fseek(file, 0, SEEK_SET);

	/* stdin / pipe, no seek support
	 * -> assume maximum IP packet payload size
	 * TODO: allow updating SDP from pipe/stdin,
	 * maybe \n\n separated?
	 * And for files, by updating/replacing the file?
	 */
	if (ret < 0)
		size = UINT16_MAX;

	payload = malloc(size + 1);
	if (!payload)
		goto err1;

	memset(payload, 0, size + 1);

	fread(payload, size, 1, file);
	if (ferror(file)) {
		free(payload);
		payload = NULL;
	}

err1:
	if (file != stdin)
		fclose(file);
err:
	return payload;
}

static const char *sap_get_next_line(const char *pos)
{
	pos = strchr(pos, '\n');
	if (!pos)
		return NULL;

	pos += 1;
	if (*pos == '\r')
		pos += 1;

	return pos;
}

static int sap_get_payload_dest(const char *payload, char *dest,
				const char **parse_end)
{
	/* TODO: check for multiple "c=" lines, get
	 * SAP multicast destination for each */
	char *end;

	if (!payload)
		return -ENOENT;

	while(1) {
		if (!strncmp("c=", payload, strlen("c=")))
			break;

		payload = sap_get_next_line(payload);
		if (!payload)
			return -ENOENT;
	}

	if (!strncmp("c=IN IP6 ", payload, strlen("c=IN IP6 ")))
		payload += strlen("c=IN IP6 ");
	else if (!strncmp("c=IN IP4 ", payload, strlen("c=IN IP4 ")))
		payload += strlen("c=IN IP4 ");

	if (dest) {
		strncpy(dest, payload, INET6_ADDRSTRLEN);

		end = strpbrk(dest, "/\r\n");
		if (end)
			*end = '\0';
	}

	if (parse_end)
		*parse_end = sap_get_next_line(payload);

	return 0;
}

static int sap_get_payload_dests_num(const char *payload)
{
	int num_dests = 0;
	int ret;

	while (payload) {
		ret = sap_get_payload_dest(payload, NULL, &payload);
		if (ret < 0)
			break;

		num_dests++;
	}

	return num_dests;
}

static char **sap_get_payload_dests(const char *payload)
{
	int num_dests = sap_get_payload_dests_num(payload);
	char *dests_store;
	char **dests = NULL;
	char *dest;
	int ret;

	if (!num_dests)
		return NULL;

	dests_store = calloc(num_dests, INET6_ADDRSTRLEN);
	if (!dests_store)
		return NULL;

	dests = calloc(num_dests + 1, sizeof(*dests));
	if (!dests)
		goto err;

	for (int i = 0; i < num_dests; i++) {
		dest = dests_store + i * INET6_ADDRSTRLEN;
		dests[i] = dest;

		ret = sap_get_payload_dest(payload, dest, &payload);
		/* sanity check, should not happen */
		if (ret < 0)
			goto err;
	}

	return dests;
err:
	free(dests_store);
	free(dests);
	return NULL;
}

static int sap_get_ip4_dst(const struct sockaddr_in *pay_dst,
			   struct sockaddr_in *sap_dst)
{
	/* TODOs/open questions:
	 * 1) from the static global scope (224.0.1.0 - 238.255.255.255),
	 * should only 224.2.128.0 - 224.2.255.255 be accepted?
	 * (see: RFC2974, section 3, "IPv4 global scope sessions ...")
	 * 2) for 239.0.0.0/8 ("Administratively Scoped IP Multicast", RFC2365),
	 * should the SAP destinations be determined through ranges obtained
	 * through MZAP (RFC2776) instead? All these ranges
	 * (except 239.255.0.0/16, local scope) seem further divisible.
	 */
	in_addr_t pdst = ntohl(pay_dst->sin_addr.s_addr);
	struct in_addr dst;

	/* 224.0.0.0/24 (v6 scope ID: 2) -> 224.0.0.255 */
	if (IN_MC_LINK_LOCAL(pdst))
		dst.s_addr = IN_MC_SAP_LINK_LOCAL;
	/* 239.255.0.0/16 (v6 scope ID: 3) -> 239.255.255.255 */
	else if (IN_MC_LOCAL(pdst))
		dst.s_addr = IN_MC_SAP_LOCAL;
	/* 239.192.0.0/14 (v6 scope ID: 8) -> 239.195.255.255 */
	else if (IN_MC_ORG_LOCAL(pdst))
		dst.s_addr = IN_MC_SAP_ORG_LOCAL;
	/* 224.0.1.0 - 238.255.255.255 (v6 scope ID: e) -> 224.2.127.254 */
	else if (IN_MC_GLOBAL(pdst))
		dst.s_addr = IN_MC_SAP_GLOBAL;
	else
		return -EINVAL;

	sap_dst->sin_family = pay_dst->sin_family;
	sap_dst->sin_addr.s_addr = htonl(dst.s_addr);
	sap_dst->sin_port = htons(SAP_PORT);

	return 0;
}

static int sap_get_ip6_dst(const struct sockaddr_in6 *pay_dst,
			   struct sockaddr_in6 *sap_dst)
{
	/* TODOs/open questions:
	 * Should we really accept unicast payload destinations here?
	 * (VLC does?)
	 */
	struct in6_addr dst = { .s6_addr = { 0xff, 0, 0, 0,
					     0, 0, 0, 0,
				  	     0, 0, 0, 0,
					     0, 0x02, 0x7f, 0xfe } };

	if (IN6_IS_ADDR_MULTICAST(&pay_dst->sin6_addr))
		/* adopt scope */
		dst.s6_addr[1] = (0x0f & pay_dst->sin6_addr.s6_addr[1]);
	/* unicast (not really part of the SAP specification?) */
	else if (IN6_IS_ADDR_LINKLOCAL(&pay_dst->sin6_addr))
		/* link-local scope */
		dst.s6_addr[1] = 0x02;
	/* TODO: is this correct? this is what VLC does */
	else
		/* global scope */
		dst.s6_addr[1] = 0x0e;

	sap_dst->sin6_family = pay_dst->sin6_family;
	sap_dst->sin6_addr = dst;
	sap_dst->sin6_port = htons(SAP_PORT);
	sap_dst->sin6_flowinfo = 0;
	sap_dst->sin6_scope_id = pay_dst->sin6_scope_id;

	return 0;
}

static int sap_get_ip_dst(union sap_sockaddr_union *addr,
			  union sap_sockaddr_union *sap_dst)
{
	switch (addr->s.sa_family) {
	case AF_INET:
		return sap_get_ip4_dst(&addr->in,
				       &sap_dst->in);
	case AF_INET6:
		return sap_get_ip6_dst(&addr->in6,
				       &sap_dst->in6);
	}

	return -EPROTONOSUPPORT;
}

static int sap_set_hop_limit(int sd, union sap_sockaddr_union *sap_dst)
{
	int hops = 255;
	in_addr_t dst;

	switch (sap_dst->s.sa_family) {
	case AF_INET:
		dst = ntohl(sap_dst->in.sin_addr.s_addr);

		if (IN_MC_LINK_LOCAL(dst))
			return 0;

		return setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &hops,
				  sizeof(hops));
	case AF_INET6:
		/* TODO: hop_limit to 1 for link-local scope? */
		return setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
				  sizeof(hops));
	}

	return -EINVAL;
}

static int sap_join_dest4(struct sap_ctx_dest *ctx_dest)
{
	struct ip_mreqn mreq = {
		.imr_multiaddr = ctx_dest->dest.in.sin_addr,
		.imr_address = ctx_dest->src.in.sin_addr,
		.imr_ifindex = 0,
	};

	return setsockopt(ctx_dest->sd_rx, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
			  sizeof(mreq));
}

static int sap_join_dest6(struct sap_ctx_dest *ctx_dest)
{
	struct ipv6_mreq mreq = {
		.ipv6mr_multiaddr = ctx_dest->dest.in6.sin6_addr,
		.ipv6mr_interface = ctx_dest->dest.in6.sin6_scope_id,
	};

	return setsockopt(ctx_dest->sd_rx, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq,
			  sizeof(mreq));
}

static int sap_join_dest(struct sap_ctx_dest *ctx_dest)
{
	switch (ctx_dest->dest.s.sa_family) {
	case AF_INET:
		return sap_join_dest4(ctx_dest);
	case AF_INET6:
		return sap_join_dest6(ctx_dest);
	}

	return -EINVAL;
}

static int sap_create_socket_tx(struct sap_ctx_dest *ctx_dest)
{
	union sap_sockaddr_union *sap_dst = &ctx_dest->dest;
	socklen_t addr_len = sizeof(ctx_dest->src);
	int sd, ret;

	sd = socket(sap_dst->s.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sd < 0)
		return sd;

	/* connect to SAP multicast destination; then we can use send() instead
	 * of sendto() later, too */
	ret = connect(sd, &sap_dst->s, sizeof(*sap_dst));
	if (ret < 0)
		goto err;

	/* after connect(), will return the source address of TX packets */
	ret = getsockname(sd, &ctx_dest->src.s, &addr_len);
	if (ret < 0)
		goto err;

	ret = sap_set_hop_limit(sd, sap_dst);
	if (ret < 0)
		goto err;

	ctx_dest->sd_tx = sd;
	return sd;
err:
	close(sd);
	return ret;
}

static int sap_create_socket_rx(struct sap_ctx_dest *ctx_dest)
{
	union sap_sockaddr_union listen = ctx_dest->dest;
	int sd, ret;

	sd = socket(listen.s.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sd < 0)
		return sd;

	ret = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
	if (ret < 0)
		goto err;

	ret = bind(sd, &listen.s, sizeof(listen));
	if (ret < 0)
		goto err;

	ctx_dest->sd_rx = sd;

	ret = sap_join_dest(ctx_dest);
	if (ret < 0)
		goto err;

	return 0;
err:
	close(sd);
	return ret;
}

static int sap_create_socket(struct sap_ctx_dest *ctx_dest, char *pay_dst,
			     int af_hint)
{
	union sap_sockaddr_union sap_dst = { 0 };
	union sap_sockaddr_union ai_addr;
	struct addrinfo hints, *servinfo, *p;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af_hint;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	if (!pay_dst)
		return -EINVAL;

	/* resolve potential hostname to IP address */
	/* TODO: 1) get/set payload port here instead of NULL? needed for SRV
	 * records?
	 * 2) try inet_pton() first, before trying to resolve hostnames?
	 */
	ret = getaddrinfo(pay_dst, NULL, &hints, &servinfo);
	if (ret < 0)
		return ret;

	ret = -EINVAL;

	for (p = servinfo; p; p = p->ai_next) {
		if (p->ai_addrlen > sizeof(ai_addr))
			break;

		memcpy(&ai_addr, p->ai_addr, p->ai_addrlen);
		ret = sap_get_ip_dst(&ai_addr, &sap_dst);
		if (ret < 0)
			break;

		ctx_dest->dest = sap_dst;

		ret = sap_create_socket_tx(ctx_dest);
		if (ret < 0)
			continue;

		ret = sap_create_socket_rx(ctx_dest);
		if (ret < 0) {
			close(ctx_dest->sd_tx);
			continue;
		}

		/* ok */
		break;
	}

	freeaddrinfo(servinfo);
	return ret;
}

static void sap_free_socket(struct sap_ctx_dest *ctx_dest)
{
	close(ctx_dest->sd_tx);
	close(ctx_dest->sd_rx);
}

static uint8_t sap_get_flags(int sap_af, int msg_type)
{
	/* V=1: SAPv1/SAPv2 */
	uint8_t flags = SAP_FLAG_VERSION;

	/* A: address type */
	if (sap_af == AF_INET6)
		flags |= SAP_FLAG_IPV6;

	if (msg_type == SAP_TERMINATE)
		flags |= SAP_FLAG_TERMINATE;

	return flags;
}

static char *sap_push_orig_source(struct sap_ctx_dest *ctx_dest, char *msg)
{
	union sap_sockaddr_union *src = &ctx_dest->src;

	switch (src->s.sa_family) {
	case AF_INET:
		struct in_addr *addr4 = (struct in_addr *)msg;
		*addr4 = src->in.sin_addr;
		return msg + sizeof(*addr4);
	case AF_INET6:
		struct in6_addr *addr6 = (struct in6_addr *)msg;
		*addr6 = src->in6.sin6_addr;
		return msg + sizeof(*addr6);
	}

	return msg;
}

static char *sap_push_auth_data(char *msg)
{
	/* TODO */
	return msg;
}

static char *sap_push_payload_type(char *msg, const char *payload_type)
{
	size_t len = strlen(payload_type);

	if (!msg)
		return msg;

	strcpy(msg, payload_type);
	return msg + len + 1;
}

static char *sap_push_payload(char *msg, const char *payload)
{
	/* TODO: compression and encryption options */
	size_t len = strlen(payload);

	if (!msg)
		return msg;

	memcpy(msg, payload, len);
	return msg + len;
}

static void sap_create_message(struct sap_ctx_dest *ctx_dest,
			       const char *payload, const char *payload_type,
			       int msg_type, uint16_t msg_id_hash)
{
	int sap_af = ctx_dest->dest.s.sa_family;
	size_t len, orig_source_len = 0;
	char *msg;

	struct sap_packet packet = {
		.flags = sap_get_flags(sap_af, msg_type),
		.auth_len = 0,
		.msg_id_hash = msg_id_hash,
	};

	switch (sap_af) {
	case AF_INET:
		orig_source_len = sizeof(struct in_addr);
		break;
	case AF_INET6:
		orig_source_len = sizeof(struct in6_addr);
		break;
	}

	len = sizeof(packet) + orig_source_len + packet.auth_len;
       	len += strlen(payload_type) + 1 + strlen(payload);

	msg = malloc(len);
	if (!msg)
		return;

	ctx_dest->message = msg;
	memset(msg, 0, len);


	memcpy(msg, &packet, sizeof(packet));
	msg += sizeof(packet);

	msg = sap_push_orig_source(ctx_dest, msg);
	msg = sap_push_auth_data(msg);
	msg = sap_push_payload_type(msg, payload_type);
	msg = sap_push_payload(msg, payload);

	if (msg - ctx_dest->message != len) {
		free(ctx_dest->message);
		ctx_dest->message = NULL;
		len = 0;
		return;
	}

	ctx_dest->msg_len = len;
	ctx_dest->total_msg_lens += len + sap_ipeth_hdrlen(&ctx_dest->dest);
	ctx_dest->num_sessions++;
}

static int sap_init_ctx_dest_add_epoll(struct sap_ctx_dest *ctx_dest)
{
	int ret;

	/* unused / should not receive anything */
	ret = sap_init_add_epoll(ctx_dest->sd_tx, ctx_dest->ctx,
				 &ctx_dest->ctx->epoll_ctx_none);
	if (ret < 0)
		return ret;

	/* SAP packet reception */
	ret = sap_init_add_epoll(ctx_dest->sd_rx, ctx_dest->ctx,
				 &ctx_dest->epoll_ctx_rx);
	if (ret < 0)
		return ret;

	/* wake-up timer for SAP packet transmission */
	ret = sap_init_add_epoll(ctx_dest->timer_fd, ctx_dest->ctx,
				 &ctx_dest->epoll_ctx_tx);
	if (ret < 0)
		return ret;

	return 0;
}

static void sap_init_ctx_dest_del_epoll(struct sap_ctx_dest *ctx_dest)
{
	sap_init_del_epoll(ctx_dest->timer_fd, ctx_dest->ctx);
	sap_init_del_epoll(ctx_dest->sd_rx, ctx_dest->ctx);
	sap_init_del_epoll(ctx_dest->sd_tx, ctx_dest->ctx);
}

static struct sap_ctx_dest *
sap_init_ctx_dest(struct sap_ctx *ctx, char *payload_dest, int payload_dest_af,
		  char *payload_type, char *payload, int msg_type,
		  uint16_t msg_id_hash)
{
	struct sap_ctx_dest *ctx_dest;
	int ret;

	ctx_dest = malloc(sizeof(*ctx_dest));
	if (!ctx_dest)
		return NULL;

	memset(ctx_dest, 0, sizeof(*ctx_dest));
	INIT_HLIST_HEAD(&ctx_dest->sessions_list);
	ctx_dest->ctx = ctx;
	ctx_dest->epoll_ctx_rx = SAP_EPOLL_CTX_TYPE_RX;
	ctx_dest->epoll_ctx_tx = SAP_EPOLL_CTX_TYPE_TX;
	ctx_dest->total_msg_lens = 0;
	ctx_dest->num_sessions = 0;

	ctx_dest->timer_fd = timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK);
	if (ctx_dest->timer_fd < 0)
		goto err1;

	ret = sap_create_socket(ctx_dest, payload_dest, payload_dest_af);
	if (ret < 0)
		goto err2;

	sap_create_message(ctx_dest, payload, payload_type, msg_type, msg_id_hash);
	if (!ctx_dest->message)
		goto err3;

	ret = sap_init_ctx_dest_add_epoll(ctx_dest);
	if (ret < 0)
		goto err4;

	return ctx_dest;
err4:
	free(ctx_dest->message);
err3:
	sap_free_socket(ctx_dest);
err2:
	close(ctx_dest->timer_fd);
err1:
	free(ctx_dest);
	return NULL;
}

static void sap_free_ctx_dest(struct sap_ctx_dest *ctx_dest)
{
	sap_init_ctx_dest_del_epoll(ctx_dest);
	free(ctx_dest->message);
	sap_free_socket(ctx_dest);
	close(ctx_dest->timer_fd);
	free(ctx_dest);
}

static void sap_free_ctx_dests(struct sap_ctx *ctx)
{
	struct sap_ctx_dest *ctx_dest;
	struct hlist_node *tmp;

	hlist_for_each_entry_safe(ctx_dest, tmp, &ctx->dest_list, node) {
		hlist_del(&ctx_dest->node);
		sap_free_ctx_dest(ctx_dest);
	}
}

static int sap_init_ctx_dests(struct sap_ctx *ctx, char *payload_dests[],
			      int payload_dest_af, char *payload_type,
			      char *payload, int msg_type, uint16_t msg_id)
{
	struct sap_ctx_dest *ctx_dest;
	char *dest;
	int i;

	for (i = 0, dest = payload_dests[i]; dest; dest = payload_dests[++i]) {
		ctx_dest = sap_init_ctx_dest(ctx, dest, payload_dest_af,
					     payload_type, payload, msg_type,
					     msg_id);
		if (!ctx_dest)
			goto err;

		hlist_add_head(&ctx_dest->node, &ctx->dest_list);
		ctx->num_dests++;
	}

	ctx->count_max *= ctx->num_dests;
	return 0;
err:
	sap_free_ctx_dests(ctx);
	return -EINVAL;
}

/* use this if you need full, customized control, e.g. for debugging (tools) */
struct sap_ctx *sap_init_custom(
	char *payload_dests[],
	int payload_dest_af,
	char *payload_filename,
	char *payload_type,
	int msg_type,
	uint16_t *msg_id_hash,
	unsigned int interval,
	int no_jitter,
	unsigned long count,
	long bw_limit)
{
	char **payload_dests_tmp = NULL;
	struct sap_ctx *ctx;
	char *payload;
	uint16_t msg_id;
	int ret;

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		errno = -ENOMEM;
		return NULL;
	}

	memset(ctx, 0, sizeof(*ctx));
	INIT_HLIST_HEAD(&ctx->dest_list);
	ctx->num_dests = 0;
	ctx->msg_type = msg_type;
	ctx->interval = interval ? interval : SAP_INTERVAL_SEC;
	ctx->no_jitter = no_jitter;
	ctx->count = 0;
	ctx->count_max = count;
	ctx->term = 0;
	ctx->epoll_ctx_none = SAP_EPOLL_CTX_TYPE_NONE;
	ctx->thread.tid = NULL;
	ctx->thread.tid_store = 0;

	/* disabled limit */
	if (bw_limit < 0)
		ctx->bw_limit = 0;
	/* default limit */
	else if (!bw_limit)
		ctx->bw_limit = SAP_BANDWIDTH_LIMIT;
	/* configured limit */
	else
		ctx->bw_limit = (unsigned long)bw_limit;

	if (mtx_init(&ctx->thread.ctrl_lock, mtx_plain) == thrd_error)
		goto err1;

	if (!payload_type)
		payload_type = SAP_PAYLOAD_TYPE_SDP;

	ret = sap_init_random(ctx);
	if (ret < 0) {
		errno = ret;
		goto err2;
	}

	msg_id = sap_get_msg_id_hash(ctx, msg_id_hash);

	ret = sap_init_epoll(ctx);
	if (ret < 0) {
		errno = -EPERM;
		goto err2;
	}

	payload = sap_get_payload(payload_filename);
	if (!payload) {
		errno = -ENOENT;
		goto err3;
	}

	if (!payload_dests && !strcmp(payload_type, SAP_PAYLOAD_TYPE_SDP)) {
		payload_dests_tmp = sap_get_payload_dests(payload);
		payload_dests = payload_dests_tmp;
	}
	if (!payload_dests) {
		errno = -EINVAL;
		exit(2);
		goto err4;
	}

	ret = sap_init_ctx_dests(ctx, payload_dests, payload_dest_af,
				 payload_type, payload, msg_type, msg_id);
	if (ret < 0)
		goto err5;

	free(payload_dests_tmp);
	free(payload);
	return ctx;

err5:
	free(payload_dests_tmp);
err4:
	free(payload);
err3:
	sap_free_epoll(ctx);
err2:
	mtx_destroy(&ctx->thread.ctrl_lock);
err1:
	free(ctx);
	return NULL;
}

/* not quite RFC2974 compliant, but more responsive alternative to sap_init() */
struct sap_ctx *sap_init_fast(char *payload_filename)
{
	return sap_init_custom(NULL, AF_UNSPEC, payload_filename, NULL, -1,
			       NULL, 5, 0, 0, 0);
}

/* use this for fully RFC2974 compliant execution, e.g. for daemons */
struct sap_ctx *sap_init(char *payload_filename)
{
	return sap_init_custom(NULL, AF_UNSPEC, payload_filename, NULL, -1,
			       NULL, 0, 0, 0, 0);
}

void sap_free(struct sap_ctx *ctx)
{
	sap_free_ctx_dests(ctx);
	sap_free_epoll(ctx);
	mtx_destroy(&ctx->thread.ctrl_lock);
	free(ctx);
}
