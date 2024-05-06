/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
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

#include <errno.h> // errno
#include <arpa/inet.h> // inet_ntop()

#include "libsap.h"
#include "times.h"

#ifdef __STDC_NO_THREADS__
#error I need threads to build this program!
#endif

#ifndef __GNUC__
#define IN6_IS_ADDR_MULTICAST(a) (((const uint8_t *) (a))[0] == 0xff)
#define IN6_IS_ADDR_LINKLOCAL(a) \
	((((const uint32_t *) (a))[0] & htonl (0xffc00000))		\
	 == htonl (0xfe800000))
#endif /* __GNUC__ */

#define BIT(n) (1 << n)

#define SAP_PORT 9875
#define SAP_PAYLOAD_TYPE_SDP "application/sdp"
#define SAP_INTERVAL_SEC 300


enum sap_msg_type {
	SAP_ANNOUNCE = 0,
	SAP_TERMINATE = 1,
};

struct sap_packet {
	uint8_t flags;
	uint8_t auth_len;
	uint16_t msg_id_hash;
} __attribute__ ((__packed__));

struct sap_ctx_dest {
	struct sap_ctx *ctx;
	enum sap_epoll_ctx_type epoll_ctx_rx;
	enum sap_epoll_ctx_type epoll_ctx_tx;
	int sd;
	int timer_fd;
	struct sockaddr_storage dest;
	struct sockaddr_storage src;
	char *message;
	size_t msg_len;
	struct hlist_node node;
};

#define sap_container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#define IN_MC_LINK_LOCAL(a) ((((in_addr_t)(a)) & 0xffffff00) == 0xe0000000)
#define IN_MC_LOCAL(a) ((((in_addr_t)(a)) & 0xffff0000) == 0xefff0000)
#define IN_MC_ORG_LOCAL(a) ((((in_addr_t)(a)) & 0xfffc0000) == 0xefc00000)
#define IN_MC_ADMIN(a) ((((in_addr_t)(a)) & 0xff000000) == 0xef000000)
#define IN_MC_GLOBAL(a) (IN_MULTICAST(a) && !IN_MC_ADMIN(a) && !IN_MC_LINK_LOCAL(a))

#define IN_MC_SAP_LINK_LOCAL ((in_addr_t) 0xe00000ff)
#define IN_MC_SAP_LOCAL ((in_addr_t) 0xefffffff)
#define IN_MC_SAP_ORG_LOCAL ((in_addr_t) 0xefc3ffff)
#define IN_MC_SAP_GLOBAL ((in_addr_t) 0xe0027ffe)

static int sap_get_ip4_dst(const struct sockaddr_in *pay_dst, struct sockaddr_in *sap_dst)
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

static int sap_get_ip6_dst(const struct sockaddr_in6 *pay_dst, struct sockaddr_in6 *sap_dst)
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

//printf("~~~ %s:%i: pay_dst: %i\n", __func__, __LINE__, pay_dst->sin6_family);
//printf("~~~ %s:%i: here\n", __func__, __LINE__);
	sap_dst->sin6_family = pay_dst->sin6_family;
	sap_dst->sin6_addr = dst;
	sap_dst->sin6_port = htons(SAP_PORT);
	sap_dst->sin6_flowinfo = 0;
	sap_dst->sin6_scope_id = pay_dst->sin6_scope_id;

	return 0;
}

static int sap_get_ip_dst(struct sockaddr *addr, struct sockaddr_storage *sap_dst)
{
	switch (addr->sa_family) {
	case AF_INET:
		return sap_get_ip4_dst((struct sockaddr_in *)addr,
				       (struct sockaddr_in *)sap_dst);
	case AF_INET6:
		return sap_get_ip6_dst((struct sockaddr_in6 *)addr,
				       (struct sockaddr_in6 *)sap_dst);
	}

	return -EPROTONOSUPPORT;
}

static int sap_set_hop_limit(int sd, struct sockaddr_storage *sap_dst)
{
	int hops = 255;
	in_addr_t dst;

	if (sap_dst->ss_family == AF_INET) {
		dst = ntohl(((struct sockaddr_in *)sap_dst)->sin_addr.s_addr);

		if (IN_MC_LINK_LOCAL(dst))
			return 0;

		return setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &hops,
				  sizeof(hops));
	} else if (sap_dst->ss_family == AF_INET6) {
		return setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
				  sizeof(hops));
	}

	return -EINVAL;
}

static int sap_join_dest4(struct sap_ctx_dest *ctx_dest)
{
	/* TODO */
	return -EINVAL;
}

static int sap_join_dest6(struct sap_ctx_dest *ctx_dest)
{
	struct sockaddr_in6 *dest = (struct sockaddr_in6 *)&ctx_dest->dest;
	int ret;

	struct ipv6_mreq mreq = {
		.ipv6mr_multiaddr = dest->sin6_addr,
		.ipv6mr_interface = dest->sin6_scope_id,
	};

	ret = setsockopt(ctx_dest->sd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
			  (void *)&mreq, sizeof(mreq));

	printf("~~~ %s:%i: ret: %i\n", __func__, __LINE__, ret);
	return ret;
}

static int sap_join_dest(struct sap_ctx_dest *ctx_dest)
{
	printf("~~~ %s:%i: start\n", __func__, __LINE__);

	switch (ctx_dest->dest.ss_family) {
	case AF_INET:
		return sap_join_dest4(ctx_dest);
	case AF_INET6:
		return sap_join_dest6(ctx_dest);
	}

	printf("~~~ %s:%i: start\n", __func__, __LINE__);
	return -EINVAL;
}

static int sap_create_socket(struct sap_ctx_dest *ctx_dest, char *pay_dst, int af_hint)
{
	char dest[INET6_ADDRSTRLEN];
	struct sockaddr_storage sap_dst = { 0 };
	struct addrinfo hints, *servinfo, *p;
	int ret, sd = -EINVAL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af_hint;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	if (!pay_dst)
		return sd;

	/* resolve potential hostname to IP address */
	/* TODO: 1) get/set payload port here instead of NULL? needed for SRV records?
	 * 2) try inet_pton() first, before trying to resolve hostnames? */
	ret = getaddrinfo(pay_dst, NULL, &hints, &servinfo);
	if (ret < 0)
		return ret;

	for (p = servinfo; p; p = p->ai_next) {
inet_ntop(p->ai_family, &((struct sockaddr_in6 *)&p->ai_addr)->sin6_addr, dest, sizeof(dest));
printf("~~~ %s:%i: here, ai_family: %i, ai_addr: %s\n", __func__, __LINE__, p->ai_family, dest);
		ret = sap_get_ip_dst(p->ai_addr, &sap_dst);
		if (ret < 0)
			break;

		if (p->ai_addr->sa_family != sap_dst.ss_family)
			fprintf(stderr, "Error: address family was not copied? %i vs. %i\n", p->ai_addr->sa_family, sap_dst.ss_family);

printf("~~~ %s:%i: sap_dst.ss_family: %i, proto: %i\n", __func__, __LINE__, sap_dst.ss_family,IPPROTO_UDP);
		sd = socket(sap_dst.ss_family, SOCK_DGRAM, IPPROTO_UDP);
		if (sd >= 0)
			break;
	}

printf("~~~ %s:%i: sd: %i\n", __func__, __LINE__, sd);
	if (sd < 0) {
		ret = sd;
		goto out;
	}

	ctx_dest->dest = sap_dst;
	ctx_dest->sd = sd;

printf("~~~ %s:%i: HEEERE\n", __func__, __LINE__);
/*	ret = connect(sd, (const struct sockaddr *)&sap_dst, sizeof(sap_dst));
	if (ret < 0)
		goto err;

	struct sockaddr unconnect = { 0 };
	unconnect.sa_family = AF_UNSPEC;

	ret = connect(sd, &unconnect, sizeof(unconnect));
	if (ret < 0)
		goto err;*/

printf("~~~ %s:%i: HEEERE2\n", __func__, __LINE__);
	struct sockaddr_in6 listen = { 0 };
	listen.sin6_family = AF_INET6;
//	listen.sin6_port = ((struct sockaddr_in6 *)&sap_dst)->sin6_port;
	listen.sin6_port = htons(SAP_PORT);
	listen.sin6_addr = in6addr_any;
	listen.sin6_scope_id = ((struct sockaddr_in6 *)&sap_dst)->sin6_scope_id;

	ret = bind(sd, (const struct sockaddr *)&listen, sizeof(listen));
	if (ret < 0)
		goto err;

printf("~~~ %s:%i: HEEERE3\n", __func__, __LINE__);
/*	ret = connect(sd, (const struct sockaddr *)&sap_dst, sizeof(sap_dst));
	if (ret < 0)
		goto err;*/

	ret = sap_set_hop_limit(sd, &sap_dst);
	if (ret < 0)
		goto err;

	ret = sap_join_dest(ctx_dest);
	if (ret < 0)
		goto err;

	return 0;

err:
	close(sd);
out:
	freeaddrinfo(servinfo);
	return ret;
}

static uint8_t sap_get_flags(int sap_af, int msg_type)
{
	/* V=1: SAPv1/SAPv2 */
	uint8_t flags = BIT(5);

	/* A: address type */
	if (sap_af == AF_INET6)
		flags |= BIT(4);

	if (msg_type == SAP_TERMINATE)
		flags |= BIT(2);

	return flags;
}

static uint16_t sap_get_rand_uint16(struct sap_ctx *ctx)
{
	int32_t res;

	random_r(&ctx->rand.rd, &res);

	return res % (UINT16_MAX + 1);
}

static uint16_t sap_get_msg_id_hash(struct sap_ctx *ctx, uint16_t *msg_id_hash)
{
	if (!msg_id_hash)
		return sap_get_rand_uint16(ctx);
	else
		return htons(*msg_id_hash);
}

static char *sap_push_orig_source(struct sap_ctx_dest *ctx_dest, char *msg, int sd)
{
	/* FIXME? incorrect now, as we don't connect? */
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);

	if (sd < 0)
		NULL;

	getsockname(sd, (struct sockaddr *)&addr, &len);
	ctx_dest->src = addr;

	switch (addr.ss_family) {
	case AF_INET:
		struct in_addr *addr4 = (struct in_addr *)msg;
		*addr4 = ((struct sockaddr_in *)&addr)->sin_addr;
		return msg + sizeof(*addr4);
	case AF_INET6:
		struct in6_addr *addr6 = (struct in6_addr *)msg;
		*addr6 = ((struct sockaddr_in6 *)&addr)->sin6_addr;
		return msg + sizeof(*addr6);
	default:
		return NULL;
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

static void sap_create_message(struct sap_ctx_dest *ctx_dest, const char *payload, const char *payload_type, int msg_type, uint16_t msg_id_hash)
{
	int sap_af = ctx_dest->dest.ss_family;
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

	msg = sap_push_orig_source(ctx_dest, msg, ctx_dest->sd);
	msg = sap_push_auth_data(msg);
	msg = sap_push_payload_type(msg, payload_type);
	msg = sap_push_payload(msg, payload);

	if (msg - ctx_dest->message != len) {
		fprintf(stderr, "Error: Invalid message length\n");
		free(ctx_dest->message);
		ctx_dest->message = NULL;
		len = 0;
	}

	ctx_dest->msg_len = len;
}

static int sap_send(struct sap_ctx_dest *ctx_dest)
{
	return sendto(ctx_dest->sd, ctx_dest->message, ctx_dest->msg_len, 0, (struct sockaddr *)&ctx_dest->dest, sizeof(ctx_dest->dest));
//	return send(ctx_dest->sd, ctx_dest->message, ctx_dest->msg_len, 0);
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

static char *sap_get_payload_dest(const char *payload, char *dest)
{
	/* TODO: check for multiple "c=" lines, get
	 * SAP multicast destination for each */
	char *end;

	while(1) {
		if (!strncmp("c=", payload, strlen("c=")))
			break;

		/* go to next line */
		payload = strchr(payload, '\n');
		if (payload) {
			payload += 1;
			if (*payload == '\r')
				payload += 1;
		/* no next line exists */
		} else {
			return NULL;
		}
	}

	if (!strncmp("c=IN IP6 ", payload, strlen("c=IN IP6 ")))
		payload += strlen("c=IN IP6 ");
	else if (!strncmp("c=IN IP4 ", payload, strlen("c=IN IP4 ")))
		payload += strlen("c=IN IP4 ");

	strncpy(dest, payload, INET6_ADDRSTRLEN);

	end = strpbrk(dest, "/\r\n");
	if (end)
		*end = '\0';

	return dest;
}

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
	int32_t rand;
	int ret;

	/* We don't need crypto quality random numbers. But we want to:
	 * a) avoid messing with the global states of (s)rand()/(s)random()
	 * as we are a library
	 * b) avoid collisions on embedded systems which often boot
	 * into the same uptime state and don't have a persistent RTC
	 * c) be MT safe
	 */

	memset(rd, 0, sizeof(*rd));
	ret = initstate_r((unsigned int)pid, sap_ctx->rand.rs, sizeof(sap_ctx->rand.rs), rd);
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

//	printf("~~~ %s:%i: up.tv_sec: %li, up.tv_nsec: %li, t.tv_sec: %li, t.tv_nsec: %li\n", __func__, __LINE__, uptime.tv_sec, uptime.tv_nsec, time.tv_sec, time.tv_nsec);

	return 0;
}

static int sap_init_add_epoll(int fd, struct sap_ctx *ctx, enum sap_epoll_ctx_type *type)
{
	struct epoll_event event;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = type;

	return epoll_ctl(ctx->epoll.epoll_fd, EPOLL_CTL_ADD, fd, &event);
}

static int sap_init_epoll(struct sap_ctx *ctx)
{
	int ret = -EINVAL;

	ctx->epoll.epoll_fd = epoll_create1(0);
	if (!ctx->epoll.epoll_fd < 0)
		goto err1;

	ret = pipe(ctx->thread.pipefd);
	if (ret < 0) {
		goto err2;
	}

	/* no action needed, only to wake up epoll_wait() to check ctx->term */
	ctx->thread.epoll_ctx = SAP_EPOLL_CTX_TYPE_NONE;
	ret = sap_init_add_epoll(ctx->thread.pipefd[0], ctx,
				 &ctx->thread.epoll_ctx);
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

static struct sap_ctx_dest *sap_init_ctx_dest(struct sap_ctx *ctx, char *payload_dest, int payload_dest_af, char *payload_type, char *payload, int msg_type, uint16_t msg_id_hash)
{
	struct sap_ctx_dest *ctx_dest;
	int ret;

	printf("~~~ %s:%i: start, dest: %s\n", __func__, __LINE__, payload_dest);
	ctx_dest = malloc(sizeof(*ctx_dest));
	if (!ctx_dest)
		goto err1;

	ctx_dest->ctx = ctx;
	ctx_dest->epoll_ctx_rx = SAP_EPOLL_CTX_TYPE_RX;
	ctx_dest->epoll_ctx_tx = SAP_EPOLL_CTX_TYPE_TX;

	ctx_dest->timer_fd = timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK);
	if (ctx_dest->timer_fd < 0)
		goto err2;

	printf("~~~ %s:%i: start, dest: %s\n", __func__, __LINE__, payload_dest);
	ret = sap_create_socket(ctx_dest, payload_dest, payload_dest_af);
	if (ret < 0)
		goto err3;

	printf("~~~ %s:%i: start, dest: %s\n", __func__, __LINE__, payload_dest);
	sap_create_message(ctx_dest, payload, payload_type, msg_type, msg_id_hash);
	if (!ctx_dest->message)
		goto err4;

	ret = sap_init_add_epoll(ctx_dest->timer_fd, ctx, &ctx_dest->epoll_ctx_tx);
	if (ret < 0)
		goto err5;

	return ctx_dest;
err5:
	free(ctx_dest->message);
err4:
	close(ctx_dest->sd);
err3:
	close(ctx_dest->timer_fd);
err2:
	free(ctx_dest);
err1:
	return NULL;
}

static int sap_init_add_ctx_dest(struct sap_ctx_dest *ctx_dest, struct sap_ctx *ctx)
{	
	// ToDo: check duplicates

	printf("~~~ %s:%i\n", __func__, __LINE__);
	hlist_add_head(&ctx_dest->node, &ctx->dest_list);

	return sap_init_add_epoll(ctx_dest->sd, ctx, &ctx_dest->epoll_ctx_rx);
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
	unsigned long count)
{
	//char dest[INET6_ADDRSTRLEN];
	char *dest;
	struct sap_ctx *ctx;
	struct sap_ctx_dest *ctx_dest;
	char *payload;
	int ret, sap_af, i;
	uint16_t msg_id;

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		errno = -ENOMEM;
		return NULL;
	}

	memset(ctx, 0, sizeof(*ctx));
	INIT_HLIST_HEAD(&ctx->dest_list);
	//ctx->sd = -1;
	ctx->msg_type = msg_type;
	ctx->interval = interval;
	ctx->no_jitter = no_jitter;
	ctx->count = count;
	ctx->term = 0;
	ctx->thread.tid = NULL;
	ctx->thread.tid_store = 0;

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

	printf("~~~ %s:%i: here\n", __func__, __LINE__);
	ret = sap_init_epoll(ctx);
	if (ret < 0) {
		errno = -EPERM;
		goto err5;
	}

	printf("~~~ %s:%i: here, payload_filename: %s\n", __func__, __LINE__, payload_filename);
	payload = sap_get_payload(payload_filename);
	if (!payload) {
		errno = -ENOENT;
		goto err2;
	}

//ToDo:
//	if (!payload_dests && !strcmp(payload_type, SAP_PAYLOAD_TYPE_SDP))
//		payload_dests = sap_get_payload_dests(payload, dest);
	if (!payload_dests) {
		errno = -EINVAL;
		exit(2);
		goto err3;
	}

	printf("~~~ %s:%i: here\n", __func__, __LINE__);
	//sap_init_for_each_payload_dest(dest, payload_dests) {
	for (i = 0, dest = payload_dests[i]; dest; dest = payload_dests[++i]) {
	printf("~~~ %s:%i: here\n", __func__, __LINE__);
		ctx_dest = sap_init_ctx_dest(ctx, dest, payload_dest_af, payload_type, payload, msg_type, msg_id);
		if (!ctx_dest)
			goto err5;

		ret = sap_init_add_ctx_dest(ctx_dest, ctx);
		if (ret < 0) {
			free(ctx_dest);
			goto err5;
		}
	}

	free(payload);
	return ctx;

err5:
//	close(ctx->sd);
err4:
//	free(ctx->message);
err3:
	free(payload);
err2:
	mtx_destroy(&ctx->thread.ctrl_lock);
err1:
	free(ctx);
	return NULL;
}

/* use this for fully RFC2974 compliant execution, e.g. for daemons */
struct sap_ctx *sap_init(char *payload_filename)
{
	return sap_init_custom(NULL, AF_UNSPEC, payload_filename, NULL, -1, NULL, 0, 0, 0);
}

void sap_free(struct sap_ctx *ctx)
{
	close(ctx->epoll.epoll_fd);
//	close(ctx->sd);
//	free(ctx->message);
	mtx_destroy(&ctx->thread.ctrl_lock);
	free(ctx);
}

/* in milliseconds */
static unsigned int sap_get_interval(struct sap_ctx *ctx)
{
	unsigned int interval = SAP_INTERVAL_SEC * 1000;
	int offset;

	if (ctx->interval)
		interval = ctx->interval * 1000;

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

/* in milliseconds */
static int sap_get_timeout(struct sap_ctx *ctx)
{
	struct timespec now;
	int64_t diff;
//	int timeout = 

	clock_gettime(CLOCK_MONOTONIC, &now);

	diff = timespec_diffus(now, ctx->epoll.epoll_timeout) / 1000;
	if (diff < 0)
		return 0;

	return (diff > INT_MAX) ? INT_MAX : (int)diff;
}

/*static void sap_set_timeout_next(struct sap_ctx *ctx)
{
	unsigned int interval = sap_get_interval(ctx);
	struct timespec now, add;

	clock_gettime(CLOCK_MONOTONIC, &now);

	add.tv_sec = interval / 1000;
	add.tv_nsec = (interval % 1000) * (1000*1000);

	ctx->epoll.epoll_timeout = timespec_sum(now, add);
}

static void sap_set_timeout_now(struct sap_ctx *ctx)
{
	clock_gettime(CLOCK_MONOTONIC, &ctx->epoll.epoll_timeout);
}*/

static struct itimerspec sap_get_timeout_next(struct sap_ctx *ctx)
{
	unsigned int interval = sap_get_interval(ctx);
	struct itimerspec timer = {
		.it_interval = 0,
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

	timer = sap_get_timeout_next(ctx_dest->ctx);
	timerfd_settime(ctx_dest->timer_fd, 0, &timer, NULL);
}

static void sap_set_timers_next(struct sap_ctx *ctx)
{
	struct sap_ctx_dest *ctx_dest;

	hlist_for_each_entry(ctx_dest, &ctx->dest_list, node) {
		sap_set_timer_next(ctx_dest);
	}
}

/*static int sap_get_next_timeout(struct sap_ctx *ctx)
{
	unsigned int interval = sap_get_interval(ctx);
	struct timespec now, add, next;
	int64_t diff;

	clock_gettime(CLOCK_MONOTONIC, &now);

	add.tv_sec = interval / 1000;
	add.tv_nsec = (interval % 1000) * (1000*1000);
	next = timespec_sum(request_time_cache[rtcidx], add);

	diff = timespec_diffus(now, next) / 1000;
	if (diff < 0)
		return 0;

	return (diff > INT_MAX) ? INT_MAX : (int)diff;
}*/

//#define MAX_EVENTS 32

static void sap_set_msg_type(struct sap_ctx_dest *ctx_dest, int msg_type)
{
	struct sap_packet *packet = (struct sap_packet *)ctx_dest->message;

	/* SAP_TERMINATE */
	if (msg_type)
		packet->flags |= BIT(2);
	/* SAP_ANNOUNCE */
	else
		packet->flags &= ~BIT(2);
}

/*void sap_msleep(struct sap_ctx *ctx, unsigned int msecs)
{
	usleep(msecs * 1000);
}*/

/*static int sap_cmp_addr(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2)
{
	char dest1[INET6_ADDRSTRLEN];
	char dest2[INET6_ADDRSTRLEN];
	printf("~~~ %s:%i: start\n", __func__, __LINE__);
	if (addr1->ss_family != addr2->ss_family)
		return 0;

	printf("~~~ %s:%i: start\n", __func__, __LINE__);
	switch (addr1->ss_family) {
	case AF_INET:
	printf("~~~ %s:%i: start\n", __func__, __LINE__);
//		struct sockaddr_in *addr4
		return !memcmp(&((struct sockaddr_in *)addr1)->sin_addr,
				&((struct sockaddr_in *)addr2)->sin_addr,
				sizeof(*addr1));
	case AF_INET6:
	inet_ntop(addr1->ss_family, &((struct sockaddr_in6 *)addr1)->sin6_addr, dest1, sizeof(dest1));
	inet_ntop(addr2->ss_family, &((struct sockaddr_in6 *)addr2)->sin6_addr, dest2, sizeof(dest2));
	printf("~~~ %s:%i: addr1: %s, addr2: %s\n", __func__, __LINE__, dest1, dest2);
		return !memcmp(&((struct sockaddr_in6 *)addr1)->sin6_addr,
				&((struct sockaddr_in6 *)addr2)->sin6_addr,
				sizeof(*addr1));
	}

	printf("~~~ %s:%i: start\n", __func__, __LINE__);
	return 0;
}*/

static int sap_is_my_source(struct sap_ctx_dest *ctx_dest, struct sockaddr_storage *addr)
{
	struct sockaddr_storage *src = &ctx_dest->src;
	struct in6_addr *ip6;

	printf("~~~ %s:%i: start, af1: %i, af2: %i\n", __func__, __LINE__, src->ss_family, addr->ss_family);
	if (src->ss_family != addr->ss_family)
		return 0;

	printf("~~~ %s:%i: start\n", __func__, __LINE__);
	switch (src->ss_family) {
	case AF_INET:
		return !memcmp(&((struct sockaddr_in *)src)->sin_addr,
			       &((struct sockaddr_in *)addr)->sin_addr,
			       sizeof(struct in_addr));
	case AF_INET6:

	ip6 = &((struct sockaddr_in6 *)src)->sin6_addr;
	printf("~~~ %s:%i: addr: %08x%08x%08x%08x\n", __func__, __LINE__,
			ntohl(ip6->s6_addr32[0]),
			ntohl(ip6->s6_addr32[1]),
			ntohl(ip6->s6_addr32[2]),
			ntohl(ip6->s6_addr32[3])
			);


	printf("~~~ %s:%i: start\n", __func__, __LINE__);
		return !memcmp(&((struct sockaddr_in6 *)src)->sin6_addr,
			       &((struct sockaddr_in6 *)addr)->sin6_addr,
			       sizeof(struct in6_addr));
	}

	printf("~~~ %s:%i: start\n", __func__, __LINE__);
	return 0;
}

static int sap_epoll_rx_handler(struct sap_ctx_dest *ctx_dest)
{
	char buffer[2048];
	unsigned int buf_len = sizeof(buffer);
	struct sockaddr_storage addr = { 0 };
	struct sockaddr_storage zero = { 0 };
	struct in6_addr *ip6;
	char dest[INET6_ADDRSTRLEN];
	socklen_t addr_len = sizeof(addr);
	ssize_t ret;
	int flags = 0;

	printf("~~~ %s:%i: start\n", __func__, __LINE__);
//	ret = recvfrom(ctx_dest->sd, NULL, 0, MSG_PEEK | MSG_TRUNC;
//	recv(ctx_dest->sd, NULL, 0, MSG_TRUNC);
	ret = recvfrom(ctx_dest->sd, buffer, 0, MSG_PEEK | MSG_TRUNC, (struct sockaddr *)&addr, &addr_len);
	if (ret < 0)
		return ret;

	if (sap_is_my_source(ctx_dest, &addr)) {
	printf("~~~ %s:%i: got own source\n", __func__, __LINE__);
		buf_len = 0;
		flags = MSG_TRUNC;
	}

	ret = recv(ctx_dest->sd, buffer, buf_len, flags);
	if (ret < 0)
		return ret;

//	ret = recv(ctx_dest->sd, NULL, 0, MSG_TRUNC);
	inet_ntop(addr.ss_family, &((struct sockaddr_in6 *)&addr)->sin6_addr, dest, sizeof(dest));
	printf("~~~ %s:%i: ret: %li, from addr: %s, af: %i, zero-addr: %s\n", __func__, __LINE__, ret, dest, addr.ss_family,
			!memcmp(&((struct sockaddr_in6 *)&addr)->sin6_addr, &((struct sockaddr_in6 *)&zero)->sin6_addr,
				sizeof(struct in6_addr)) ? "yes" : "no");

	ip6 = &((struct sockaddr_in6 *)&addr)->sin6_addr;
	printf("~~~ %s:%i: addr: %08x%08x%08x%08x\n", __func__, __LINE__,
			ntohl(ip6->s6_addr32[0]),
			ntohl(ip6->s6_addr32[1]),
			ntohl(ip6->s6_addr32[2]),
			ntohl(ip6->s6_addr32[3])
			);

	printf("~~~ %s:%i: start, addrlen(new): %li, addrlen(old): %li\n", __func__, __LINE__, addr_len, sizeof(addr));
//	sap_cmp_addr(&addr, &ctx_dest->dest);
//	if (memcmp(&addr, &ctx_dest->dest, sizeof(addr))) {
//	if (!sap_cmp_addr(&addr, &ctx_dest->dest)) {
//	printf("~~~ %s:%i: not for our multicast?\n", __func__, __LINE__);
//		return 0;
//	}


	inet_ntop(addr.ss_family, &((struct sockaddr_in6 *)&addr)->sin6_addr, dest, sizeof(dest));
	printf("~~~ %s:%i: ret: %li, from addr: %s\n", __func__, __LINE__, ret, dest);
out:

	return 0;
}

static int sap_epoll_tx_handler(struct sap_ctx_dest *ctx_dest)
{
	char dest[INET_ADDRSTRLEN];
	uint64_t res;
	int ret;

//	struct sap_ctx *ctx;
	printf("~~~ %s:%i: start\n", __func__, __LINE__);

	if (ctx_dest->dest.ss_family == AF_INET6)
		inet_ntop(ctx_dest->dest.ss_family, &((struct sockaddr_in6 *)&ctx_dest->dest)->sin6_addr, dest, sizeof(dest));

	ret = read(ctx_dest->timer_fd, &res, sizeof(res));
	printf("~~~ %s:%i: res: %lu, dest: %s\n", __func__, __LINE__, res, dest);

	sap_send(ctx_dest);
	sap_set_timer_next(ctx_dest);

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

int sap_run(struct sap_ctx *ctx)
{
	unsigned long count = 0;
	int ret;

	int sfd, timeout = -1, ev_count = -1;

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
//	timeout = sap_get_interval(ctx);

/*	sigset_t mask, old_mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGTERM);*/

//	ret = pthread_sigmask(SIG_UNBLOCK, &mask, &old_mask);
/*	ret = pthread_sigmask(SIG_SETMASK, &mask, &old_mask);
	if (ret != 0) {
	printf("~~~ %s:%i: pthread_sigmask() returned an error: %i\n", __func__, __LINE__, ret);
		exit(4);
	}*/

/*	sfd = signalfd(-1, &mask, 0);
	if (sfd == -1)
		exit(2);

	printf("~~~ %s:%i: signalfd(): ret: %i\n", __func__, __LINE__, sfd);*/


	while(!ctx->term) {
		/* we timed out */
/*		if (!ev_count || !timeout) {
			if (ctx->count && (count++) >= ctx->count)
				break;

			ret = sap_send(ctx);
			if (ret < 0) {
		printf("~~~ %s:%i: getting out after sap_send()\n", __func__, __LINE__);
				goto out;
			}*/

			/* for "debug mode" exit immediately, don't wait
			 * for another interval
			 */
/*			if (ctx->msg_type >= 0 &&
			    ctx->count && count >= ctx->count)
				goto out;

//			sap_set_timeout_next(ctx);
		}*/

		printf("~~~ %s:%i: calling: epoll_wait(), timeout: %i  (ctx->term: %i)\n", __func__, __LINE__, timeout, ctx->term);
//		timeout = sap_get_timeout(ctx);
//		ev_count = epoll_wait(ctx->epoll.epoll_fd, ctx->epoll.events, SAP_EPOLL_MAX_EVENTS, timeout);
		ev_count = epoll_wait(ctx->epoll.epoll_fd, ctx->epoll.events, SAP_EPOLL_MAX_EVENTS, -1);

		printf("~~~ %s:%i: epoll_wait() returned, ev_count: %i (ctx->term: %i)\n", __func__, __LINE__, ev_count, ctx->term);
		for(int i = 0; i < ev_count; i++) {
			ret = sap_epoll_event_handler(&ctx->epoll.events[i]);
			printf("~~~ %s:%i: epoll_wait(), ev: %i, fd: %i (ctx->term: %i)\n", __func__, __LINE__, i, ctx->epoll.events[i].data.fd, ctx->term);
//			events[i].data.fd
		}

	printf("~~~ %s:%i: here1, %u\n", __func__, __LINE__, timeout);

//		sleep(sap_get_interval(ctx));
	}

//	printf("~~~ %s:%i: term=1, getting out\n", __func__, __LINE__);
//	if (ctx->msg_type < 0) {
//		sap_set_msg_type(ctx, SAP_TERMINATE);
		/* TODO: update payload, RFC2974, section 6:
		 * "If the payload format is `application/sdp'
		 *  the deletion message is a single SDP line consisting of the origin
		 *  field of the announcement to be deleted."
		 */
//		ret = sap_send(ctx);
//		goto out;
//	}

	ret = 0;
out:
	ctx->term = 0;
	return ret;

//	close(epoll_fd);
}

int sap_run_thread(void *arg)
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
//	pthread_kill(*ctx->thread_state.tid, SIGINT);
//	pthread_kill(*ctx->thread_state.tid, SIGHUP);
//	pthread_kill(*ctx->thread_state.tid, SIGTERM);


	printf("~~~ %s:%i: calling thrd_join()\n", __func__, __LINE__);
		thrd_join(*ctx->thread.tid, NULL);
	printf("~~~ %s:%i: thrd_join() returned\n", __func__, __LINE__);
		ctx->thread.tid = NULL;
		ctx->thread.tid_store = 0;
	}

	mtx_unlock(&ctx->thread.ctrl_lock);
	/* waiting for runner to finish in case it's not a thread but
	 * a child/fork()'d process instead
	 */
/*	while (ctx->term) {
	printf("~~~ %s:%i: waiting for runner to finish\n", __func__, __LINE__);
		sleep(1);
	}*/
}


