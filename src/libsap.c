/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

#include <errno.h> // errno
#include <arpa/inet.h> // inet_ntop()

#include "libsap.h"

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


enum sap_msg_type {
	SAP_ANNOUNCE = 0,
	SAP_TERMINATE = 1,
};

struct sap_packet {
	uint8_t flags;
	uint8_t auth_len;
	uint16_t msg_id_hash;
} __attribute__ ((__packed__));

#define IN_MC_LINK_LOCAL(a) ((((in_addr_t)(a)) & 0xffffff00) == 0xe0000000)
#define IN_MC_LOCAL(a) ((((in_addr_t)(a)) & 0xffff0000) == 0xefff0000)
#define IN_MC_ORG_LOCAL(a) ((((in_addr_t)(a)) & 0xfffc0000) == 0xefc00000)
#define IN_MC_ADMIN(a) ((((in_addr_t)(a)) & 0xff000000) == 0xef000000)
#define IN_MC_GLOBAL(a) (IN_MULTICAST(a) && !IN_MC_ADMIN(a) && !IN_MC_LINK_LOCAL(a))

#define IN_MC_SAP_LINK_LOCAL ((in_addr_t) 0xe00000ff)
#define IN_MC_SAP_LOCAL ((in_addr_t) 0xefffffff)
#define IN_MC_SAP_ORG_LOCAL ((in_addr_t) 0xefc3ffff)
#define IN_MC_SAP_GLOBAL ((in_addr_t) 0xe0027ffe)

static int sap_get_ip4_dst(struct sockaddr_in *pay_dst, struct sockaddr_in *sap_dst)
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
		break;
	case AF_INET6:
		return sap_get_ip6_dst((struct sockaddr_in6 *)addr,
				       (struct sockaddr_in6 *)sap_dst);
		break;
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

static int sap_create_socket(char *pay_dst, int af_hint, int *sap_af)
{
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
		return sd;

	for (p = servinfo; p; p = p->ai_next) {
		ret = sap_get_ip_dst(p->ai_addr, &sap_dst);
		if (ret < 0)
			break;

		sd = socket(sap_dst.ss_family, SOCK_DGRAM, IPPROTO_UDP);
		if (sd >= 0)
			break;
	}

	if (sd < 0)
		goto out;

	ret = connect(sd, (const struct sockaddr *)&sap_dst, sizeof(sap_dst));
	if (ret < 0)
		goto err;

	ret = sap_set_hop_limit(sd, &sap_dst);
	if (ret < 0)
		goto err;

	*sap_af = sap_dst.ss_family;	
	goto out;

err:
	close(sd);
	sd = -EINVAL;
out:
	freeaddrinfo(servinfo);	
	return sd;
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

	random_r(&ctx->rand_state.rd, &res);

	return res % (UINT16_MAX + 1);
}

static uint16_t sap_get_msg_id_hash(struct sap_ctx *ctx, uint16_t *msg_id_hash)
{
	if (!msg_id_hash)
		return sap_get_rand_uint16(ctx);
	else
		return ntohs(*msg_id_hash);
}

static char *sap_push_orig_source(char *msg, int sd)
{
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);

	getsockname(sd, (struct sockaddr *)&addr, &len);

	switch (addr.ss_family) {
	case AF_INET:
		struct in_addr *addr4 = (struct in_addr *)msg;
		*addr4 = ((struct sockaddr_in *)&addr)->sin_addr;
		return msg + sizeof(*addr4);
	case AF_INET6:
		struct in6_addr *addr6 = (struct in6_addr *)msg;
		*addr6 = ((struct sockaddr_in6 *)&addr)->sin6_addr;
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

	strcpy(msg, payload_type);
	return msg + len + 1;
}

static char *sap_push_payload(char *msg, const char *payload)
{
	/* TODO: compression and encryption options */
	size_t len = strlen(payload);

	memcpy(msg, payload, len);
	return msg + len;
}

static void sap_create_message(struct sap_ctx *ctx, int sap_af, const char *payload, const char *payload_type, int msg_type, uint16_t *msg_id_hash)
{
	size_t len, orig_source_len = 0;
	char *msg;
	struct sap_packet packet = {
		.flags = sap_get_flags(sap_af, msg_type),
		.auth_len = 0,
		.msg_id_hash = sap_get_msg_id_hash(ctx, msg_id_hash),
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

	ctx->message = msg;
	memset(msg, 0, len);


	memcpy(msg, &packet, sizeof(packet));
	msg += sizeof(packet);

	msg = sap_push_orig_source(msg, ctx->sd);
	msg = sap_push_auth_data(msg);
	msg = sap_push_payload_type(msg, payload_type);
	msg = sap_push_payload(msg, payload);

	if (msg - ctx->message != len) {
		fprintf(stderr, "Error: Invalid message length\n");
		free(ctx->message);
		ctx->message = NULL;
		len = 0;
	}

	ctx->msg_len = len;
}

static int sap_send(struct sap_ctx *ctx)
{
	return send(ctx->sd, ctx->message, ctx->msg_len, 0);
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
	struct random_data *rd = &sap_ctx->rand_state.rd;
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
	ret = initstate_r((unsigned int)pid, sap_ctx->rand_state.rs, sizeof(sap_ctx->rand_state.rs), rd);
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

	printf("~~~ %s:%i: up.tv_sec: %li, up.tv_nsec: %li, t.tv_sec: %li, t.tv_nsec: %li\n", __func__, __LINE__, uptime.tv_sec, uptime.tv_nsec, time.tv_sec, time.tv_nsec);

	return 0;
}

int sap_init(struct sap_ctx *sap_ctx,
	     char *payload_dest,
	     int payload_dest_af,
	     char *payload_filename,
	     char *payload_type,
	     int msg_type,
	     uint16_t *msg_id_hash,
	     unsigned int interval)
{
	char dest[INET6_ADDRSTRLEN];
	struct sap_ctx ctx;
	char *payload;
	int ret, sap_af;

	ctx.msg_type = msg_type;
	ctx.interval = interval;
	ctx.term = 0;

	ctx.thread_state.tid = NULL;
	ctx.thread_state.tid_store = 0;
	cnd_init(&ctx.thread_state.cnd);

	if (!payload_type)
		payload_type = SAP_PAYLOAD_TYPE_SDP;

	ret = sap_init_random(&ctx);
	if (ret < 0)
		return ret;

	payload = sap_get_payload(payload_filename);
	if (!payload)
		return -ENOENT;

	if (!payload_dest && !strcmp(payload_type, SAP_PAYLOAD_TYPE_SDP))
		payload_dest = sap_get_payload_dest(payload, dest);
	if (!payload_dest) {
		free(payload);
		return -EINVAL;
	}

	ctx.sd = sap_create_socket(payload_dest, payload_dest_af, &sap_af);
	if (ctx.sd < 0) {
		free(payload);
		return -EHOSTUNREACH;
	}

	sap_create_message(&ctx, sap_af, payload, payload_type, msg_type, msg_id_hash);
	if (!ctx.message) {
		free(payload);
		close(ctx.sd);
		return -EINVAL;
	}

	*sap_ctx = ctx;
	return 0;
}

void sap_free(struct sap_ctx *ctx)
{
	sap_stop(ctx);
	close(ctx->sd);
	free(ctx->message);
}

static unsigned int sap_get_interval(struct sap_ctx *ctx)
{
	unsigned int interval = 300 * 1000;
	int offset;

	if (ctx->interval)
		return ctx->interval * 1000;

	offset = sap_get_rand_uint16(ctx) % (interval * 2 / 3);
	offset -= interval / 3;

	printf("~~~ %s:%i: interval: %u, offset: %i\n", __func__, __LINE__, interval, offset);
	/* should not happen */
	if (interval + offset < 0)
		return interval;

	return interval + offset;
}

//#define MAX_EVENTS 32

static void sap_set_msg_type(struct sap_ctx *ctx, int msg_type)
{
	struct sap_packet *packet = (struct sap_packet *)ctx->message;

	/* SAP_TERMINATE */
	if (msg_type)
		packet->flags |= BIT(2);
	/* SAP_ANNOUNCE */
	else
		packet->flags &= ~BIT(2);
}

void sap_msleep(struct sap_ctx *ctx, unsigned int msecs)
{
	usleep(msecs * 1000);
}

int sap_run(struct sap_ctx *ctx)
{
	int ret;
//	static struct epoll_event events[MAX_EVENTS];
//	static int epoll_fd;

	unsigned int timeout;
//	int epoll_fd = epoll_create1(0);

	/* Without an explicit interval and with a specific
	 * message type we will just send a single one-shot
	 * packet of this type.
	 */
	if (!ctx->interval && ctx->msg_type >= 0) {
		ret = sap_send(ctx);
		goto out;
	}

	printf("~~~ %s:%i: here1\n", __func__, __LINE__);
//	timeout = sap_get_interval(ctx);

	while(!ctx->term) {
//		epoll_wait(epoll_fd, events, MAX_EVENTS, timeout)

		timeout = sap_get_interval(ctx);

		sap_msleep(ctx, timeout);

	printf("~~~ %s:%i: here1, %u\n", __func__, __LINE__, timeout);
		ret = sap_send(ctx);
		if (ret < 0)
			goto out;

//		sleep(sap_get_interval(ctx));
	}

	printf("~~~ %s:%i: term=1, getting out\n", __func__, __LINE__);
	if (ctx->msg_type < 0) {
		sap_set_msg_type(ctx, SAP_TERMINATE);
		/* TODO: update payload, RFC2974, section 6:
		 * "If the payload format is `application/sdp'
		 *  the deletion message is a single SDP line consisting of the origin
		 *  field of the announcement to be deleted."
		 */
		ret = sap_send(ctx);
		goto out;
	}

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

	ret = thrd_create(&tid, sap_run_thread, ctx);
	if (ret != thrd_success)
		return -EPERM;

	ctx->thread_state.tid_store = tid;
	ctx->thread_state.tid = &ctx->thread_state.tid_store;

	return 0;
}

void sap_stop(struct sap_ctx *ctx)
{
	ctx->term = 1;

	if (ctx->thread_state.tid) {
		thrd_join(*ctx->thread_state.tid, NULL);
		ctx->thread_state.tid = NULL;
		ctx->thread_state.tid_store = 0;
	}

	/* waiting for runner to finish in case it's not a thread but
	 * a child/fork()'d process instead
	 */
/*	while (ctx->term) {
	printf("~~~ %s:%i: waiting for runner to finish\n", __func__, __LINE__);
		sleep(1);
	}*/
}
