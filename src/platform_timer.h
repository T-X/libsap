#ifndef __LIBSAP_PLATFORM_TIMER_H__
#define __LIBSAP_PLATFORM_TIMER_H__

#include <time.h>
#include "libsap_priv.h"
#include "platform_types.h"

#ifdef HAVE_UV
#include <uv.h>

//int uv_timer_init(uv_loop_t *loop, uv_timer_t *handle)


static inline int sap_timer_create(const struct sap_ctx *ctx, sap_timer_t *timer)
//static inline sap_timerfd sap_timerfd_create(int clockid, int flags)
{
	int ret = uv_timer_init(ctx->epoll.uv_loop, timer);
	if (ret < 0)
		return -EINVAL;

	return 0;
}

static inline void sap_timer_destroy(sap_timer_t *timer)
{
	return;
}

// typedef void (*uv_timer_cb)(uv_timer_t *handle)
//static int sap_epoll_tx_handler(struct sap_ctx_dest *ctx_dest)

static inline void sap_timer_cb(sap_timer_t *handle)
{
	struct sap_ctx_dest *ctx_dest;

	ctx_dest = sap_container_of(handle, struct sap_ctx_dest, timer);
	sap_epoll_tx_handler(ctx_dest);
}

static inline void sap_timer_settime(sap_timer_t *sap_timer, struct itimerspec *timer)
{
	uint64_t timeout;

	timeout = timer->it_value.tv_sec * 1000;
	timeout += timer->it_value.tv_nsec % (1000 * 1000);

	uv_timer_start(sap_timer, sap_timer_cb, timeout, 0);
}

static inline void sap_timer_cooldown(sap_timer_t *timer)
{
}

#else /* !HAVE_UV */
#include <sys/timerfd.h>
//int timerfd_create(int clockid, int flags);

static inline int sap_timer_create(const struct sap_ctx *, sap_timer_t *timer)
{
	int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (fd < 0)
		return fd;

	*timer = fd;
	return 0;
}

static inline void sap_timer_destroy(sap_timer_t *timer)
{
	close(*timer);
}

static inline void sap_timer_settime(sap_timer_t *sap_timer, struct itimerspec *timer)
{
	timerfd_settime(*sap_timer, 0, timer, NULL);
}

static inline void sap_timer_cooldown(sap_timer_t *timer)
{
	uint64_t res;
	read(*timer, &res, sizeof(res));
}

#endif /* HAVE_UV */

//	ctx_dest->timer_fd = sap_timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK);
//
#endif /* __LIBSAP_PLATFORM_TIMER_H__ */
