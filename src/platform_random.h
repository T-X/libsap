#ifndef __LIBSAP_PLATFORM_RANDOM_H__
#define __LIBSAP_PLATFORM_RANDOM_H__

#include <stdlib.h>

#include "libsap_priv.h"
#include "platform_types.h"

#ifdef HAVE_UV
#include <uv.h>

//typedef void (*uv_random_cb)(uv_random_t *req, int status, void *buf, size_t buflen)

//int uv_random(uv_loop_t *loop, uv_random_t *req, void *buf, size_t buflen, unsigned int flags, uv_random_cb cb)

static inline int sap_init_random(struct sap_ctx *sap_ctx)
{
	return 0;
}

static inline uint16_t sap_get_rand_uint16(struct sap_ctx *ctx)
{
	uint16_t buf;
	int ret;

	ret = uv_random(NULL, NULL, &buf, sizeof(buf), 0, NULL);
	if (ret < 0)
		abort();

	return buf;
}

#else /* !HAVE_UV */

#include <sys/random.h>

static inline int sap_init_random(struct sap_ctx *sap_ctx)
{
	struct random_data *rd = &sap_ctx->rand.rd;
	unsigned int seed;
	int ret;

	//getrandom(void buf[.buflen], size_t buflen, unsigned int flags);
	memset(rd, 0, sizeof(*rd));
	getrandom(&seed, sizeof(seed), 0);
	if (ret < 0)
		return ret;

	return initstate_r(seed, sap_ctx->rand.rs,
			   sizeof(sap_ctx->rand.rs), rd);

//	ret = initstate_r((unsigned int)pid, sap_ctx->rand.rs,
//			  sizeof(sap_ctx->rand.rs), rd);
//	if (ret < 0)
//		return ret;

}

static inline uint16_t sap_get_rand_uint16(struct sap_ctx *ctx)
{
	int32_t res;

	random_r(&ctx->rand.rd, &res);

	return res % (UINT16_MAX + 1);
}

#endif /* HAVE_UV */

#endif /* __LIBSAP_PLATFORM_RANDOM_H__ */
