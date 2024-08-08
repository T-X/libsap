#ifndef __LIBSAP_PLATFORM_THREADS_H__
#define __LIBSAP_PLATFORM_THREADS_H__

#if defined(HAVE_UV) && (defined(_WIN32) || defined(WIN32) || defined(__STDC_NO_THREADS__))
#include <uv.h>

typedef uv_thread_t sap_thrd_t;
typedef uv_thread_cb sap_thrd_start_t;
typedef uv_mutex_t sap_mtx_t;

#define sap_thrd_success 0
#define sap_mtx_plain 0

static inline int sap_thrd_create(sap_thrd_t *thr, int(*)(void *), sap_thrd_start_t func, void *arg)
{
	return uv_thread_create(thr, func, arg);
}

static inline int sap_thrd_join(sap_thrd_t *thr, int *)
{
	return uv_thread_join(thr);
}

static inline sap_thrd_t sap_thrd_current(void)
{
	return uv_thread_self();
}

static inline int sap_mtx_init(sap_mtx_t *mutex, int)
{
	return uv_mutex_init(mutex);
}

static inline void sap_mtx_destroy(sap_mtx_t *mutex)
{
	return uv_mutex_destroy(mutex);
}

static inline int sap_mtx_lock(sap_mtx_t *mutex)
{
	uv_mutex_lock(mutex);
	return 0;
}

static inline int sap_mtx_unlock(sap_mtx_t *mutex)
{
	uv_mutex_unlock(mutex);
	return 0;
}

#else
#include <threads.h>

typedef thrd_t sap_thrd_t;
typedef thrd_start_t sap_thrd_start_t;
typedef mtx_t sap_mtx_t;

#define sap_thrd_success thrd_success
#define sap_thrd_error thrd_error
#define sap_mtx_plain mtx_plain

static inline int sap_thrd_create(sap_thrd_t *thr, sap_thrd_start_t func, void(*)(void *), void *arg)
{
	return thrd_create(thr, func, arg);
}

static inline int sap_thrd_join(sap_thrd_t *thr, int *res)
{
	return thrd_join(*thr, res);
}

static inline sap_thrd_t sap_thrd_current(void)
{
	return thrd_current();
}

static inline int sap_mtx_init(sap_mtx_t *mutex, int type)
{
	return mtx_init(mutex, type);
}

static inline void sap_mtx_destroy(sap_mtx_t *mutex)
{
	return mtx_destroy(mutex);
}

static inline int sap_mtx_lock(sap_mtx_t *mutex)
{
	return mtx_lock(mutex);
}

static inline int sap_mtx_unlock(mtx_t *mutex)
{
	return mtx_unlock(mutex);
}
#endif

#endif /* __LIBSAP_PLATFORM_THREADS_H__ */
