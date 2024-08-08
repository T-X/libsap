#ifndef __LIBSAP_PLATFORM_TYPES_H__
#define __LIBSAP_PLATFORM_TYPES_H__

#ifdef HAVE_UV
#include <uv.h>

typedef int sap_random_data;
typedef uv_timer_t sap_timer_t;

#else /* !HAVE_UV */

typedef struct random_data sap_random_data;
typedef int sap_timer_t;

#endif /* HAVE_UV */

#endif /* __LIBSAP_PLATFORM_TYPES_H__ */
