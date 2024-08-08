#ifndef __LIBSAP_PLATFORM_PIPE_H__
#define __LIBSAP_PLATFORM_PIPE_H__

#ifdef HAVE_UV
#include <uv.h>

typedef uv_file sap_fd;

static inline int sap_pipe(sap_fd pipefd[2])
{
	return uv_pipe(pipefd, 0, 0);
}

#else /* !HAVE_UV */

#include <unistd.h>

typedef int sap_fd;

static inline int sap_pipe(sap_fd pipefd[2])
{
	return pipe(pipefd);
}

#endif /* HAVE_UV */

#endif /* __LIBSAP_PLATFORM_PIPE_H__ */
