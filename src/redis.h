#ifndef _NPROXY_REDIS_H
#define _NPROXY_REDIS_H

#include <hiredis.h>

redisContext *redis_connect(const char *host, int port, int timeout);


#endif
