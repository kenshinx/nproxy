
#include <hiredis.h>

#include "core.h"


redisContext *
redis_connect(const char *host, int port, int timeout)
{
    redisContext *c;

    struct timeval _timeout  = {timeout, 0};
    
    c = redisConnectWithTimeout(host, port, _timeout);
    if (c == NULL || c->err) {
        if (c) {
            log_error("connect redis '%s:%d' failed: %s\n", host, port, c->errstr);
            redisFree(c);
        } else {
            log_error("connect redis error. can't allocate redis context");
        }

        return NULL;
    }

    log_debug("connect redis %s:%d\n",host, port);
    
    return c;
}
