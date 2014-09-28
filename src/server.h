#ifndef _NPROXY_SERVER_H_
#define _NPROXY_SERVER_H_

#include "core.h"
#include "array.h"
#include "string.h"

#define NPROXY_PROXY_POOL_LENGTH 200

struct nproxy_server {
    char            *configfile;
    struct config   *cfg;
    np_array        *proxy_pool;   
    char            *pidfile;
    pid_t           pid;
}; 


np_status_t server_init(struct nproxy_server *server);

np_status_t server_setup(struct nproxy_server *server);

#endif

