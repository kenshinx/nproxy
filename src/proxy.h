#ifndef _NPROXY_PROXY_H_
#define _NPROXY_PROXY_H_

#include "string.h"
#include "util.h"

#ifndef SOCKS5_PROXY_SUPPORT
#define SOCKS5_PROXY_SUPPORT
#endif


typedef struct np_proxy {
    np_string   *host;
    int         port;
    np_string   *proto;
    np_string   *username;
    np_string   *password;
} np_proxy_t;

np_proxy_t *proxy_create(np_string *host, int port, np_string *proto, np_string *username, np_string *password);

void proxy_destroy(np_proxy_t *proxy);

np_proxy_t *proxy_from_json(const char *str);

void proxy_load_pool(np_array *pool, redisContext *c, char *key);

void proxy_pool_dump(np_array *proxy_pool);

#endif
