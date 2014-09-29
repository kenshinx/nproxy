#ifndef _NPROXY_SOCKS_H_
#define _NPROXY_SOCKS_H_

#include "string.h"


typedef struct np_proxy {
    np_string   *host;
    int         port;
    np_string   *proto;
    np_string   *username;
    np_string   *password;
} np_proxy;

np_proxy *proxy_create(np_string *host, int port, np_string *proto, np_string *username, np_string *password);

np_proxy *proxy_from_json(const char *str);

void proxy_pool_dump(np_array *proxy_pool);

#endif
