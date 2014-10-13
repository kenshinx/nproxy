#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <uv.h>
#include <hiredis.h>

#include "string.h"
#include "array.h"
#include "config.h"
#include "proxy.h"
#include "log.h"
#include "server.h"

np_status_t 
server_init(struct nproxy_server *server)
{
    server->us = NULL;
    server->loop = NULL;

    server->configfile = NULL;
    server->cfg = NULL;
    
    server->proxy_pool = array_create(NPROXY_PROXY_POOL_LENGTH, sizeof(np_proxy));
    if (server->proxy_pool == NULL) {
        return  NP_ERROR;
    }

    server->pidfile = NULL;
    server->pid = getpid();
    
    server->debug = false;

    return NP_OK;
}

static np_status_t
server_load_config(struct nproxy_server *server)
{
    
    struct config *cfg;
    cfg = config_create(server->configfile);
    if (cfg == NULL) {
        return NP_ERROR;
    }
    server->cfg = cfg;
    log_info("load config '%s' sucess", server->configfile);

    return NP_OK;
}

redisContext *
server_redis_connect(struct nproxy_server *server)
{
    redisContext *c;

    struct timeval timeout  = {server->cfg->redis->timeout, 0};
    
    c = redisConnectWithTimeout(server->cfg->redis->server->data, server->cfg->redis->port, timeout);
    if (c == NULL || c->err) {
        if (c) {
            log_error("connect redis '%s:%d' failed: %s\n", 
                    server->cfg->redis->server->data, server->cfg->redis->port, c->errstr);
            redisFree(c);
        } else {
            log_error("connect redis error. can't allocate redis context");
        }

        return NULL;
    }

    log_debug("connect redis %s:%d\n", server->cfg->redis->server->data, server->cfg->redis->port);
    
    return c;
}

static np_status_t
server_load_proxy_pool(struct nproxy_server *server)
{
    redisContext    *c;
    redisReply      *reply;
    np_proxy        *proxy;
    unsigned int i;
    
    c = server_redis_connect(server);
    if (c == NULL) {
        return NP_ERROR;
    }

    reply = redisCommand(c, "SMEMBERS %s", server->cfg->server->redis_key->data);

    if (reply->type == REDIS_REPLY_ARRAY) {
        for (i = 0; i < reply->elements; i++) {
            proxy = proxy_from_json(reply->element[i]->str);
            if (proxy != NULL) {
                array_push(server->proxy_pool, proxy);
            }
        }
    }

    freeReplyObject(reply);

    return NP_OK;
}

np_status_t
server_setup(struct nproxy_server *server)
{
    np_status_t status;

    status = server_load_config(server);
    if (status != NP_OK) {
        log_stderr("load config '%s' failed", server->configfile);
        return status;
    }    
    
    config_dump(server->cfg);

    status = server_load_proxy_pool(server);
    if (status != NP_OK) {
        log_stderr("load proxy pool from redis failed.");
        return status;
    }
    
    proxy_pool_dump(server->proxy_pool);

    return NP_OK;
}

static uv_buf_t *
server_handshake_alloc_cb(uv_handle_t *handler/*handle*/, size_t suggested_size, uv_buf_t* buf) {
        *buf = uv_buf_init((char*) malloc(suggested_size), suggested_size);
        return buf;
}

struct sockaddr *
server_get_remote_addr(uv_stream_t *handler)
{
    struct sockaddr *remote_addr;
    int namelen;
    int err;

    remote_addr = np_malloc(sizeof(*remote_addr));
    if (remote_addr == NULL) {
        return NULL;
    }    
    
    namelen = sizeof(*remote_addr);
    printf("handler->type: %d\n", handler->type);
    err = uv_tcp_getpeername((uv_tcp_t *)handler, remote_addr, &namelen);
    if (err != 0) {
        log_error("get remote ip failed");
        return NULL;
    }

    return remote_addr; 
}

char *
server_sockaddr_to_str(struct sockaddr_storage *addr)
{
    char *ip;
    int err;
    
    if (addr->ss_family == AF_INET) {
        ip = np_malloc(INET_ADDRSTRLEN);
        if (ip == NULL) {
            return NULL;
        }
        
        err = uv_ip4_name((struct sockaddr_in *)addr, ip, INET_ADDRSTRLEN);
        if (err) {
            np_free(ip);
            return NULL;
        }
        
    } else if (addr->ss_family == AF_INET6) {
        ip = np_malloc(INET6_ADDRSTRLEN);
        if (ip == NULL) {
            return NULL;
        }

        err = uv_ip6_name((struct sockaddr_in6 *)addr, ip, INET6_ADDRSTRLEN); 
        if (err) {
            np_free(ip);
            return NULL;
        }
    }

    return ip;
}

char *
server_get_remote_ip(uv_stream_t *handler)
{
    struct sockaddr *remote_addr;
    char *ip;
    remote_addr = server_get_remote_addr(handler);
    if (remote_addr == NULL) {
        return NULL;
    }
    
    ip = server_sockaddr_to_str((struct sockaddr_storage *)remote_addr);
    np_free(remote_addr);
    return ip;
}

static void
server_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    log_stdout("read: %s", buf->base);
}


static void
server_on_connect(uv_stream_t *us, int status)
{
    int err;
    char *remote_ip;
    
    UV_CHECK(status, "libuv on connect");

    uv_tcp_t *uc = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(us->loop, uc);
    
    err = uv_accept((uv_stream_t *)us, (uv_stream_t *)uc);
    UV_CHECK(err, "libuv accept");

    err = uv_read_start((uv_stream_t *)uc, (uv_alloc_cb)server_handshake_alloc_cb, (uv_read_cb)server_on_read);
    UV_CHECK(err, "libuv read_start");
    
    REMOTE_IP(uc, remote_ip);
    log_debug("Aceepted connect from %s", remote_ip);
    np_free(remote_ip);
}

void
server_run(struct nproxy_server *server)
{
    uv_tcp_t *us;
    uv_loop_t *loop;
    struct sockaddr_in addr;
    int err;

    us = (uv_tcp_t *)np_malloc(sizeof(*us));
    if (us == NULL) {
        return;
    }

    loop = uv_default_loop();

    uv_tcp_init(loop, us);
    
    uv_ip4_addr(server->cfg->server->listen->data, server->cfg->server->port, &addr);
    err = uv_tcp_bind(us, (struct sockaddr *)&addr, 0);
    UV_CHECK(err, "libuv tcp bind");
    
    server->us = us;
    server->loop = loop;
    
    err = uv_listen(us, MAX_CONNECT_QUEUE, server_on_connect);
    UV_CHECK(err, "libuv listen");

    uv_run(loop, UV_RUN_DEFAULT);
    
}
