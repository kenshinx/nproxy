#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>

#include <hiredis.h>

#include "string.h"
#include "array.h"
#import "config.h"
#include "proxy.h"
#include "server.h"

np_status_t 
server_init(struct nproxy_server *server)
{
    server->configfile = NULL;
    server->cfg = NULL;
    
    server->proxy_pool = array_create(NPROXY_PROXY_POOL_LENGTH, sizeof(np_proxy));
    if (server->proxy_pool == NULL) {
        return  NP_ERROR;
    }

    server->pidfile = NULL;
    server->pid = getpid();

    return NP_OK;
}


static np_status_t
server_load_config(struct nproxy_server *server)
{
    
    struct config *cfg;
    cfg = config_creat(server->configfile);
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

static void
_print_proxy(np_proxy *proxy)
{
    log_notice("%s://%s:%d", proxy->proto->data, proxy->host->data, proxy->port);
}

static void 
server_proxy_pool_dump(struct nproxy_server *server)
{
    log_notice("[Nproxy proxy pool]");
    array_foreach(server->proxy_pool, &_print_proxy);
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
    
    server_proxy_pool_dump(server);

    return NP_OK;
}

