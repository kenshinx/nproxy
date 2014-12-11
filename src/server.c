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
#include "log.h"
#include "proxy.h"
#include "socks5.h"
#include "server.h"

static np_status_t server_context_init(np_context_t *ctx);
static void server_context_deinit(np_context_t *ctx);
static np_status_t server_load_config(struct nproxy_server *server);
static np_status_t server_load_proxy_pool(struct nproxy_server *server);
static np_status_t server_get_remote_addr(uv_stream_t *handler, struct sockaddr *addr);
static char *server_sockaddr_to_str(struct sockaddr_storage *addr);
static char *server_get_remote_ip(uv_stream_t *handler);

static void server_do_next(np_connect_t *conn, const uint8_t *buf, ssize_t nread);
static s5_phase_t server_do_handshake(np_connect_t *conn, const uint8_t *data, ssize_t nread);
static s5_phase_t server_do_handshake_auth(np_connect_t *conn, const uint8_t *data, ssize_t nread);
static s5_phase_t server_do_sub_negotiation(np_connect_t *conn, const uint8_t *data, ssize_t nread);
static s5_phase_t server_do_request(np_connect_t *conn, const uint8_t *data, ssize_t nread);
static s5_phase_t server_do_kill(np_connect_t *conn);

static uv_buf_t *server_on_alloc_cb(uv_handle_t *handler/*handle*/, size_t suggested_size, uv_buf_t* buf); 
static void server_on_close(uv_handle_t *stream);
static void server_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void server_on_write(np_connect_t *conn, const char *data, unsigned int len);
static void server_on_write_done(uv_write_t *req, int status);
static void server_on_connect(uv_stream_t *us, int status);

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
server_context_init(np_context_t *ctx)
{
    np_connect_t *client;
    np_connect_t *upstream;
    s5_session_t *sess;
    
    client = (np_connect_t *)np_malloc(sizeof(*client));
    if (client == NULL) {
        return NP_ERROR;
    }

    sess = (s5_session_t *)np_malloc(sizeof(*sess));
    if (sess == NULL) {
        return NP_ERROR;
    }

    client->sess = sess;
    socks5_init(client->sess);
    ctx->client = client;

    upstream = (s5_session_t *)np_malloc(sizeof(*upstream));

    if (upstream == NULL) {
        return NP_ERROR;
    }

    sess = (s5_session_t *)np_malloc(sizeof(*sess));
    if (sess == NULL) {
        return NP_ERROR;
    }
    upstream->sess = sess;
    socks5_init(upstream->sess);
    ctx->upstream = upstream;
    
    return NP_OK;
}

static void
server_context_deinit(np_context_t *ctx)
{
    np_free(ctx->client->sess);
    np_free(ctx->client);
    np_free(ctx->upstream->sess);
    np_free(ctx->upstream);
    np_free(ctx);
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

    /*
    status = server_load_proxy_pool(server);
    if (status != NP_OK) {
        log_stderr("load proxy pool from redis failed.");
        return status;
    }
    proxy_pool_dump(server->proxy_pool);

    */
    return NP_OK;
}

static uv_buf_t *
server_on_alloc_cb(uv_handle_t *handler/*handle*/, size_t suggested_size, uv_buf_t* buf) 
{
        *buf = uv_buf_init((char*) np_malloc(suggested_size), suggested_size);
        np_assert(buf->base != NULL);
        return buf;
}

static np_status_t
server_get_remote_addr(uv_stream_t *handler, struct sockaddr *addr)
{
    int len;
    int err;

    len = sizeof(*addr);

    err = uv_tcp_getpeername((uv_tcp_t *)handler, addr, &len);
    if (err != 0) {
        log_error("get remote ip failed");
        return NP_ERROR;
    }

    return NP_OK; 
}

static char *
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

static char *
server_get_remote_ip(uv_stream_t *handler)
{
    struct sockaddr *remote_addr;
    char *ip;

    remote_addr = np_malloc(sizeof(*remote_addr));
    server_get_remote_addr(handler, remote_addr);
    if (remote_addr == NULL) {
        return NULL;
    }
    
    ip = server_sockaddr_to_str((struct sockaddr_storage *)remote_addr);
    np_free(remote_addr);
    return ip;
}

static void 
server_do_next(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{   
    int new_phase;

    s5_session_t *sess = conn->sess;

    switch (sess->phase) {
        case SOCKS5_HANDSHAKE:
            new_phase = server_do_handshake(conn, data, nread);
            break;
        case SOCKS5_SUB_NEGOTIATION:
            new_phase = server_do_sub_negotiation(conn, data, nread);
            break;
        case SOCKS5_REQUEST:
            new_phase = server_do_request(conn, data, nread);
            break;
        case SOCKS5_ALMOST_DEAD:
            new_phase = server_do_kill(conn);
            break;
        case SOCKS5_DEAD:
            log_error("socks5 dead");
            return;
    }    
    sess->phase = new_phase;
}


static s5_phase_t
server_do_handshake(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{
    s5_error_t err;

    s5_session_t *sess = conn->sess;

    err = socks5_parse(sess, &data, &nread);
    if (err != SOCKS5_OK) {
        log_error("handshake error: %s", socks5_strerror(err));
        return server_do_kill(conn);
        //return SOCKS5_HANDSHAKE; 
    }

    if (nread != 0) {
        log_error("junk in handshake phase");
        return server_do_kill(conn);
    }
    
    socks5_select_auth(sess);

    switch(sess->method) {
        case SOCKS5_NO_AUTH:
            server_on_write(conn, "\x05\x00", 2);
            return SOCKS5_REQUEST;
        case SOCKS5_AUTH_PASSWORD:
            server_on_write(conn, "\x05\x02", 2);
            return SOCKS5_SUB_NEGOTIATION;
        defaut:
            server_on_write(conn, "\x05\xff", 2);            
            return server_do_kill(conn);
    }

    log_debug("handshake sucess.");
}

static s5_phase_t
server_do_sub_negotiation(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{
    s5_error_t err;

    s5_session_t *sess = conn->sess;

    sess->state = SOCKS5_AUTH_PW_VER; 
    
    err = socks5_parse(sess, &data, &nread);
    if (err != SOCKS5_OK) {
        log_error("sub negotiate error: %s", socks5_strerror(err));
        return server_do_kill(conn);
    }

    if (nread != 0) {
        log_error("junk in sub negotiation phase");
        return server_do_kill(conn);
    }

    log_debug("usename:%s, password:%s", sess->uname, sess->passwd);

    np_context_t *ctx = conn->handle.data;
    struct nproxy_server *server = ctx->server;

    if ((strcmp(server->cfg->server->username->data, sess->uname) == 0) && \
            (strcmp(server->cfg->server->password->data, sess->passwd) == 0)) {
        log_debug("sub negotiation sucess");
        server_on_write(conn, "\x01\x00", 2);
        return SOCKS5_REQUEST;
    } else {
        log_debug("sub negotiation failed");
        server_on_write(conn, "\x01\x01", 2);
        return server_do_kill(conn);
    }

}

static s5_phase_t
server_do_request(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{
    s5_error_t err;

    s5_session_t *sess = conn->sess;

    sess->state = SOCKS5_REQ_VER;

    err = socks5_parse(sess, &data, &nread);
    if (err != SOCKS5_OK) {
        log_error("request  error: %s", socks5_strerror(err));
        return server_do_kill(conn);
    }

    if (nread != 0 ){
        log_error("junk in request phase");
        return server_do_kill(conn);
    }

    if (sess->cmd == SOCKS5_CMD_BIND) {
        log_warn("bind request not supported");
        return server_do_kill(conn);
    }
    
    if (sess->cmd == SOCKS5_CMD_UDP_ASSOCIATE) {
        log_warn("udp associate request not supported");
        return server_do_kill(conn);
    }
    
    if (sess->atyp == SOCKS5_ATYP_IPV4) {
        
        log_debug("daddr:%s, dport:%d", sess->daddr, sess->dport);
    }


    log_debug("request sucess");
    return SOCKS5_REPLY;
}


static s5_phase_t
server_do_kill(np_connect_t *conn)
{
    uv_close((uv_handle_t* )&conn->handle, (uv_close_cb) server_on_close);
    uv_close((uv_handle_t*)&conn->timer, (uv_close_cb) server_on_close);
    log_debug("do kill");
    return SOCKS5_DEAD;
}

static void
server_on_close(uv_handle_t *stream)
{
    /* todo 
    np_context_t *ctx = (np_context_t *)sess->handle->data;
    server_context_deinit(ctx);
    */
    return;
}

static void
server_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    np_context_t *ctx = stream->data;
    np_connect_t *client = ctx->client;
    np_assert((uv_stream_t *)&client->handle == stream);

    if (nread < 0) {
        if (nread != UV_EOF) {
            UV_SHOW_ERROR(nread, "read error");
        }
        server_do_kill(client);
        return;
    } else {
        server_do_next(client, (uint8_t *)buf->base, nread);
    }
    np_free(buf->base);
}

static void 
server_on_write(np_connect_t *conn, const char *data, unsigned int len)
{

    uv_buf_t buf;
    int r;

    buf.base = data;
    buf.len = len;

    r = uv_write(&conn->write_req, (uv_stream_t *)&conn->handle, &buf, 1 , server_on_write_done);

    int i;

    for (i=0; i<len; i++) {
        log_debug("write: %02X", data[i]);
    }


    if (r < 0) {
        UV_SHOW_ERROR(r, "write error");
    }
    
    //server_timer_reset(np_connect_t *conn);
    
}


static void
server_on_write_done(uv_write_t *req, int status)
{
    return;
}

static void
server_on_connect(uv_stream_t *us, int status)
{
    int err;
    np_status_t st;
    np_context_t *ctx;
    np_connect_t *client;
    char *client_ip;
    struct nproxy_server *server;
    
    if (status != 0) {
        UV_SHOW_ERROR(status, "libuv on connect");
        return;
    }

    server = (struct nproxy_server *)us->data;

    ctx = (np_context_t *)np_malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return ;
    }

    ctx->server = server;

    st = server_context_init(ctx);
    if (st != NP_OK) {
        return ;
    }

    client = ctx->client;

    uv_tcp_init(us->loop, &ctx->client->handle);
    uv_timer_init(us->loop, &ctx->client->timer);
    
    err = uv_accept((uv_stream_t *)us, (uv_stream_t *)&client->handle);
    if (err) {
        UV_SHOW_ERROR(err, "libuv on accept");
        return;
    }
    
    err = server_get_remote_addr((uv_stream_t *)&client->handle, &client->srcaddr.addr);
    if (err) {
        UV_SHOW_ERROR(err, "libuv on get remote addr");
        return;
    }

    
    client->handle.data = ctx;

    err = uv_read_start((uv_stream_t *)&client->handle, (uv_alloc_cb)server_on_alloc_cb, (uv_read_cb)server_on_read);
    if (err) {
        UV_SHOW_ERROR(err, "libuv read start");
    }
    
    client_ip = server_sockaddr_to_str((struct sockaddr_storage *)&client->srcaddr.addr);

    log_debug("Aceepted connect from %s", client_ip);

    np_free(client_ip);
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

    us->data = server;
    
    err = uv_listen((uv_stream_t *)us, MAX_CONNECT_QUEUE, server_on_connect);
    UV_CHECK(err, "libuv listen");

    uv_run(loop, UV_RUN_DEFAULT);
    
}
