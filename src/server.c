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
#include "util.h"
#include "proxy.h"
#include "socks5.h"
#include "redis.h"
#include "server.h"

static np_status_t server_connect_init(np_connect_t *conn);
static void server_connect_deinit(np_connect_t *conn);
static np_status_t server_context_init(np_context_t *ctx);
static void server_context_deinit(np_context_t *ctx);
static np_status_t server_load_config();
static np_status_t server_load_proxy_pool();
static np_status_t server_get_peeraddr(uv_stream_t *handle, struct sockaddr *addr);
static np_status_t server_get_sockaddr(uv_stream_t *handle, struct sockaddr *addr);
static np_status_t server_sockaddr_to_str(struct sockaddr_storage *addr, char *ip);
static void server_do_parse(np_connect_t *conn, const uint8_t *buf, ssize_t nread);
static void server_do_callback(np_connect_t *conn);
static np_phase_t server_do_handshake_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread);
static np_phase_t server_do_handshake_reply(np_connect_t *conn);
static np_phase_t server_do_sub_negotiate_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread);
static np_phase_t server_do_sub_negotiate_reply(np_connect_t *conn);
static np_phase_t server_do_request_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread);
static np_phase_t server_do_request_lookup(np_connect_t *conn);
//static np_phase_t server_do_request_verify(np_connect_t *conn);
static np_phase_t server_upstream_do_connect(np_connect_t *conn);
static np_phase_t server_upstream_do_handshake(np_connect_t *conn);
static np_phase_t server_upstream_do_handshake_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread);
static np_phase_t server_upstream_do_sub_negotiate(np_connect_t *conn);
static np_phase_t server_upstream_do_sub_negotiate_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread);
static np_phase_t server_upstream_do_request(np_connect_t *conn);
static np_phase_t server_upstream_do_reply_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread);
static np_phase_t server_do_reply(np_connect_t *conn);
static np_phase_t server_do_proxy(np_connect_t *conn, const uint8_t *data, ssize_t nread);
static np_phase_t server_do_cycle(np_connect_t *in, np_connect_t *out, const uint8_t *data, ssize_t nread);
static void server_do_kill(np_context_t *ctx);
static void server_conn_close(np_connect_t *conn);
static void server_on_close(uv_handle_t *handle);
static void server_on_read_done(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static uv_buf_t *server_on_alloc_cb(uv_handle_t *handle /*handle*/, size_t suggested_size, uv_buf_t* buf); 
static void server_write(np_connect_t *conn, const char *data, unsigned int len);
static void server_on_write_done(uv_write_t *req, int status);
static void server_get_addrinfo(np_connect_t *conn, const char *hostname); 
static void server_on_get_addrinfo_done(uv_getaddrinfo_t *req, int status, struct addrinfo *ai);
static int  server_connect(np_connect_t *conn);
static void server_on_connect_done(uv_connect_t* req, int status);
static void server_on_new_connect(uv_stream_t *us, int status);

np_status_t 
server_init()
{
    server.us = NULL;
    server.loop = NULL;

    server.configfile = NULL;
    server.cfg = NULL;
    
    server.proxy_pool = array_create(NPROXY_PROXY_POOL_LENGTH, sizeof(np_proxy_t));
    if (server.proxy_pool == NULL) {
        return  NP_ERROR;
    }

    server.pidfile = NULL;
    server.pid = getpid();
    
    server.debug = false;

    return NP_OK;
}

void 
server_deinit()
{
    config_destroy(server.cfg);
    array_destroy(server.proxy_pool);
}

static np_status_t 
server_connect_init(np_connect_t *conn) 
{
    s5_session_t *sess;

    sess = (s5_session_t *)np_malloc(sizeof(*sess));
    if (sess == NULL) {
        return NP_ERROR;
    }
    conn->sess = sess;

    conn->phase = SOCKS5_INIT;

    conn->last_status = 0;

    conn->rstat = np_stop;

    conn->wstat = np_stop;

    return NP_OK;

}

static void
server_connect_deinit(np_connect_t *conn)
{
    np_free(conn->sess);
    np_free(conn);
}


static np_status_t
server_context_init(np_context_t *ctx)
{
    np_connect_t *client;
    np_connect_t *upstream;
    np_status_t status;
    
    client = (np_connect_t *)np_malloc(sizeof(*client));
    if (client == NULL) {
        return NP_ERROR;
    }
    status = server_connect_init(client);
    if (status != NP_OK) {
        return NP_ERROR;
    }
    ctx->client = client;
    client->ctx = ctx;

    upstream = (np_connect_t *)np_malloc(sizeof(*upstream));
    if (upstream == NULL) {
        return NP_ERROR;
    }
    status = server_connect_init(upstream);
    if (status != NP_OK) {
        return NP_ERROR;
    }
    ctx->upstream = upstream;
    upstream->ctx = ctx;
    
    return NP_OK;
}

static void
server_context_deinit(np_context_t *ctx)
{
    np_free(ctx);
}

static np_status_t
server_load_config()
{
    
    struct config *cfg;
    cfg = config_create(server.configfile);
    if (cfg == NULL) {
        return NP_ERROR;
    }
    server.cfg = cfg;
    log_info("load config '%s' sucess", server.configfile);
    return NP_OK;
}


static np_status_t
server_load_proxy_pool()
{
    redisContext *c;

    c = redis_connect(server.cfg->redis->server->data, 
                      server.cfg->redis->port,
                      server.cfg->redis->timeout);
    if (c == NULL) {
        return NP_ERROR;
    }
    
    proxy_load_pool(server.proxy_pool, c, server.cfg->server->redis_key->data);

    redisFree(c);

    return NP_OK;
}

static np_proxy_t *
server_get_proxy()
{
    /* return random np_proxy_t from proxy_pool */
    int i;
    np_proxy_t *proxy;
    
    i = np_random(server.proxy_pool->nelts);
    proxy = array_get(server.proxy_pool, i);

    return proxy;
}

static uv_buf_t *
server_on_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t* buf) 
{
    *buf = uv_buf_init((char*) np_malloc(suggested_size), suggested_size);
    np_assert(buf->base != NULL);
    return buf;
}

static np_status_t
server_get_peeraddr(uv_stream_t *handle, struct sockaddr *addr)
{
    int len;
    int err;

    len = sizeof(*addr);
    err = uv_tcp_getpeername((uv_tcp_t *)handle, addr, &len);
    if (err != 0) {
        log_error("get peer ip failed");
        return NP_ERROR;
    }

    return NP_OK; 
}

static np_status_t
server_get_sockaddr(uv_stream_t *handle, struct sockaddr *addr)
{
    int err;
    int len;

    len = sizeof(*addr);
    err = uv_tcp_getsockname((uv_tcp_t *)handle, addr, &len);
    if (err != 0 ) {
        log_error("get sock ip failed");
        return NP_ERROR;
    }
    return NP_OK;
}

static np_status_t
server_sockaddr_to_str(struct sockaddr_storage *addr, char *ip)
{
    int err;
    
    if (addr->ss_family == AF_INET) {
        err = uv_ip4_name((struct sockaddr_in *)addr, ip, INET_ADDRSTRLEN);
        if (err) {
            np_free(ip);
            return NP_ERROR;
        }
        
    } else if (addr->ss_family == AF_INET6) {
        err = uv_ip6_name((struct sockaddr_in6 *)addr, ip, INET6_ADDRSTRLEN); 
        if (err) {
            np_free(ip);
            return NP_ERROR;
        }
    }

    return NP_OK;
}

/*
static char *
server_get_remote_ip(uv_stream_t *handle)
{
    struct sockaddr *remote_addr;
    char *ip;

    remote_addr = np_malloc(sizeof(*remote_addr));
    server_get_peeraddr(handle, remote_addr);
    if (remote_addr == NULL) {
        return NULL;
    }
    
    ip = server_sockaddr_to_str((struct sockaddr_storage *)remote_addr);
    np_free(remote_addr);
    return ip;
}
*/

static void 
server_do_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{   
    int new_phase;

    switch (conn->phase) {
        case SOCKS5_HANDSHAKE:
            new_phase = server_do_handshake_parse(conn, data, nread);
            break;
        case SOCKS5_SUB_NEGOTIATION:
            new_phase = server_do_sub_negotiate_parse(conn, data, nread);
            break;
        case SOCKS5_REQUEST:
            new_phase = server_do_request_parse(conn, data, nread);
            break;
        case SOCKS5_UPSTREAM_HANDSHAKE:
            new_phase = server_upstream_do_handshake_parse(conn, data, nread);
            break;
        case SOCKS5_UPSTREAM_SUB_NEGOTIATION:
            new_phase = server_upstream_do_sub_negotiate_parse(conn, data, nread);
            break;
        case SOCKS5_UPSTREAM_REPLY:
            new_phase = server_upstream_do_reply_parse(conn, data, nread);
            break;
        case SOCKS5_PROXY:
            new_phase = server_do_proxy(conn, data, nread);
            break;
        case SOCKS5_ALMOST_DEAD:
            server_do_kill(conn->ctx);
            return;
        case SOCKS5_DEAD:
            log_error("socks5 has dead");
            return;
        default :
            return;
    }    
    conn->phase = new_phase;
}

static void 
server_do_callback(np_connect_t *conn)
{   
    int new_phase;

    //log_error("callback called: %d", conn->phase);

    switch (conn->phase) {
        case SOCKS5_WAIT_LOOKUP:
            new_phase = server_do_request_lookup(conn);
            break;
        /*
        case SOCKS5_WAIT_CONN:
            new_phase = server_do_reply(conn);
            break;
        */
        case SOCKS5_WAIT_UPSTREAM_CONN:
            new_phase = server_upstream_do_handshake(conn);
            break;
        case SOCKS5_ALMOST_DEAD:
            server_do_kill(conn->ctx);
            return;
        case SOCKS5_DEAD:
            log_error("socks5 has dead");
            return;
        default:
            return;
    }    

    conn->phase = new_phase;
}

static np_phase_t
server_do_handshake_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{
    s5_error_t err;

    s5_session_t *sess = conn->sess;
    sess->state = SOCKS5_VERSION;

    err = socks5_parse(sess, &data, &nread);
    if (err != SOCKS5_OK) {
        log_error("handshake error: %s", socks5_strerror(err));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    if (nread != 0) {
        log_error("junk in handshake phase");
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    return server_do_handshake_reply(conn);
}
    
static np_phase_t
server_do_handshake_reply(np_connect_t *conn)
{
    np_phase_t new_phase;

    socks5_select_auth(conn->sess);

    switch(conn->sess->method) {
#ifndef ENABLE_SOCKS5_SERVER_AUTH 
        case SOCKS5_NO_AUTH:
            server_write(conn, "\x05\x00", 2);
            new_phase = SOCKS5_REQUEST;
            break;
        case SOCKS5_AUTH_PASSWORD:
            server_write(conn, "\x05\x02", 2);
            new_phase = SOCKS5_SUB_NEGOTIATION;
            break;
#else
        case SOCKS5_NO_AUTH:
            server_write(conn, "\x05\x02", 2);
            new_phase = SOCKS5_SUB_NEGOTIATION;
            break;
        case SOCKS5_AUTH_PASSWORD:
            server_write(conn, "\x05\x00", 2);
            new_phase = SOCKS5_REQUEST;
            break;
#endif
        case SOCKS5_AUTH_GSSAPI:
        case SOCKS5_AUTH_REFUSED:
            server_write(conn, "\x05\xff", 2);            
            new_phase = SOCKS5_ALMOST_DEAD;
            break;
    }

    log_debug("handshake sucesss");
    
    return new_phase;
    
}

static np_phase_t
server_do_sub_negotiate_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{
    s5_error_t err;

    s5_session_t *sess = conn->sess;

    sess->state = SOCKS5_AUTH_PW_VER; 

    if (conn->last_status != 0 ) {
        log_error("last phase error: %s", socks5_strerror(conn->last_status));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }
  
    err = socks5_parse(sess, &data, &nread);
    if (err != SOCKS5_OK) {
        log_error("sub negotiate error: %s", socks5_strerror(err));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    if (nread != 0) {
        log_error("junk in sub negotiation phase");
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    log_debug("sub negotiate usename:%s, password:%s", sess->uname, sess->passwd);

    return server_do_sub_negotiate_reply(conn);

}

static np_phase_t
server_do_sub_negotiate_reply(np_connect_t *conn)
{
    s5_session_t *sess = conn->sess;

    if ((strcmp(server.cfg->server->username->data, (char *)&sess->uname) == 0) && \
            (strcmp(server.cfg->server->password->data, (char *)&sess->passwd) == 0)) {
        log_debug("sub negotiation sucess");
        server_write(conn, "\x01\x00", 2);
        return SOCKS5_REQUEST;
    } else {
        log_debug("sub negotiation failed");
        server_write(conn, "\x01\x01", 2);
        return SOCKS5_ALMOST_DEAD;
    }
}

static np_phase_t
server_do_request_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{
    s5_error_t err;

    s5_session_t *sess = conn->sess;

    sess->state = SOCKS5_REQ_VER;

    if (conn->last_status != 0 ) {
        log_error("last phase error: %s", socks5_strerror(conn->last_status));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    err = socks5_parse(sess, &data, &nread);
    if (err != SOCKS5_OK) {
        log_error("request parse error: %s", socks5_strerror(err));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    if (nread != 0 ) {
        log_error("junk in request phase");
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    if (sess->atyp == SOCKS5_ATYP_DOMAIN) {
        server_get_addrinfo(conn, (const char *)sess->daddr);
        return SOCKS5_WAIT_LOOKUP;
    }
    
    if (sess->atyp == SOCKS5_ATYP_IPV4) {
        struct sockaddr_in *addr = &conn->remoteaddr.addr4;
        bzero(addr, sizeof(*addr)); 
        addr->sin_family = AF_INET;
        addr->sin_port = htons(sess->dport);
        memcpy(&addr->sin_addr, sess->daddr, sizeof(addr->sin_addr));
        
    } else if (sess->atyp == SOCKS5_ATYP_IPV6) {
        struct sockaddr_in6 *addr = &conn->remoteaddr.addr6;
        bzero(addr, sizeof(*addr)); 
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(sess->dport);
        memcpy(&addr->sin6_addr, sess->daddr, sizeof(addr->sin6_addr));
    }

    server_sockaddr_to_str((struct sockaddr_storage *)&conn->remoteaddr, (char *)&conn->remoteip);

    log_debug("request parse sucess");

    return server_upstream_do_connect(conn);
}

static np_phase_t
server_do_request_lookup(np_connect_t *conn)
{

    if (conn->last_status != 0 ) {
        log_error("LOOKUP for %s error: %s", conn->sess->daddr, socks5_strerror(conn->last_status));
        server_write(conn, "\5\4\0\1\0\0\0\0\0\0", 10);
        return SOCKS5_ALMOST_DEAD;
    } else {
        /* Assume the dns lookup always return ipv4 address */
        conn->remoteaddr.addr4.sin_port = htons(conn->sess->dport);
        server_sockaddr_to_str((struct sockaddr_storage *)&conn->remoteaddr, (char *)&conn->remoteip);
        log_info("LOOKUP %s -> %s", conn->sess->daddr, conn->remoteip);
        return server_upstream_do_connect(conn);
    }
    
}

/*
static np_phase_t
server_do_request_verify(np_connect_t *conn) 
{
    int r;

    s5_session_t *sess = conn->sess;

    if (sess->cmd == SOCKS5_CMD_BIND) {
        log_warn("bind request not supported");
        server_write(conn, "\5\7\0\1\0\0\0\0\0\0", 10);
        return SOCKS5_ALMOST_DEAD;
    }
    
    if (sess->cmd == SOCKS5_CMD_UDP_ASSOCIATE) {
        log_warn("udp associate request not supported");
        server_write(conn, "\5\7\0\1\0\0\0\0\0\0", 10);
        return SOCKS5_ALMOST_DEAD;
    }

    r = server_connect(conn);

    if (r<0) {
        UV_SHOW_ERROR(r, "connect error");
        server_do_kill(conn);
        return SOCKS5_DEAD;
    }

    return SOCKS5_WAIT_CONN;
}
*/

static np_phase_t
server_upstream_do_connect(np_connect_t *conn)
{
    int err;

    np_proxy_t *proxy;
    np_context_t *ctx;
    np_connect_t *client;
    np_connect_t *upstream;
    s5_session_t *sess;

    proxy = server_get_proxy();

    client = conn;
    ctx = conn->ctx;
    upstream = ctx->upstream;

    np_memcpy(&upstream->remoteaddr, &client->remoteaddr, sizeof(client->remoteaddr));
    server_sockaddr_to_str((struct sockaddr_storage *)&upstream->remoteaddr, (char *)&upstream->remoteip);

    uv_ip4_addr(proxy->host->data, proxy->port, &upstream->dstaddr.addr4);
    server_sockaddr_to_str((struct sockaddr_storage *)&upstream->dstaddr, (char *)&upstream->dstip);
    

    uv_tcp_init(server.loop, &upstream->handle);
    uv_timer_init(server.loop, &upstream->timer);

    upstream->phase = SOCKS5_WAIT_UPSTREAM_CONN;
    upstream->handle.data = upstream;

    sess = upstream->sess;   
    /* uint32_t -> uint8_t */
    sess->ulen = (uint8_t)proxy->username->len;
    if (sess->ulen) {
        np_memcpy(&sess->uname, proxy->username->data, sess->ulen+1);    
    }
    sess->plen = (uint8_t)proxy->password->len;
    if (sess->plen) {
        np_memcpy(&sess->passwd, proxy->password->data, sess->plen+1);
    }
    
    log_info("CONNECT START (%s:%d -> %s:%d -> %s:%d)", client->srcip, 
                                        ntohs(client->srcaddr.addr4.sin_port), 
                                        upstream->dstip,
                                        ntohs(upstream->dstaddr.addr4.sin_port),
                                        upstream->remoteip,
                                        ntohs(upstream->remoteaddr.addr4.sin_port));
    server_connect(upstream);

    err = uv_read_start((uv_stream_t *)&upstream->handle, (uv_alloc_cb)server_on_alloc_cb, (uv_read_cb)server_on_read_done);
    if (err) {
        UV_SHOW_ERROR(err, "libuv upstream read error");
    }

    /*client handshake ready. wait upstream handshake finished*/
    return SOCKS5_WAIT_PROXY;
}

static np_phase_t 
server_upstream_do_handshake(np_connect_t *conn)
{

    server_sockaddr_to_str((struct sockaddr_storage *)&conn->dstaddr,(char *)&conn->dstip);

    if (conn->last_status != 0 ) {
        log_error("connect upstream '%s' error: %s", 
                conn->dstip, socks5_strerror(conn->last_status));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    log_debug("connect sucess with upstream (%s)", conn->dstip);

    /* set upstream->srcaddr */
    server_get_sockaddr((uv_stream_t *)&conn->handle, &conn->srcaddr.addr);
    server_sockaddr_to_str((struct sockaddr_storage *)&conn->srcaddr, (char *)&conn->srcip);

    log_debug("upstream (%s) beigin handshake", conn->dstip);

#ifdef ENABLE_SOCKS5_CLIENT_AUTH
     /* V5\Auth_Field_Len:2\No_Auth\Uname_Passwd */
    server_write(conn, "\5\2\0\2", 4);
#else
     /* V5\Auth_Field_Len:1\No_Auth */
    server_write(conn, "\5\1\0", 3);
#endif

    return SOCKS5_UPSTREAM_HANDSHAKE;
}


static np_phase_t
server_upstream_do_handshake_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{
    int err;
    
    s5_session_t *sess = conn->sess;
    
    sess->state = SOCKS5_CLIENT_VERSION;

    if (conn->last_status != 0) {
        log_error("upstream do handshake phase error: %s", 
                 socks5_strerror(conn->last_status));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    err = socks5_parse(sess, &data, &nread);
    if (err != SOCKS5_OK) {
        log_error("upstream parse error: %s", socks5_strerror(err));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    if (nread != 0) {
        log_error("junk in upstream handshake phase");
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    log_debug("upstream (%s) handshake sucess", conn->dstip);

    if (sess->method == SOCKS5_NO_AUTH) {
        return server_upstream_do_request(conn);       
    } else if (sess->method == SOCKS5_AUTH_PASSWORD) {
        return server_upstream_do_sub_negotiate(conn);
    } else {
        log_error("unsupport auth method.");
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }
}

static np_phase_t
server_upstream_do_sub_negotiate(np_connect_t *conn)
{
    char buf[256];
    s5_session_t *sess;

    sess = conn->sess;
    
    buf[0] = SOCKS5_AUTH_PW_VERSION; 
    buf[1] = sess->ulen;
    np_memcpy(buf+2, sess->uname, sess->ulen);
    buf[2+sess->ulen] = sess->plen;
    np_memcpy(buf+3+sess->ulen, sess->passwd, sess->plen); 
    
    log_debug("upstream (%s) begin do sub negotiate", conn->dstip);
    
    server_write(conn, buf, 3+sess->ulen+sess->plen);
    
    return SOCKS5_UPSTREAM_SUB_NEGOTIATION;
}

static np_phase_t
server_upstream_do_sub_negotiate_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{
    int err;

    s5_session_t *sess = conn->sess;

    sess->state = SOCKS5_CLIENT_AUTH_VERSION;
    
    if (conn->last_status != 0) {
        log_error("upstream (%s) send sub-nego mesg  error: %s", 
                 conn->dstip, socks5_strerror(conn->last_status));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    err = socks5_parse(sess, &data, &nread);
    if (err != SOCKS5_OK) {
        log_error("upstream (%s) sub negotiate error: %s", conn->dstip, socks5_strerror(err));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    if (nread != 0) {
        log_error("junk in upstream handshake phase");
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    log_debug("upstream (%s) sub negotiation sucess", conn->dstip);

    return server_upstream_do_request(conn);
}

static np_phase_t
server_upstream_do_request(np_connect_t *conn)
{
    char buf[256];
    const struct sockaddr_storage *remote;
    
    log_debug("upstream (%s) begin do request", conn->dstip);

    remote  = (struct sockaddr_storage *)&conn->remoteaddr;
    
    buf[0] = SOCKS5_SUPPORT_VERSION ;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0;  /* Reserved */
    
    if (remote->ss_family == AF_INET) {
        buf[3] = 1; /* ipv4 */ 
        np_memcpy(buf+4, &conn->remoteaddr.addr4.sin_addr, 4);
        np_memcpy(buf+8, &conn->remoteaddr.addr4.sin_port, 2);
        server_write(conn, buf, 10);
    } else if (remote->ss_family == AF_INET6) {
        buf[3] = 4; /* ipv6 */
        np_memcpy(buf+4, &conn->remoteaddr.addr6.sin6_addr, 16);
        np_memcpy(buf+20, &conn->remoteaddr.addr6.sin6_port, 2);
        server_write(conn, buf, 22);
    } else {
        NOT_REACHED();
    }
    log_debug("upstream (%s) send request sucess", conn->dstip);
    return SOCKS5_UPSTREAM_REPLY;
}


static np_phase_t
server_upstream_do_reply_parse(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{
    int err;

    s5_session_t *sess = conn->sess;

    sess->state = SOCKS5_CLIENT_REP_VERSION;
    
    if (conn->last_status != 0) {
        log_error("upstream (%s) send request mesg  error: %s", 
                 conn->dstip, socks5_strerror(conn->last_status));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    err = socks5_parse(sess, &data, &nread);
    if (err != SOCKS5_OK) {
        log_error("upstream (%s) reply phase error: %s", 
                 conn->dstip, socks5_strerror(err));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    if (nread != 0) {
        log_error("junk in upstream handshake phase");
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }

    log_debug("upstream (%s) parse reply sucess", conn->dstip);

    return server_do_reply(conn);
}

static np_phase_t
server_do_reply(np_connect_t *conn)
{
    char buf[256];
    uint8_t addr_len;

    np_context_t *ctx = conn->ctx;
    np_connect_t *client = ctx->client;
    np_connect_t *upstream = conn;

    addr_len = upstream->sess->alen;

    buf[0] = SOCKS5_SUPPORT_VERSION;
    buf[1] = upstream->sess->rep;
    buf[2] = 0;
    buf[3] = upstream->sess->atyp;
    np_memcpy(buf+4, &upstream->sess->baddr, addr_len);
    np_memcpy(buf+4+addr_len, &upstream->sess->bport, 2);
    

    if (upstream->sess->rep != SOCKS5_REP_SUCESS) {
        /* upstream connect remote failed */
        log_error("upstream connect remote (%s) failed. error id: %d", 
                upstream->remoteip, upstream->sess->rep);
        client->phase = SOCKS5_ALMOST_DEAD;
        server_write(client, buf, 6+addr_len);
        return SOCKS5_DEAD;
    }

    /* 
     * send reply mesg to client
     * mesg conetent associated with the result of upstream reply  
     */
    server_write(client, buf, 6+addr_len);

    log_debug("nproxy handshake sucess. begin into proxy phase");

    client->phase = SOCKS5_PROXY;
    upstream->phase = SOCKS5_PROXY;
    
    return SOCKS5_PROXY;
}

static np_phase_t
server_do_proxy(np_connect_t *conn, const uint8_t *data, ssize_t nread)
{
    if (conn->last_status != 0) {
        log_error("last write error: %s", 
                 socks5_strerror(conn->last_status));
        server_do_kill(conn->ctx);
        return SOCKS5_DEAD;
    }
    
    np_context_t *ctx = conn->ctx;
    np_connect_t *client = ctx->client;
    np_connect_t *upstream = ctx->upstream;

    np_assert(client->phase == SOCKS5_PROXY);
    np_assert(upstream->phase == SOCKS5_PROXY);
    /*
    np_assert(client->sess->state == SOCKS5_REQ_DPORT1);
    np_assert(upstream->sess->state == SOCKS5_CLIENT_REP_BPORT1);
    */


    
    if (conn == client) {
        return server_do_cycle(client, upstream, data, nread);
    } else {
        return server_do_cycle(upstream, client, data, nread);
    }
}

static np_phase_t
server_do_cycle(np_connect_t *in, np_connect_t *out, const uint8_t *data, ssize_t nread)
{
    log_debug("write: %zd bytes", nread);

    if (nread ==  UV_EOF) {
        log_info("REQUEST (%s) FINISHED", out->remoteip);
        server_do_kill(in->ctx);
        return SOCKS5_DEAD;
    } else {
        server_write(out, (const char *)data, nread);   
        return SOCKS5_PROXY;
    }
    
}

static void
server_do_kill(np_context_t *ctx)
{
    server_conn_close(ctx->client);
    server_conn_close(ctx->upstream);
    
    if (ctx->client->phase == SOCKS5_DEAD && ctx->upstream->phase == SOCKS5_DEAD) {
        server_context_deinit(ctx);
    }

}

static void
server_conn_close(np_connect_t *conn)
{

    if (conn->wstat == np_busy) {
        /* Wait wirte handle be done then close the connect*/
        conn->phase = SOCKS5_ALMOST_DEAD;
        return;
    }
    
    /* Return immediately if connectted has been closed*/
    if (conn->phase == SOCKS5_DEAD) {
        return;
    }

    if (conn->phase == SOCKS5_WAIT_LOOKUP) {
        uv_cancel((uv_req_t *)&conn->addrinfo_req);
    }

    /* Before closed.  Make sure the connect has been established */
    if (conn->phase > SOCKS5_INIT) {
        uv_read_stop((uv_stream_t *)&conn->handle);
        
        /*
        uv_shutdown_t *req = np_malloc(sizeof(uv_shutdown_t));
        req->data = conn;
        int n = uv_shutdown(req, (uv_stream_t *)&conn->handle, server_on_shutdown);
        if (n){
            uv_close((uv_handle_t *)&conn->handle, (uv_close_cb) server_on_close);
            np_free(req);
        }
        */
        
        /*
        if (!uv_is_closing((uv_handle_t *)&conn->handle)) {
            uv_close((uv_handle_t *)&conn->handle, (uv_close_cb) server_on_close);
        }
        */
        uv_close((uv_handle_t *)&conn->handle, (uv_close_cb) server_on_close);
        uv_close((uv_handle_t *)&conn->timer, NULL);
        log_info("CONNECT TERMINATE (%s -> %s)", conn->srcip, conn->dstip);
    }

    conn->rstat = np_dead;
    conn->wstat = np_dead;
    conn->phase = SOCKS5_DEAD;
}

static void
server_on_close(uv_handle_t *handle)
{
    np_connect_t *conn = handle->data;
    server_connect_deinit(conn);
    return ;
}

static void
server_on_read_done(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    np_connect_t *conn = stream->data;
    np_assert((uv_stream_t *)&conn->handle == stream);

    if (nread < 0) {
        if (nread != UV_EOF) {
            UV_SHOW_ERROR(nread, "read error");
            server_do_kill(conn->ctx);
            return;
        }
    }
    server_do_parse(conn, (uint8_t *)buf->base, nread);
    np_free(buf->base);
}

static void 
server_write(np_connect_t *conn, const char *data, unsigned int len)
{

    uv_buf_t buf;
    int r;
    unsigned int i;

    buf.base = (char *)data;
    buf.len = len;

    conn->write_req.data = conn;

    conn->wstat = np_busy;

    r = uv_write(&conn->write_req, (uv_stream_t *)&conn->handle, &buf, 1 , server_on_write_done);


    if (conn->phase == SOCKS5_PROXY) {
        log_debug("write: %s", data);
    } else {
        for (i=0; i<len; i++) {
            log_debug("write: %02X", data[i]);
        }
    }

    if (r < 0) {
        UV_SHOW_ERROR(r, "write error");
    }
    
    //server_timer_reset(np_connect_t *conn);
    
}


static void
server_on_write_done(uv_write_t *req, int status)
{
    np_connect_t *conn;

    if (status == UV_ECANCELED) {
        return;
    }
    
    conn = req->data;

    conn->last_status = status;
    if (status != 0) {
        log_warn("write error");
        //conn->phase = SOCKS5_ALMOST_DEAD;
        server_do_kill(conn->ctx);
        return;
    }

    conn->wstat = np_done;
    
    server_do_callback(conn);
}

static void 
server_get_addrinfo(np_connect_t *conn, const char *hostname) 
{
    int r;
    struct addrinfo hints;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0 ;

    conn->addrinfo_req.data = conn;
    
    r = uv_getaddrinfo(conn->handle.loop, &conn->addrinfo_req, 
                          server_on_get_addrinfo_done, hostname, NULL, &hints);
    if (r<0) {
      UV_SHOW_ERROR(r, "get addrinfo error");
    }
// conn_timer_reset(c);
}

static void 
server_on_get_addrinfo_done(uv_getaddrinfo_t *req, int status, struct addrinfo *ai)
{
    np_connect_t *conn;
    //np_context_t *ctx;
    
    conn = req->data;
    //conn = ctx->client;
    
    if (status == 0) {
      /* FIXME(bnoordhuis) Should try all addresses. */
      if (ai->ai_family == AF_INET) {
        conn->remoteaddr.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
      } else if (ai->ai_family == AF_INET6) {
        conn->remoteaddr.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
      } else {
          NOT_REACHED();
      }
    }

    conn->last_status = status;

    uv_freeaddrinfo(ai);

    server_do_callback(conn);
}

static int
server_connect(np_connect_t *conn)
{
    int r;

    conn->connect_req.data = conn;

    r = uv_tcp_connect(&conn->connect_req,
                       &conn->handle, 
                       (const struct sockaddr*)&conn->dstaddr, 
                       server_on_connect_done);
    return r;
    
}

static void 
server_on_connect_done(uv_connect_t* req, int status)
{
    np_connect_t *conn;

    conn = req->data; 

    conn->last_status = status;
    
    server_do_callback(conn);
}

static void
server_on_new_connect(uv_stream_t *us, int status)
{
    int err;
    np_status_t st;
    np_context_t *ctx;
    np_connect_t *client;
    
    if (status != 0) {
        UV_SHOW_ERROR(status, "libuv on connect");
        return;
    }


    ctx = (np_context_t *)np_malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return ;
    }

    st = server_context_init(ctx);
    if (st != NP_OK) {
        return ;
    }

    client = ctx->client;

    uv_tcp_init(us->loop, &client->handle);
    uv_timer_init(us->loop, &client->timer);

    //uv_tcp_keepalive(&client->handle, 0, 1);
    
    err = uv_accept((uv_stream_t *)us, (uv_stream_t *)&client->handle);
    if (err) {
        UV_SHOW_ERROR(err, "libuv on accept");
        return;
    }
    
    err = server_get_peeraddr((uv_stream_t *)&client->handle, &client->srcaddr.addr);
    if (err) {
        UV_SHOW_ERROR(err, "libuv on get peeraddr");
        return;
    }
    server_sockaddr_to_str((struct sockaddr_storage *)&client->srcaddr, (char *)&client->srcip);

    err = server_get_sockaddr((uv_stream_t *)&client->handle, &client->dstaddr.addr);
    if (err) {
        UV_SHOW_ERROR(err, "libuv on get sockaddr");
        return ;
    }
    server_sockaddr_to_str((struct sockaddr_storage *)&client->dstaddr, (char *)&client->dstip);

    client->handle.data = client;
    client->phase = SOCKS5_HANDSHAKE;

    err = uv_read_start((uv_stream_t *)&client->handle, (uv_alloc_cb)server_on_alloc_cb, (uv_read_cb)server_on_read_done);
    if (err) {
        UV_SHOW_ERROR(err, "libuv read start");
    }
    
    log_info("ACCEPT CONNECT from %s", client->srcip);
}

np_status_t
server_setup()
{
    np_status_t status;

    status = server_load_config(server);
    if (status != NP_OK) {
        log_stderr("load config '%s' failed", server.configfile);
        return status;
    }    
    
    config_dump(server.cfg);

    status = server_load_proxy_pool(server);
    if (status != NP_OK) {
        log_stderr("load proxy pool from redis failed.");
        return status;
    }
    proxy_pool_dump(server.proxy_pool);

    return NP_OK;
}

void 
server_stop()
{

    log_debug("server stopping");
    uv_stop(server.loop);
    server_deinit();
}


void
server_run()
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
    
    uv_ip4_addr(server.cfg->server->listen->data, server.cfg->server->port, &addr);
    err = uv_tcp_bind(us, (struct sockaddr *)&addr, 0);
    UV_CHECK(err, "libuv tcp bind");
    
    server.us = us;
    server.loop = loop;

    us->data = &server;
    
    err = uv_listen((uv_stream_t *)us, MAX_CONNECT_QUEUE, server_on_new_connect);
    UV_CHECK(err, "libuv listen");

    uv_run(loop, UV_RUN_DEFAULT);
    
}
