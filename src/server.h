#ifndef _NPROXY_SERVER_H_
#define _NPROXY_SERVER_H_

#include <uv.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <hiredis.h>

#include "core.h"
#include "array.h"
#include "string.h"
#include "socks5.h"

#define NPROXY_PROXY_POOL_LENGTH 200
#define MAX_CONNECT_QUEUE 512

#define UV_CHECK(err, what) do {                                             \
    if ((err) != 0) {                                                       \
        log_error("server run failed. %s:%s", what, uv_err_name(err));      \
        abort();                                                            \
    }                                                                       \
} while(0)                                                                  

#define UV_SHOW_ERROR(err, what) log_error("%s:%s", what, uv_strerror(err))     \


#define REMOTE_IP(handler, ip) do {                                             \
    struct sockaddr *remote_addr;                                               \
    remote_addr = server_get_remote_addr((uv_stream_t *)handler);               \
    if (remote_addr != NULL) {                                                  \
        ip = server_sockaddr_to_str((struct sockaddr_storage *)remote_addr);    \
    }                                                                           \
    np_free(remote_addr);                                                       \
} while(0)

union proxy_handler {
#ifdef SOCK5_PROXY_SUPPORT
    struct socks5_handler;
#endif

#ifdef SOCK4_PROXY_SUPPORT
    struct socks4_handler;
#endif

#ifdef HTTP_PROXY_SUPPORT
    struct http_handler;
#endif
};


typedef union {
    uv_getaddrinfo_t addrinfo_req;
    uv_connect_t connect_req;
    uv_req_t req;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    struct sockaddr addr;
    char buf[2048];  /* Scratch space. Used to read data into. */
} np_addr_t;

typedef enum {
    SOCKS5_HANDSHAKE,
    SOCKS5_SUB_NEGOTIATION,
    SOCKS5_REQUEST,
    SOCKS5_WAIT_LOOKUP,
    SOCKS5_REPLY,
    SOCKS5_CONN,
    SOCKS5_ALMOST_DEAD,
    SOCKS5_DEAD,
} np_phase_t;


typedef struct nproxy_connect 
{
    s5_session_t    *sess;
    np_phase_t      phase;
    uv_tcp_t        handle;
    uv_timer_t      timer;
    uv_write_t      write_req;
    np_addr_t       srcaddr;
    np_addr_t       dstaddr;
    int             last_status;
} np_connect_t;

typedef struct nproxy_context {
    struct nproxy_server    *server;
    np_connect_t            *client;
    np_connect_t            *upstream;          
} np_context_t;

struct nproxy_server {
    uv_tcp_t        *us; /* libuv tcp server */
    uv_loop_t       *loop; /* libuv loop */
    char            *configfile;
    struct config   *cfg;
    np_array        *proxy_pool;   
    char            *pidfile;
    pid_t           pid;
    unsigned        debug:1;
}; 

np_status_t server_init(struct nproxy_server *server);
np_status_t server_setup(struct nproxy_server *server);
redisContext *server_redis_connect(struct nproxy_server *server);
void server_run(struct nproxy_server *server);

#endif

