#ifndef _NPROXY_SERVER_H_
#define _NPROXY_SERVER_H_

#include <uv.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <hiredis.h>

#include "core.h"
#include "socks5.h"

#define NPROXY_PROXY_POOL_LENGTH 200
#define MAX_CONNECT_QUEUE 2048

//#define ENABLE_SOCKS5_SERVER_AUTH
#define ENABLE_SOCKS5_CLIENT_AUTH

#define TCP_KEEPALIVE_DELAY 60

#define CONNECT_IDLE_TIMEOUT 60000  /* 1 minute */

#define LOAD_PROXY_POOL_INTERVAL 60000

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

typedef union {
    uv_req_t req;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    struct sockaddr addr;
    //char buf[2048];  /* Scratch space. Used to read data into. */
} np_addr_t;

typedef enum {
    np_busy,
    np_done,
    np_stop,
    np_dead,
} np_iostat_t;

typedef enum {
    SOCKS5_INIT,

    SOCKS5_HANDSHAKE,
    SOCKS5_SUB_NEGOTIATION,
    SOCKS5_REQUEST,
    SOCKS5_WAIT_LOOKUP,
    SOCKS5_WAIT_CONN,
    SOCKS5_WAIT_PROXY,
    SOCKS5_PROXY,
    SOCKS5_ALMOST_DEAD,
    SOCKS5_DEAD,

    SOCKS5_WAIT_UPSTREAM_CONN,
    SOCKS5_UPSTREAM_HANDSHAKE,
    SOCKS5_UPSTREAM_SUB_NEGOTIATION,
    SOCKS5_UPSTREAM_REPLY,
} np_phase_t;


typedef struct nproxy_connect 
{
    s5_session_t            *sess;
    struct nproxy_context   *ctx;
    np_phase_t              phase;
    uv_tcp_t                handle;
    uv_timer_t              timer;
    uv_write_t              write_req;
    uv_getaddrinfo_t        addrinfo_req;
    uv_connect_t            connect_req;
    np_addr_t               srcaddr;
    np_addr_t               dstaddr;
    np_addr_t               remoteaddr;
    char                    srcip[64];
    char                    dstip[64];
    char                    remoteip[64];
    int                     last_status;
    np_iostat_t             rstat;
    np_iostat_t             wstat;
} np_connect_t;

typedef struct nproxy_context {
    np_connect_t            *client;
    np_connect_t            *upstream;          
} np_context_t;

struct nproxy_server {
    uv_tcp_t        *us; /* libuv tcp server */
    uv_loop_t       *loop; /* libuv loop */
    char            *configfile;
    struct config   *cfg;
    np_array        *proxy_pool;   
    pid_t           pid;
    unsigned        debug:1;
    unsigned        daemon:1;
}; 

extern struct nproxy_server server;

np_status_t server_init();
void server_deinit();
np_status_t server_load_config();
np_status_t server_load_proxy_pool();
np_status_t server_load_log();
void server_stop();
void server_run();

#endif

