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



typedef struct nproxy_context {
    s5_session_t            *client;
    s5_session_t            *upstream;          
    struct sockaddr         *client_addr;
    char                    *client_ip;
    struct sockaddr         *remote_addr;
    char                    *remote_ip;
} np_context_t;


np_status_t server_init(struct nproxy_server *server);

static np_status_t server_context_init(np_context_t *ctx);

static void server_context_deinit(np_context_t *ctx);

static np_status_t server_load_config(struct nproxy_server *server);

static np_status_t server_load_proxy_pool(struct nproxy_server *server);

np_status_t server_setup(struct nproxy_server *server);

redisContext *server_redis_connect(struct nproxy_server *server);


static uv_buf_t *server_alloc_cb(uv_handle_t *handler/*handle*/, size_t suggested_size, uv_buf_t* buf); 

struct sockaddr *server_get_remote_addr(uv_stream_t *handler);

char *server_sockaddr_to_str(struct sockaddr_storage *addr);

char *server_get_remote_ip(uv_stream_t *handler);

static void server_do_next(s5_session_t *sess, const uint8_t *buf, ssize_t nread);
static s5_phase_t server_do_handshake(s5_session_t *sess, const uint8_t *data, ssize_t nread);
static s5_phase_t server_do_handshake_auth(s5_session_t *sess, const uint8_t *data, ssize_t nread);
static s5_phase_t server_do_kill(s5_session_t *sess);

static void server_on_close(uv_handle_t *stream);
static void server_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void server_on_write(s5_session_t *sess, const char *data, unsigned int len);
static void server_on_write_done(uv_write_t *req, int status);
static void server_on_connect(uv_stream_t *us, int status);


void server_run(struct nproxy_server *server);

#endif

