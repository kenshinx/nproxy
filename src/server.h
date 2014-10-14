#ifndef _NPROXY_SERVER_H_
#define _NPROXY_SERVER_H_

#include <uv.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "core.h"
#include "array.h"
#include "string.h"
#include "socks.h"

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
    uv_tcp_t            *client;
    struct sockaddr     *remote_addr;
    char                *remote_ip;
    struct s5_handler   *handler;
} np_context_t;


np_status_t server_init(struct nproxy_server *server);

np_status_t server_setup(struct nproxy_server *server);

struct sockaddr *server_get_remote_addr(uv_stream_t *handler);

char *server_sockaddr_to_str(struct sockaddr_storage *addr);

char *server_get_remote_ip(uv_stream_t *handler);

void server_run(struct nproxy_server *server);

#endif

