/** Socks v5 protocol implementaion
 * RFC(1928)
 * http://www.ietf.org/rfc/rfc1928.txt
*/

#ifndef _NPROXY_SOCKS_H_
#define _NPROXY_SOCKS_H_

#include <stdint.h>
#include <uv.h>


#define SOCKS5_SUPPORT_VERSION 0X05 //socks v5

#define SOCKS5_SHOW_ERROR(err) log_error("%s:%s", what, uv_strerror(err))     \


#define SOCKS5_ERR_MAP(V)                                                           \
    V(-1, BAD_VERSION, "Bad protocol version.")                                 \
    V(-2, BAD_CMD, "Bad protocol command.")                                     \
    V(-3, BAD_ATYP, "Bad address type.")                                        \
    V(0, OK, "No error.")                                                       \
    V(1, AUTH_SELECT, "Select authentication method.")                          \
    V(2, AUTH_VERIFY, "Verify authentication.")                                 \
    V(3, EXEC_CMD, "Execute command.")                                          \

typedef enum {
#define SOCKS5_ERR_GEN(code, name, _) SOCKS5_ ## name = code,
      SOCKS5_ERR_MAP(SOCKS5_ERR_GEN)
#undef SOCKS5_ERR_GEN
} s5_error_t;

struct socks5_handler {
    uint8_t     protocol;
    uint8_t     version;
    uint8_t     method;
    uint8_t     state;
};

typedef enum {
    SOCKS5_VERSION,
    SOCKS5_NMETHODS,
    SOCKS5_METHODS,
    SOCKS5_AUTH_VER,
} s5_state_t;

typedef enum {
    SOCKS5_HANDSHAKE,
    SOCKS5_HANDSHAKE_AUTH,
    SOCKS5_ALMOST_DEAD,
    SOCKS5_DEAD,
} s5_phase_t;


typedef enum {
    SOCKS5_NO_AUTH =        1 << 0,
    SOCKS5_AUTH_GSSAPI =    1 << 1,
    SOCKS5_AUTH_PASSWORD =  1 << 2,
    SOCKS5_AUTH_REFUSED =   0Xff,
} s5_methods_t;


typedef enum {
    SOCKS5_CMD_ACCEPT =     0X01,
    SOCKS5_CMD_BIND,
    SOCKS5_CMD_UDP_ASSOCIATE,
} s5_cmd_t;

typedef enum {
    SOCKS5_ATYP_IPV4 =      0X01,
    SOCKS5_ATYP_DOMAIN =    0X03,
    SOCKS5_ATYP_IPV6 =      0X04,
} s5_atyp_t;

typedef struct socks5_session {
    s5_state_t      state;
    s5_phase_t      phase;
    uv_tcp_t        handle;
    uv_timer_t      timer;
    uint8_t         nmethods;
    uint8_t         methods;
    s5_cmd_t        cmd;
    s5_atyp_t       atyp;
} s5_session_t;

static s5_error_t socks5_parse(s5_session_t *sess, uint8_t **data, size_t *nread);
static s5_phase_t socks5_do_handshake(s5_session_t *sess, const uint8_t *data, ssize_t nread);
static s5_phase_t socks5_do_handshake_auth(s5_session_t *sess, const uint8_t *data, ssize_t nread);
static s5_phase_t socks5_do_kill(s5_session_t *sess);
const char *socks5_strerror(s5_error_t err);
void socks5_init(s5_session_t *sess);
void socks5_do_next(s5_session_t *sess, const uint8_t *buf, ssize_t nread);

#endif
