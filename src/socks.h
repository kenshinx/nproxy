/** Socks v5 protocol implementaion
 * RFC(1928)
 * http://www.ietf.org/rfc/rfc1928.txt
*/

#ifndef _NPROXY_SOCKS_H_
#define _NPROXY_SOCKS_H_

#include <stdint.h>
#include <uv.h>


#define SOCKS5_SUPPORT_VERSION 5

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
    SOCKS5_HANDSHAKE,
    SOCKS5_HANDSHAKE_AUTH,
} s5_state_t;

typedef enum {
    SOCKS5_BAD_VERSION = -3,
    SOCKS5_BAD_CMD,
    SOCKS5_BAD_ATYP,
    SOCKS5_OK,
    SOCKS5_AUTH_SELECT,
    SOCKS5_AUTH_VERIFY,
    SOCKS5_EXEC_CMD
} s5_error_t;

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
    uv_tcp_t        handle;
    uv_timer_t      timer;
    s5_methods_t    methods;
    s5_cmd_t        cmd;
    s5_atyp_t       atyp;
} s5_session_t;

static s5_error_t socks5_parse(s5_session_t *sess, const uint8_t *buf, ssize_t *nread);
static s5_state_t socks5_do_handshake(s5_session_t *sess, const uint8_t *data, ssize_t nread);
static s5_state_t socks5_do_handshake_auth(s5_session_t *sess, const uint8_t *data, ssize_t nread);
void socks5_do_next(s5_session_t *sess, const uint8_t *buf, ssize_t nread);

#endif
