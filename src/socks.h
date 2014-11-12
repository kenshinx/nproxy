/** Socks v5 protocol implementaion
 * RFC(1928)
 * http://www.ietf.org/rfc/rfc1928.txt
*/

#ifndef _NPROXY_SOCKS_H_
#define _NPROXY_SOCKS_H_

#include <stdint.h>
#include <uv.h>

struct socks5_handler {
    uint8_t     protocol;
    uint8_t     version;
    uint8_t     method;
    uint8_t     state;
};

typedef enum {
    socks5_handshake,
    socks5_handshake_auth,
} s5_state_t;

typedef struct socks5_session {
    s5_state_t      state;
    uv_tcp_t        handle;
    uv_timer_t      timer;
} s5_session_t;


typedef enum {
    SOCKS_BAD_VERSION = -3,
    SOCKS_BAD_CMD,
    SOCKS_BAD_ATYP,
    SOCKS_OK,
    SOCKS_AUTH_SELECT,
    SOCKS_AUTH_VERIFY,
    SOCKS_EXEC_CMD
} s5_error_t;

typedef enum {
    SOCKS5_NO_AUTH =        0x00,
    SOCKS5_AUTH_GSSAPI =    0X01,
    SOCKS5_AUTH_PASSWORD =  0X02,
    SOCKS5_AUTH_REFUSED =   0Xff,
} s5_methods_t;


typedef enum {
    SOCKS5_CMD_ACCEPT =     0X01,
    SOCKS5_CMD_BIND =       0X02,
    SOCKS5_CMD_UDP_ASSOCIATE = 0X03,
} s5_cmd_t;

typedef enum {
    SOCKS5_ATYP_IPV4 =      0X01,
    SOCKS5_ATYP_DOMAIN =    0X03,
    SOCKS5_ATYP_IPV6 =      0X04,
} s5_atyp_t;

static s5_state_t socks5_do_handshake();
static s5_state_t socks5_do_handshake_auth();
void socks5_do_next(s5_session_t *sess, const char *data, ssize_t nread);

#endif
