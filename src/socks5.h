/* 
 * Socks v5 protocol implementaion
 * RFC(1928)
 * http://www.ietf.org/rfc/rfc1928.txt
 *
 * Username/Password authentication for socks5
 * RFC(1929)
 * http://www.ietf.org/rfc/rfc1929.txt
*/

#ifndef _NPROXY_SOCKS_H_
#define _NPROXY_SOCKS_H_

#include <stdint.h>
#include <uv.h>


#define SOCKS5_SUPPORT_VERSION 0X05
#define SOCKS5_AUTH_PW_VERSION 0X01 


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


typedef enum {
    SOCKS5_VERSION,
    SOCKS5_NMETHODS,
    SOCKS5_METHODS,
    SOCKS5_AUTH_PW_VER,
    SOCKS5_AUTH_PW_ULEN,
    SOCKS5_AUTH_PW_UNAME,
    SOCKS5_AUTH_PW_PLEN,
    SOCKS5_AUTH_PW_PASSWD,
    SOCKS5_REQ_VER,
    SOCKS5_REQ_CMD,
    SOCKS5_REQ_RSV,
    SOCKS5_REQ_ATYP,
    SOCKS5_REQ_DADDR,
    SOCKS5_REQ_DDOMAIN,
    SOCKS5_REQ_DPORT0,
    SOCKS5_REQ_DPORT1,
    
} s5_state_t;


typedef enum {
    SOCKS5_NO_AUTH =        1 << 0,
    SOCKS5_AUTH_GSSAPI =    1 << 1,
    SOCKS5_AUTH_PASSWORD =  1 << 2,
    SOCKS5_AUTH_REFUSED =   0Xff,
} s5_methods_t;


typedef enum {
    SOCKS5_CMD_CONNECT =     0X01,
    SOCKS5_CMD_BIND,
    SOCKS5_CMD_UDP_ASSOCIATE,
} s5_cmd_t;

typedef enum {
    SOCKS5_ATYP_IPV4 =      0X01,
    SOCKS5_ATYP_DOMAIN =    0X03,
    SOCKS5_ATYP_IPV6 =      0X04,
} s5_atyp_t;

typedef struct socks5_session {
    size_t          __len;
    s5_state_t      state;
    uint8_t         nmethods;
    uint8_t         methods;
    s5_methods_t    method;
    uint8_t         ulen;
    uint8_t         uname[256];
    uint8_t         plen;
    uint8_t         passwd[256];
    s5_cmd_t        cmd;
    s5_atyp_t       atyp;
    uint8_t         alen;
    uint8_t         daddr[256]; /* 256 for atyp is domain */
    uint16_t        dport; 
} s5_session_t;

s5_error_t socks5_parse(s5_session_t *sess, const uint8_t **data, ssize_t *nread);
const char *socks5_strerror(s5_error_t err);
void socks5_select_auth(s5_session_t *sess);


#endif
