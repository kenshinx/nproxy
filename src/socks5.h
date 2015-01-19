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


#define SOCKS5_ERR_MAP(V)                                                       \
    V(-1, SOCKS5_BAD_VERSION, "Bad protocol version.")                                 \
    V(-2, SOCKS5_BAD_CMD, "Bad protocol command.")                                     \
    V(-3, SOCKS5_BAD_ATYP, "Bad address type.")                                        \
    V(-4, SOCKS5_AUTH_ERROR, "Auth failure.")                                          \
    V(-5, SOCKS5_NEED_MORE_DATA, "Need more data.")                                    \
    V(0,  SOCKS5_OK, "No error.")                                                       \
    V(1,  SOCKS5_AUTH_SELECT, "Select authentication method.")                          \
    V(2,  SOCKS5_AUTH_VERIFY, "Verify authentication.")                                 \
    V(3,  SOCKS5_EXEC_CMD, "Execute command.")                                          \

typedef enum {
#define SOCKS5_ERR_GEN(code, name, _) name = code,
      SOCKS5_ERR_MAP(SOCKS5_ERR_GEN)
#undef SOCKS5_ERR_GEN
} s5_error_t;


#define SOCKS5_REP_MAP(V)   \
    V(0, SOCKS5_REP_SUCESS, "Connect sucess.") \
    V(1, SOCKS5_REP_SOCKS_FAIL, "Connect failed.")  \
    V(2, SOCKS5_REP_CONN_REFUSED_BY_RULESET, "Connect refused by ruleset.") \
    V(3, SOCKS5_REP_NET_UNREACHABLE, "Net unreachable") \
    V(4, SOCKS5_REP_HOST_UNREACHABLE, "Host unreachable") \
    V(5, SOCKS5_REP_CONN_REFUSED, "Connect refused")\
    V(6, SOCKS5_REP_TTL_EXPIRED, "TTL expired")\
    V(7, SOCKS5_REP_CMD_NOT_SUPPORTED, "SOCKS5 CMD not supported")  \
    V(8, SOCKS5_REP_ATYP_NOT_SUPPORTED, "SOCKS5 ATYP not supported") \
    V(0xff, SOCKS5_REP_UNASSIGNED, "Unassigned error id")   \

typedef enum {
#define SOCKS5_REP_GEN(code, name, _) name = code,
      SOCKS5_REP_MAP(SOCKS5_REP_GEN)
#undef SOCKS5_REP_GEN
} s5_rep_t;

#define SOCKS5_AUTH_SUCESS  0

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
    
    SOCKS5_CLIENT_VERSION,
    SOCKS5_CLIENT_METHOD,
    SOCKS5_CLIENT_AUTH_VERSION,
    SOCKS5_CLIENT_AUTH_STATUS,
    SOCKS5_CLIENT_REP_VERSION,
    SOCKS5_CLIENT_REP_REP,
    SOCKS5_CLIENT_REP_RSV,
    SOCKS5_CLIENT_REP_ATYP,
    SOCKS5_CLIENT_REP_BADDR,
    SOCKS5_CLIENT_REP_BDOMAIN,
    SOCKS5_CLIENT_REP_BPORT0,
    SOCKS5_CLIENT_REP_BPORT1
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
    uint8_t         baddr[256]; /* 256 for atyp is domain */
    uint16_t        bport; 
    s5_rep_t        rep;
} s5_session_t;

s5_error_t socks5_parse(s5_session_t *sess, const uint8_t **data, ssize_t *nread);
const char *socks5_strerror(s5_error_t err);
const char *socks5_strrep(s5_rep_t rep);
void socks5_select_auth(s5_session_t *sess);


#endif
