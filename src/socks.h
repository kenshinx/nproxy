/** Socks v5 protocol implementaion
 * RFC(1928)
 * http://www.ietf.org/rfc/rfc1928.txt
*/

#ifndef _NPROXY_SOCKS_H_
#define _NPROXY_SOCKS_H_

#include <stdint.h>

#define HTTP        1
#define SOCKSV4     2
#define SOCKSV5     3

struct socks5_handler {
    uint8_t     protocol;
    uint8_t     version;
    uint8_t     method;
    uint8_t     state;
};

typedef enum {
    SOCKS5_NO_AUTH =        0x00,
    SOCKS5_AUTH_GSSAPI =    0X01,
    SOCKS5_AUTH_PASSWORD =  0X02,
    SOCKS5_AUTH_REFUSED =   0Xff,
} socks5_methods_t;


typedef enum {
    SOCKS5_CMD_ACCEPT =     0X01,
    SOCKS5_CMD_BIND =       0X02,
    SOCKS5_CMD_UDP_ASSOCIATE = 0X03,
} socks5_cmd_t;

typedef enum {
    SOCKS5_ATYP_IPV4 =      0X01,
    SOCKS5_ATYP_DOMAIN =    0X03,
    SOCKS5_ATYP_IPV6 =      0X04,
} socks5_atyp_t;

#endif
