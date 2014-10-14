#ifndef _NPROXY_SOCKS_H_
#define _NPROXY_SOCKS_H_

#define HTTP        1
#define SOCKSV4     2
#define SOCKSV5     3

struct s5_handler {
    char    *protocol;
    int     version;
};

#endif
