
#include "string.h"
#include "socks.h"

socks_proxy *
socks_proxy_from_json(const char *str)
{
    socks_proxy *proxy;

    proxy = np_malloc(sizeof(*proxy));
    if (proxy == NULL) {
        return NULL;       
    }

    return proxy;

}
