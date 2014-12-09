#include "log.h"
#include "socks5.h"

void socks5_init(s5_session_t *sess)
{
    sess->state = SOCKS5_VERSION;
    sess->phase = SOCKS5_HANDSHAKE;
}

void
socks5_select_auth(s5_session_t *sess)
{
    if (sess->methods & SOCKS5_NO_AUTH) {
        sess->method = SOCKS5_NO_AUTH;
    } else if (sess->methods & SOCKS5_AUTH_PASSWORD) {
        sess->method = SOCKS5_AUTH_PASSWORD;
    } else if (sess->methods & SOCKS5_AUTH_GSSAPI) {
        sess->method = SOCKS5_AUTH_GSSAPI;
    } else {
        sess->method = SOCKS5_AUTH_REFUSED;
    }
}

s5_error_t
socks5_parse(s5_session_t *sess, uint8_t **data, size_t *nread)
{
    s5_error_t err;
    uint8_t c;
    uint8_t *p;
    size_t n;
    size_t i;
    size_t read;
    
    p = *data;
    n = *nread;
    i = 0;
    read = 0;

    while (i < n) {
        c = p[i];
        i += 1;
        log_debug("read %02X", c);
        switch (sess->state) {
            case SOCKS5_VERSION:
                if (c != SOCKS5_SUPPORT_VERSION) {
                    err = SOCKS5_BAD_VERSION;
                    goto out;
                }
                sess->state = SOCKS5_NMETHODS;
                break;

            case SOCKS5_NMETHODS:
                sess->nmethods = c;
                sess->state = SOCKS5_METHODS;
                break;
            
            case SOCKS5_METHODS:
                if (read < sess->nmethods) {
                    switch (c) {
                        case 0:
                            sess->methods |= SOCKS5_NO_AUTH;
                            break;
                        case 1:
                            sess->methods |= SOCKS5_AUTH_GSSAPI;
                            break;
                        case 2:
                            sess->methods |= SOCKS5_AUTH_PASSWORD;
                            break;
                    }
                    read += 1;
                } 
                if (read == sess->nmethods) {
                    sess->state = SOCKS5_AUTH_VER;
                    break;
                }
               
                
        }
    }

    err = SOCKS5_OK;

out:
    *data = p +i;
    *nread = n - i;
    return err;
}


const char *
socks5_strerror(s5_error_t err) {
#define SOCKS5_ERR_GEN(_, name, errmsg) case SOCKS5_ ## name: return errmsg;
    switch (err) {
        SOCKS5_ERR_MAP(SOCKS5_ERR_GEN)
        default: ;  /* Silence s5_max_errors -Wswitch warning. */
    }
#undef SOCKS5_ERR_GEN
    return "Unknown error.";
}



