#include "log.h"
#include "socks5.h"

void socks5_init(s5_session_t *sess)
{
    sess->state = SOCKS5_VERSION;
    sess->phase = SOCKS5_HANDSHAKE;
}

s5_error_t
socks5_parse(s5_session_t *sess, uint8_t **data, size_t *nread)
{
    s5_error_t err;
    uint8_t c;
    uint8_t *p;
    size_t n;
    size_t i;
    
    p = *data;
    n = *nread;
    i = 0;

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
                sess->__len = 0;
                sess->nmethods = c;
                sess->state = SOCKS5_METHODS;
                break;
            
            case SOCKS5_METHODS:
                if (sess->__len < sess->nmethods) {
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
                    sess->__len += 1;
                } 
                if (sess->__len == sess->nmethods) {
                    err = SOCKS5_OK;
                    goto out;
                }
                break;

            case SOCKS5_AUTH_PW_VER:
                if (c != SOCKS5_AUTH_PW_VERSION) {
                    err = SOCKS5_BAD_VERSION;
                    goto out;
                }
                sess->state = SOCKS5_AUTH_PW_ULEN;
                break;
            
            case SOCKS5_AUTH_PW_ULEN:
                sess->__len = 0;
                sess->ulen = c;
                sess->state = SOCKS5_AUTH_PW_UNAME;
                break;

            case SOCKS5_AUTH_PW_UNAME:
                if (sess->__len < sess->ulen) {
                    sess->uname[sess->__len] = c;
                    sess->__len += 1;
                }
                if (sess->__len == sess->ulen) {
                    sess->uname[sess->ulen] = '\0';
                    sess->state = SOCKS5_AUTH_PW_PLEN;
                }
                break;

            case SOCKS5_AUTH_PW_PLEN:
                sess->__len = 0;
                sess->plen = c;
                sess->state = SOCKS5_AUTH_PW_PASSWD;
                break;

            case SOCKS5_AUTH_PW_PASSWD:
                if (sess->__len < sess->plen) {
                    sess->passwd[sess->__len] = c;
                    sess->__len += 1;
                }        
                if (sess->__len == sess->plen) {
                    sess->passwd[sess->plen] = '\0';
                    err = SOCKS5_OK;
                    goto out;
                }
                break;

            case SOCKS5_REQ_VER:
                if (c != SOCKS5_SUPPORT_VERSION) {
                    err = SOCKS5_BAD_VERSION;
                    goto out;
                }
                sess->state = SOCKS5_REQ_CMD;
                break;

            case SOCKS5_REQ_CMD:
                switch (c) {
                    case 0:
                        sess->cmd = SOCKS5_CMD_CONNECT;
                        break;
                    case 1:
                        sess->cmd = SOCKS5_CMD_BIND;
                        break;
                    case 2:
                        sess->cmd = SOCKS5_CMD_UDP_ASSOCIATE;
                        break;
                    default:
                        err = SOCKS5_BAD_CMD;
                        goto out;
                }
                sess->state = SOCKS5_REQ_RSV;
                break;

            case SOCKS5_REQ_RSV:
                sess->state = SOCKS5_REQ_ATYP;
                break;
                
            case SOCKS5_REQ_ATYP:
                sess->__len = 0;
                switch(c) {
                    case 1:
                        sess->atyp = SOCKS5_ATYP_IPV4;
                        
                }
            

                
        }
    }

    err = SOCKS5_OK;

out:
    *data = p +i;
    *nread = n - i;
    return err;
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


