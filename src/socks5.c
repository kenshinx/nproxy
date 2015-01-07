#include "log.h"
#include "socks5.h"

s5_error_t
socks5_parse(s5_session_t *sess, const uint8_t **data, ssize_t *nread)
{
    s5_error_t err;
    uint8_t c;
    const uint8_t *p;
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
            /* handshake phase start */
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
            /* handshake phase end */

            /* sub negotiation start */
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
            /* sub negotiation end */

            /* request  phase start */
            case SOCKS5_REQ_VER:
                if (c != SOCKS5_SUPPORT_VERSION) {
                    err = SOCKS5_BAD_VERSION;
                    goto out;
                }
                sess->state = SOCKS5_REQ_CMD;
                break;

            case SOCKS5_REQ_CMD:
                switch (c) {
                    case 1:
                        sess->cmd = SOCKS5_CMD_CONNECT;
                        break;
                    case 2:
                        sess->cmd = SOCKS5_CMD_BIND;
                        break;
                    case 3:
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
                    case 1:  /* IPV4 */
                        sess->atyp = SOCKS5_ATYP_IPV4;
                        sess->alen = 4;
                        sess->state = SOCKS5_REQ_DADDR;
                        break;
                    case 3: /* DOMAIN */
                        sess->atyp = SOCKS5_ATYP_DOMAIN;
                        sess->alen = 0;
                        sess->state = SOCKS5_REQ_DDOMAIN;
                        break;
                    case 4: /* IPV6 */
                        sess->atyp = SOCKS5_ATYP_IPV6;
                        sess->alen = 16;
                        sess->state = SOCKS5_REQ_DADDR;
                        break;
                }
                break;

            case SOCKS5_REQ_DDOMAIN:
                sess->alen = c;  /* Hostname.  First byte is length. */
                sess->state = SOCKS5_REQ_DADDR;
                break;
           
            case SOCKS5_REQ_DADDR:
                if (sess->__len < sess->alen) {
                    sess->daddr[sess->__len] = c;
                    sess->__len += 1;
                }
                if (sess->__len == sess->alen) {
                    sess->daddr[sess->alen] = '\0';
                    sess->state = SOCKS5_REQ_DPORT0;
                }
                break;

            case SOCKS5_REQ_DPORT0:
                sess->dport = c <<8;
                sess->state = SOCKS5_REQ_DPORT1;
                break;
            
            case SOCKS5_REQ_DPORT1:
                sess->dport |= c;
                err = SOCKS5_OK;
                goto out;

            /* request phase end */


            /* client handshake phase start */
            case SOCKS5_CLIENT_VERSION:
                if (c != SOCKS5_SUPPORT_VERSION) {
                    err = SOCKS5_BAD_VERSION;
                    goto out;
                }
                sess->state = SOCKS5_CLIENT_METHOD;
                break;

            case SOCKS5_CLIENT_METHOD:
                switch(c) {
                    case 0:
                        sess->method = SOCKS5_NO_AUTH;
                        break;
                    case 1:
                        sess->method = SOCKS5_AUTH_GSSAPI;
                        break;
                    case 2:
                        sess->method = SOCKS5_AUTH_PASSWORD;
                        break;
                }

                err = SOCKS5_OK;
                goto out;
            /* client handshake phase end */

            /* client auth phase start */
            case SOCKS5_CLIENT_AUTH_VERSION:
                if (c != SOCKS5_AUTH_PW_VERSION) {
                    err = SOCKS5_BAD_VERSION;
                    goto out;
                }
                sess->state = SOCKS5_CLIENT_AUTH_STATUS;
                break;
                
            case SOCKS5_CLIENT_AUTH_STATUS:
                if (c != SOCKS5_AUTH_SUCESS) {
                    err = SOCKS5_AUTH_ERROR;
                    goto out;
                }
                err = SOCKS5_OK;
                goto out;
            /* client auth phase end */

            /* client reply phase start*/
            case SOCKS5_CLIENT_REP_VERSION:
                if (c != SOCKS5_SUPPORT_VERSION) {
                    err = SOCKS5_BAD_VERSION;
                    goto out;
                }
                sess->state = SOCKS5_CLIENT_REP_REP;
                break;

            case SOCKS5_CLIENT_REP_REP:
                switch(c) {
                    case 0:
                        sess->rep = SOCKS5_REP_SUCESS;
                        break;
                    case 1:
                        sess->rep = SOCKS5_REP_SOCKS_FAIL;
                        break;
                    case 2:
                        sess->rep = SOCKS5_REP_CONN_REFUSED_BY_RULESET;
                        break;
                    case 3:
                        sess->rep = SOCKS5_REP_NET_UNREACHABLE;
                        break;
                    case 4:
                        sess->rep = SOCKS5_REP_HOST_UNREACHABLE;
                        break;
                    case 5:
                        sess->rep = SOCKS5_REP_CONN_REFUSED;
                        break;
                    case 6:
                        sess->rep = SOCKS5_REP_TTL_EXPIRED;
                        break;
                    case 7:
                        sess->rep = SOCKS5_REP_CMD_NOT_SUPPORTED;
                        break;
                    case 8:
                        sess->rep = SOCKS5_REP_AYP_NOT_SUPPORTED;
                        break;
                    default:
                        sess->rep = SOCKS5_REP_UNSSIGNED;
                        break;
                }
                
                sess->state = SOCKS5_CLIENT_REP_RSV;
                break;

            case SOCKS5_CLIENT_REP_RSV:
                sess->state = SOCKS5_CLIENT_REP_ATYP;
                break;

            case SOCKS5_CLIENT_REP_ATYP:
                sess->__len = 0;
                switch(c) {
                    case 1:  /* IPV4 */
                        sess->atyp = SOCKS5_ATYP_IPV4;
                        sess->alen = 4;
                        sess->state = SOCKS5_CLIENT_REP_BADDR;
                        break;
                    case 3: /* DOMAIN */
                        sess->atyp = SOCKS5_ATYP_DOMAIN;
                        sess->alen = 0;
                        sess->state = SOCKS5_CLIENT_REP_BDOMAIN;
                        break;
                    case 4: /* IPV6 */
                        sess->atyp = SOCKS5_ATYP_IPV6;
                        sess->alen = 16;
                        sess->state = SOCKS5_CLIENT_REP_BADDR;
                        break;
                }
                break;
                
            case SOCKS5_CLIENT_REP_BDOMAIN:
                sess->alen = c;  /* Hostname.  First byte is length. */
                sess->state = SOCKS5_CLIENT_REP_BADDR;
                break;
           
            case SOCKS5_CLIENT_REP_BADDR:
                if (sess->__len < sess->alen) {
                    sess->baddr[sess->__len] = c;
                    sess->__len += 1;
                }
                if (sess->__len == sess->alen) {
                    sess->daddr[sess->alen] = '\0';
                    sess->state = SOCKS5_CLIENT_REP_BPORT0;
                }
                break;

            case SOCKS5_CLIENT_REP_BPORT0:
                sess->bport = c <<8;
                sess->state = SOCKS5_CLIENT_REP_BPORT1;
                break;
            
            case SOCKS5_CLIENT_REP_BPORT1:
                sess->bport |= c;
                err = SOCKS5_OK;
                goto out;
            /* client reply phase end*/


        }
    }
    
    err = SOCKS5_NEED_MORE_DATA;

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



