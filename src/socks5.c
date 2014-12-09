#include "log.h"
#include "socks5.h"

void socks5_init(s5_session_t *sess)
{
    sess->state = SOCKS5_VERSION;
    sess->phase = SOCKS5_HANDSHAKE;
}

void 
socks5_do_next(s5_session_t *sess, const uint8_t *data, ssize_t nread)
{   
    int new_phase;

    switch (sess->phase) {
        case SOCKS5_HANDSHAKE:
            new_phase = socks5_do_handshake(sess, data, nread);
            break;
        case SOCKS5_HANDSHAKE_AUTH:
            new_phase = socks5_do_handshake_auth(sess, data, nread);
            break;
        case SOCKS5_DEAD:
            log_error("socks5 dead");
            break;
    }    
    sess->phase = new_phase;
}


static s5_phase_t
socks5_do_handshake(s5_session_t *sess, const uint8_t *data, ssize_t nread)
{
    s5_error_t err;
    err = socks5_parse(sess, &data, &nread);
    if (err != SOCKS5_OK) {
        log_error("handshake error: %s", socks5_strerror(err));
        return socks5_do_kill(sess);
        //return SOCKS5_HANDSHAKE; 
    }
    if (nread != 0) {
        log_error("junk in handshake");
        return socks5_do_kill(sess);
    }
    return SOCKS5_HANDSHAKE_AUTH;
}

static s5_phase_t
socks5_do_handshake_auth(s5_session_t *sess, const uint8_t *data, ssize_t nread)
{
    log_stdout("handshake auth called");
    return SOCKS5_HANDSHAKE_AUTH;
}


static s5_phase_t
socks5_do_kill(s5_session_t *sess)
{
    return  SOCKS5_DEAD;
}

static s5_error_t
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



