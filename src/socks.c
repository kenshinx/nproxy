#include "log.h"
#include "socks.h"


void 
socks5_do_next(s5_session_t *sess, const uint8_t *data, ssize_t nread)
{   
    int new_state;
    
    switch (sess->state) {
        case SOCKS5_HANDSHAKE:
            new_state = socks5_do_handshake(sess, data, nread);
            break;
        case SOCKS5_HANDSHAKE_AUTH:
            new_state = socks5_do_handshake_auth(sess, data, nread);
            break;
    }    
    sess->state = new_state;
}


static s5_state_t
socks5_do_handshake(s5_session_t *sess, const uint8_t *data, ssize_t nread)
{
    s5_error_t err;
    sess->state = SOCKS5_VERSION;
    err = socks5_parse(sess, data, &nread);
    return SOCKS5_HANDSHAKE_AUTH;
}

static s5_state_t
socks5_do_handshake_auth(s5_session_t *sess, const uint8_t *data, ssize_t nread)
{
    log_stdout("handshake auth called");
    return SOCKS5_HANDSHAKE_AUTH;
}

static s5_error_t
socks5_parse(s5_session_t *sess, const uint8_t *buf, ssize_t *nread)
{
    int i = 0;
    uint8_t c;
    s5_error_t err;
    while (i < nread) {
        c = buf[i];
        i += 1;
        switch (sess->state) {
            case SOCKS5_VERSION:
                if (c != SOCKS5_SUPPORT_VERSION) {
                    err = SOCKS5_BAD_VERSION;
                    goto err;
                }
                sess->state = SOCKS5_NMETHODS;
                break;
        }
    }

    err:
        return err;
}
