#include "log.h"
#include "socks.h"


void 
socks5_do_next(s5_session_t *sess, const char *data, ssize_t nread)
{   
    int new_state;
    switch (sess->state) {
        case socks5_handshake:
            new_state = socks5_do_handshake();
            break;
        case socks5_handshake_auth:
            new_state = socks5_do_handshake_auth();
            break;
    }    
    sess->state = new_state;
}


static s5_state_t
socks5_do_handshake()
{
    log_stdout("handshake called");
    return socks5_handshake_auth;
}

static s5_state_t
socks5_do_handshake_auth()
{
    log_stdout("handshake auth called");
    return socks5_handshake_auth;
}

/*
static s5_error_t
socks5_parse(s5_session_t *sess, char *data, )
*/
