#ifndef _DPROXY_H_
#define _DPROXY_H_


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "log.h"


#define NPROXY_VERSION              "0.1.1"
#define NPROXY_DEFAULT_CONFIG_FILE  "conf/nproxy.yml"
#define NPROXY_DEFAULT_LISTEN       "127.0.0.1"
#define NPROXY_DEFAULT_PORT         1221
#define NPROXY_DEFAULT_DAEMONIZE    0
#define NPROXY_DEFAULT_LOG_FILE     NULL
#define NPROXY_DEFAULT_LOG_LEVEL    LOG_NOTICE

#define CRLF                        "\r\n"
#define NP_OK                       0
#define NP_ERROR                    -1

typedef int np_status_t;

struct nproxy_server {
    char        *configfile;
    char        *pidfile;
    char        *listen;
    uint16_t    port;
    int         daemon;
    char        *logfile;
    int         loglevel;
    pid_t       pid;
}; 

#endif
