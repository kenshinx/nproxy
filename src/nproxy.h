#ifndef _DPROXY_H_
#define _DPROXY_H_



#define NPROXY_DEBUG                    0
#define NPROXY_VERSION                  "0.1.1"
#define NPROXY_DEFAULT_CONFIG_FILE      "conf/nproxy.yml"
#define NPROXY_DEFAULT_LISTEN           "127.0.0.1"
#define NPROXY_DEFAULT_PORT             1221
#define NPROXY_DEFAULT_DAEMONIZE        0
#define NPROXY_DEFAULT_LOG_FILE         NULL
#define NPROXY_DEFAULT_LOG_LEVEL        LOG_INFO
#define NPROXY_DEFAULT_REDIS_SERVER     "127.0.0.1"
#define NPROXY_DEFAULT_REDIS_PORT       6439


struct nproxy_server {
    char            *configfile;
    struct config   *cfg;
    char            *pidfile;
    char            *logfile;
    int             loglevel;
    pid_t           pid;
}; 

#endif
