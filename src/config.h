#ifndef _NPROXY_CONFIG_H_
#define _NPROXY_CONFIG_H_

#include <stdio.h>
#include <errno.h>
#include <yaml.h>

#include "nproxy.h"
#include "util.h"
#include "log.h"


#define CONFIG_ROOT_DEPTH   1
#define CONFIG_MAX_DEPTH    CONFIG_ROOT_DEPTH + 1

struct config_server {
    char        *listen;
    int         port;
    unsigned    daemon:1;
    char        *pfile;
};

struct config_log {
    char    *file;
    char    *level;
};

struct config_redis {
    char    *server;
    int     port;
    int     db;
    char    *password;
};

struct config {
    char                    *fname; 
    FILE                    *fp;
    struct config_server    *server;
    struct config_log       *log;
    struct config_redis     *redis;
    int                     depth;
    yaml_parser_t           parser;
    yaml_event_t            event;
    yaml_token_t            token;
    unsigned                seq:1;
    unsigned                valid_parser:1;
    unsigned                valid_event:1;
    unsigned                valid_token:1;
};

struct config *config_creat(char *filename);

#endif
