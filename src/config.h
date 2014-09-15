#include <stdio.h>
#include <errno.h>
#include <yaml.h>

#include "nproxy.h"
#include "util.h"
#include "log.h"

#ifndef _NPROXY_CONFIG_H_
#define _NPROXY_CONFIG_H_


struct config_server {
    char *listen;
    int  port;
    int daemonize;
    char *config_file;
};

struct config_log {
    char *file;
    char *level;
};

struct config {
    char            *fname; 
    FILE            *fp;
    int             depth;
    yaml_parser_t   parser;
    yaml_event_t    event;
    yaml_token_t    token;
    unsigned        seq:1;
    unsigned        valid_parser:1;
    unsigned        valid_event:1;
    unsigned        valid_token:1;
};

struct config *config_creat(char *filename);

#endif
