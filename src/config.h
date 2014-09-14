#include <stdio.h>
#include <yaml.h>

#ifndef _NPROXY_CONFIG_H_
#define _NPROXY_CONFIG_H_


struct conf_server {
    char *listen;
    int  port;
    int daemonize;
    char *config_file;
};

struct conf_log {
    char *file;
    char *level;
}

struct conf {
    char *fname; 
}

void config_init(char *filename);

#endif
