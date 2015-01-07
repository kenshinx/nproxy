#ifndef _NPROXY_CONFIG_H_
#define _NPROXY_CONFIG_H_

#include <yaml.h>
#include <stdint.h>
#include <sys/types.h>

#include "string.h"
#include "array.h"

#define CONFIG_ROOT_DEPTH   1
#define CONFIG_MAX_DEPTH    CONFIG_ROOT_DEPTH + 1
#define CONFIG_ARGS_LENGTH  4

#define NPROXY_DEFAULT_CONFIG_FILE      "conf/nproxy.yml"
#define NPROXY_DEFAULT_LISTEN           "127.0.0.1"
#define NPROXY_DEFAULT_PORT             1221
#define NPROXY_DEFAULT_DAEMONIZE        0
#define NPROXY_DEFAULT_REDIS_SERVER     "127.0.0.1"
#define NPROXY_DEFAULT_REDIS_PORT       6439

typedef uint8_t yaml_char;
typedef uint32_t yaml_len;

struct config_server {
    np_string       *listen;
    int             port;
    unsigned        daemon:1;
    np_string       *pfile;
    np_string       *redis_key;
    np_string       *username;
    np_string       *password;
};

struct config_log {
    np_string       *file;
    np_string       *level;
};

struct config_redis {
    np_string       *server;
    int             port;
    int             db;
    np_string       *password;
    int             timeout;
};

struct config {
    char                    *fname; 
    FILE                    *fp;
    struct config_server    *server;
    struct config_log       *log;
    struct config_redis     *redis;
    uint32_t                depth;
    np_array                *args;
    yaml_parser_t           parser;
    yaml_event_t            event;
    yaml_token_t            token;
    unsigned                seq:1;
    unsigned                valid_parser:1;
    unsigned                valid_event:1;
    unsigned                valid_token:1;
};

struct config *config_create(char *filename);
void config_dump(struct config *cfg);
void config_destroy(struct config *cfg);

#endif
