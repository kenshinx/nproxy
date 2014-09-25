#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>

#include <hiredis.h>

#include "core.h"
#include "config.h"
#include "array.h"
#include "string.h"
#include "nproxy.h"


static void
np_show_usage(void)
{ 
    char *confile;
    confile = np_get_absolute_path(NPROXY_DEFAULT_CONFIG_FILE);
    log_stderr(
        "Usage:" CRLF
        "   -h --help           :this help" CRLF
        "   -V --version        :show version and exit" CRLF
        "   -v --verbose        :set log level be debug" CRLF
        "   -c --config         :set configuration file (default:%s)" CRLF
        "",
        confile
    );
    exit(1);
}


static void
np_print_version(void)
{
    log_stdout("nproxy %s", NPROXY_VERSION);
    exit(0);
}

static np_status_t 
np_init_server(struct nproxy_server *server)
{
    server->configfile = NULL;
    server->cfg = NULL;
    
    server->proxy_pool = array_create(NPROXY_PROXY_POOL_LENGTH, sizeof(np_string));
    if (server->proxy_pool == NULL) {
        return  NP_ERROR;
    }

    server->pidfile = NULL;
    server->logfile = NPROXY_DEFAULT_LOG_FILE;
    server->loglevel = NPROXY_DEFAULT_LOG_LEVEL;
    server->pid = getpid();

    return NP_OK;
}

static void
np_parse_option(int argc, char **argv, struct nproxy_server *server)
{
    char *configfile = NPROXY_DEFAULT_CONFIG_FILE;
    if (argc >= 2) {   
        if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
            np_print_version();
        }
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--verbose") == 0) {
            server->loglevel = LOG_DEBUG;
        }
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            np_show_usage();
        }
        if (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--config") == 0) {
            if (argc != 3) {
                np_show_usage();
            } else {
                configfile = argv[2];
            }
        }
    }

    char *realpath;
    if ((realpath = np_get_absolute_path(configfile)) != NULL) {
        server->configfile = realpath;
    } else {
        log_stderr("configuration file %s can't found", configfile);
        exit(1);
    }

}

static np_status_t
np_load_server_config(struct nproxy_server *server)
{
    
    struct config *cfg;
    cfg = config_creat(server->configfile);
    if (cfg == NULL) {
        return NP_ERROR;
    }
    server->cfg = cfg;
    log_info("load config '%s' sucess", server->configfile);

    return NP_OK;
    
}

static np_status_t
np_init_log(struct nproxy_server *server)
{
    np_status_t status;
    status = log_init(server->loglevel, server->logfile);   
    return status;
}

static np_status_t
np_reinit_log(struct nproxy_server *server)
{
    /* reinit log with configuration load from config file */
    server->loglevel = server->cfg->log->level;
    server->logfile = server->cfg->log->file->data;
    return np_init_log(server);
}

redisContext *
np_redis_connect(struct nproxy_server *server)
{
    redisContext *c;

    struct timeval timeout  = {server->cfg->redis->timeout, 0};
    
    c = redisConnectWithTimeout(server->cfg->redis->server->data, server->cfg->redis->port, timeout);
    if (c == NULL || c->err) {
        if (c) {
            log_error("connect redis '%s:%d' failed: %s\n", 
                    server->cfg->redis->server->data, server->cfg->redis->port, c->errstr);
            redisFree(c);
        } else {
            log_error("connect redis error. can't allocate redis context");
        }

        return NULL;
    }

    log_debug("connect redis %s:%d\n", server->cfg->redis->server->data, server->cfg->redis->port);
    
    return c;
}

static np_status_t
np_load_proxy_pool(struct nproxy_server *server)
{
    redisContext *c;
    redisReply *reply;
    np_string   *proxy;
    unsigned int i;
    
    c = np_redis_connect(server);
    if (c == NULL) {
        return NP_ERROR;
    }

    reply = redisCommand(c, "SMEMBERS %s", server->cfg->server->redis_key->data);

    if (reply->type == REDIS_REPLY_ARRAY) {
        for (i = 0; i < reply->elements; i++) {
            proxy = string_create_with_len(reply->element[i]->str, reply->element[i]->len);
            array_push(server->proxy_pool, proxy);
        }
    }

    return NP_OK;
}

static void
_np_print_pool(np_string *proxy)
{
    log_notice("%s", proxy->data);
}

static void 
np_proxy_pool_dump(struct nproxy_server *server)
{
    np_string *proxy;

    log_notice("[Nproxy proxy pool]");
    array_each(server->proxy_pool, &_np_print_pool);
    
}


static np_status_t
np_setup_server(struct nproxy_server *server)
{
    np_status_t status;

    status = np_init_log(server);
    if (status != NP_OK) {
        log_stderr("init log failed");
        return status;
    }

    status = np_load_server_config(server);
    if (status != NP_OK) {
        log_stderr("load config '%s' failed", server->configfile);
        return status;
    }    
    
    config_dump(server->cfg);

    status = np_reinit_log(server);
    if (status != NP_OK) {
        log_stderr("reinit log failed");
        return status;
    }

    status = np_load_proxy_pool(server);
    if (status != NP_OK) {
        log_stderr("load proxy pool from redis failed.");
        return status;
    }
    
    np_proxy_pool_dump(server);

    return NP_OK;
}


static void
np_print_run(struct nproxy_server *server)
{
    log_stdout("nproxy server start");
    log_stdout("listen on %s:%d", server->cfg->server->listen->data, 
            server->cfg->server->port);
    log_stdout("config file: %s", server->configfile);
}


static void 
np_run(struct nproxy_server *server)
{
    printf("\n");
    
}


int
main(int argc, char **argv)
{
    struct nproxy_server server;
    np_status_t status;
    
    status = np_init_server(&server);
    if (status != NP_OK) {
        log_stderr("init server failed.");
        exit(1);
    }

    np_parse_option(argc, argv, &server);

    status = np_setup_server(&server);
    if (status != NP_OK) {
        log_stderr("setup server failed.");
        exit(1);
    }
    
    np_print_run(&server);
    np_run(&server);
    
    exit(1);
    
}
