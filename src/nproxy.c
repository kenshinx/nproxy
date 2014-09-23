#include <stdio.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>

#include <hiredis.h>

#include "core.h"
#include "config.h"
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

static void
np_init_server_config(struct nproxy_server *server)
{
    server->configfile = NULL;
    server->pidfile = NULL;
    server->listen = NPROXY_DEFAULT_LISTEN;
    server->port = NPROXY_DEFAULT_PORT;
    server->daemon = NPROXY_DEFAULT_DAEMONIZE;
    server->logfile = NPROXY_DEFAULT_LOG_FILE;
    server->loglevel = NPROXY_DEFAULT_LOG_LEVEL;
    server->pid = getpid();
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
    return np_init_log(server);
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

    status = np_reinit_log(server);
    if (status != NP_OK) {
        log_stderr("reinit log failed");
        return status;
    }



    return NP_OK;
}

static void
np_print_run(struct nproxy_server *server)
{
    log_stdout("nproxy server start");
    log_stdout("listen on %s:%d", server->listen, server->port);
    log_stdout("config file: %s", server->configfile);
}

static void 
np_run(struct nproxy_server *server)
{
    redisContext *c = redisConnect(server->cfg->redis->server->data, server->cfg->redis->port);
    
}


int
main(int argc, char **argv)
{
    struct nproxy_server server;
    np_status_t status;
    
    np_init_server_config(&server);
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
