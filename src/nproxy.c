#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>

#include "array.h"
#include "string.h"
#include "util.h"
#include "config.h"
#include "version.h"
#include "server.h"


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
np_parse_option(int argc, char **argv, struct nproxy_server *server)
{
    char *configfile = NPROXY_DEFAULT_CONFIG_FILE;
    if (argc >= 2) {   
        if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
            np_print_version();
        } else if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--verbose") == 0) {
            log_set_level(LOG_DEBUG);
        } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            np_show_usage();
        } else if (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--config") == 0) {
            if (argc != 3) {
                np_show_usage();
            } else {
                configfile = argv[2];
            }
        } else {
            np_show_usage();   
        }
    }

    char *realpath;
    if ((realpath = np_get_absolute_path(configfile)) != NULL) {
        server->configfile = realpath;
    } else {
        log_stderr("configuration file %s can't found", configfile);
        return NP_ERROR;
    }

    return NP_OK;

}

static void
np_print_run(struct nproxy_server *server)
{
    log_stdout("nproxy server start");
    log_stdout("listen on %s:%d", server->cfg->server->listen->data, server->cfg->server->port);
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
    
    log_init();

    status = server_init(&server);
    if (status != NP_OK) {
        log_stderr("init server failed.");
        exit(1);
    }

    status = np_parse_option(argc, argv, &server);
    if (status != NP_OK) {
        log_stderr("parse option failed.");
        exit(1);
    }

    status = server_setup(&server);
    if (status != NP_OK) {
        log_stderr("setup server failed.");
        exit(1);
    }

    status = log_create(server.cfg->log->level, server.cfg->log->file->data);
    if (status != NP_OK) {
        log_stderr("init log failed");
        exit(1);
    }
    
    np_print_run(&server);
    np_run(&server);
    
    exit(1);
    
}
