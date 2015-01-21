#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>

#include "core.h"
#include "config.h"
#include "version.h"
#include "server.h"

/*
 *        s5         s5 
 * client --> nproxy --> (upstream)proxy --> remote 
 *    ^         | ^             |
 *    |_ _ _ _  v | _ _ _ _ _ _ v
 *               
 */

struct nproxy_server server;


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
np_parse_option(int argc, char **argv)
{
    char *configfile = NPROXY_DEFAULT_CONFIG_FILE;
    if (argc >= 2) {   
        if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
            np_print_version();
        } else if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--verbose") == 0) {
            log_set_level(LOG_DEBUG);
            server.debug = true;
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
        server.configfile = realpath;
    } else {
        log_stderr("configuration file %s can't found", configfile);
        return NP_ERROR;
    }

    return NP_OK;

}

static void
np_print_run()
{
    log_stdout("nproxy server start");
    log_stdout("listen on %s:%d", server.cfg->server->listen->data, server.cfg->server->port);
    log_stdout("config file: %s", server.configfile);
}

static void
np_handle_signal(int sig)
{
    server_stop();

    switch (sig) {
        case SIGINT:
            log_notice("Received SIGINT scheduling shutdown...");
            exit(1);
        case SIGTERM:
            log_notice("Received SIGTERM scheduling shutdown...");
            exit(0);
        case SIGUSR1:
            log_notice("Received SIGUSR1 call grpof hook before shutdown...");
            /* 
             * TODO
             * gprof program must call "exit"(2) then generate gmon.out file 
             * */
            exit(2);
        default:
            log_notice("Received shutdown signal, scheduling shutdown...");
            exit(1);
    }
}

static void
np_setup_signal()
{
    struct sigaction act;

    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = np_handle_signal;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGUSR1, &act, NULL);
}

int
main(int argc, char **argv)
{
    
    np_status_t status;
    
    log_init();

    np_setup_signal();

    status = server_init();
    if (status != NP_OK) {
        log_stderr("init server failed.");
        exit(1);
    }

    status = np_parse_option(argc, argv);
    if (status != NP_OK) {
        log_stderr("parse option failed.");
        exit(1);
    }

    status = server_setup();
    if (status != NP_OK) {
        log_stderr("setup server failed.");
        exit(1);
    }

    /*
     * Update logger with the option in config file 
     */
    if (server.debug) {
        status = log_update(LOG_DEBUG, server.cfg->log->file->data);
    } else {
        int log_level = log_level_to_int(server.cfg->log->level->data);
        status = log_update(log_level, server.cfg->log->file->data);
    }
    if (status != NP_OK) {
        log_stderr("update log failed");
        exit(1);
    }
    
    np_print_run();
    
    server_run();
    
    exit(1);
    
}
