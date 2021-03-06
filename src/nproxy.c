#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

#include "core.h"
#include "config.h"
#include "proxy.h"
#include "version.h"
#include "server.h"

/*
 *        s5         s5 
 * client --> nproxy --> (upstream)proxy --> remote 
 *    ^         | ^             |   ^          |
 *    |_ _ _ _  v | _ _ _ _ _ _ v   |_ _ _ _ _ v
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
        "   -d --config         :run as daemonize" CRLF
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
    if (argc >= 2) {   
        if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
            np_print_version();
        } else if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--verbose") == 0) {
            log_set_level(LOG_DEBUG);
            server.debug = 1;
        } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            np_show_usage();
        } else if (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--config") == 0) {
            if (argc != 3) {
                np_show_usage();
            } else {
                server.configfile = argv[2];
            }
        } else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--daemon") == 0) {
            server.daemon = 1;
        } else {
            np_show_usage();   
        }
    }

    return NP_OK;
}

static np_status_t
np_daemonize()
{
    pid_t pid, sid;
    int fd;
    
    pid = fork();
    switch (pid) {
        case -1:
            log_error("fork() failed: %s", strerror(errno));
            return NP_ERROR;
        case 0:
            break;
        default:
            /* parent process terminate */
            exit(0);
    }

    sid = setsid();
    if (sid < 0) {
        log_error("setsid failed: %s", strerror(errno));
        return NP_ERROR;
    }

    pid = fork();
    switch (pid) {
        case -1:
            log_error("double fork() failed: %s", strerror(errno));
            return NP_ERROR;
        case 0:
            break;
        default:
            /* parent process terminate */
            exit(0);
    }
    
    if (chdir("/") < 0) {
        log_error("chdir(/) failed: %s", strerror(errno));
        return NP_ERROR;
    }

    umask(0);
    
    if ((fd=open("/dev/null", O_RDWR, 0)) != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) {
            close(fd);
        }

        return NP_OK;
    } else {
        log_error("open('/dev/null') failed: %s", strerror(errno));
        return NP_ERROR;
    }
}

static np_status_t
np_create_pidfile()
{
    FILE *fp;
    char *pidfile;

    pidfile = server.cfg->server->pfile->data;
    fp = fopen(pidfile, "w");
    if (fp) {
        fprintf(fp, "%d\n", server.pid);
        fclose(fp);
        return NP_OK;
    } else {
        log_error("write pidfile '%s' failed: %s", pidfile,  strerror(errno));
        return NP_ERROR;
    }
}

static void
np_remove_pidfile()
{
    int status;
    char *pidfile;
    
    pidfile = server.cfg->server->pfile->data;
    status = unlink(pidfile);
    if (status < 0) {
        log_warn("Remove pdifile '%s' failed: %s", pidfile, strerror(errno));
    }
}

static void 
np_shutdown()
{
    server_stop();
    log_destroy();
    if (server.daemon) {
        np_remove_pidfile();
    }
    server_deinit();
}

static void
np_handle_signal(int sig)
{
    switch (sig) {
        case SIGINT:
            log_notice("Received SIGINT scheduling shutdown...");
            np_shutdown();
            exit(1);
        case SIGTERM:
            log_notice("Received SIGTERM scheduling shutdown...");
            np_shutdown();
            exit(0);
        case SIGUSR1:
            log_notice("Received SIGUSR1 call grpof hook before shutdown...");
            np_shutdown();
            /* 
             * TODO
             * gprof program must call "exit"(2) then generate gmon.out file 
             * */
            exit(2);
        default:
            log_notice("Received unhandle signal");
            return;
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

static np_status_t
np_setup()
{
    np_status_t status;
    char *realpath;

    status = server_init();
    if (status != NP_OK) {
        log_stderr("init server failed.");
        exit(1);
    }

    if (server.configfile == NULL) {
        server.configfile = NPROXY_DEFAULT_CONFIG_FILE;
        
    }
    if ((realpath = np_get_absolute_path(server.configfile)) != NULL) {
        server.configfile = realpath;
    } else {
        log_stderr("configuration file %s can't found", server.configfile);
        return NP_ERROR;
    }

    status = server_load_config();
    if (status != NP_OK) {
        log_stderr("load config '%s' failed", server.configfile);
        return status;
    }    
    
    config_dump(server.cfg);

    status = server_load_proxy_pool();
    if (status != NP_OK) {
        log_stderr("load proxy pool from redis failed.");
        return status;
    }
    proxy_pool_dump(server.proxy_pool);

    status = server_load_log();
    if (status != NP_OK) {
        log_stderr("load log failed");
        return status;
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
np_run()
{
    np_status_t status;

    if (server.daemon) {
        status = np_daemonize();
        if (status != NP_OK) {
            log_stderr("run as daemon failed.");
            exit(1);
        }
    }

    server.pid = getpid();

    if (server.daemon) {
        status = np_create_pidfile();
        if (status != NP_OK) {
            log_stderr("write pidfile failed.");
            exit(1);
        }
    }


    server_run();
}

int
main(int argc, char **argv)
{
    
    np_status_t status;
    
    log_init();

    status = np_parse_option(argc, argv);
    if (status != NP_OK) {
        log_stderr("parse option failed.");
        exit(1);
    }

    status = np_setup();
    if (status != NP_OK) {
        log_stderr("setup server failed.");
        exit(1);
    }

    np_setup_signal();
    np_print_run();
    np_run();
    np_shutdown();
    exit(1);
    
}
