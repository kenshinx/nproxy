#include <stdio.h>
#include <unistd.h>

#include "config.h"

static struct config_server *
config_server_init(void)
{
    struct config_server *server;

    server = np_malloc(sizeof(*server));
    if (server == NULL) {
        return NULL;
    }
    
    server->listen = NPROXY_DEFAULT_LISTEN;
    server->port = NPROXY_DEFAULT_PORT; 
    server->daemon = NPROXY_DEFAULT_DAEMONIZE;
    server->pfile = NULL;
    
    return server;
}

static struct config_log *
config_log_init(void)
{
    struct config_log *log;

    log = np_malloc(sizeof(*log));
    if (log == NULL) {
        return NULL;
    }

    log->file = NPROXY_DEFAULT_LOG_FILE;
    log->level = NPROXY_DEFAULT_LOG_LEVEL;
    
    return log;
}

static struct config_redis *
config_redis_init(void)
{
    struct config_redis *redis;

    redis = np_malloc(sizeof(*redis));
    if (redis == NULL) {
        return NULL;
    }
    
    redis->server = NPROXY_DEFAULT_REDIS_SERVER;
    redis->port = NPROXY_DEFAULT_REDIS_PORT;
    redis->db = 0;
    redis->password = NULL;
    
    return redis;
}

static void 
config_destroy(struct config *cfg)
{
    if (cfg->server != NULL) {
        np_free(cfg->server);
    }
    if (cfg->log != NULL) {
        np_free(cfg->log);
    }
    if (cfg->redis != NULL) {
        np_free(cfg->redis);
    }
    if (cfg != NULL) {
        np_free(cfg);
    }
}

static struct config *
config_init(char *filename)
{
    struct config *cfg;
    struct config_server *cfg_server;
    struct config_log *cfg_log;
    struct config_redis *cfg_redis;
    FILE *fp;
    
    fp = fopen(filename, "r");
    if (fp == NULL) {
        log_error("failed to open configuration file: %s", filename);
        return NULL;
    }

    cfg = np_malloc(sizeof(*cfg));
    if (cfg == NULL) {
        goto error;
    }

    cfg_server = config_server_init();
    if (cfg_server == NULL) {
        goto error;
    }
    cfg->server = cfg_server;

    cfg_log = config_log_init();
    if (cfg_log == NULL) {
        goto error;
    }
    cfg->log = cfg_log;


    cfg_redis = config_redis_init();
    if (cfg_redis == NULL) {
        goto error;
    }
    cfg->redis = cfg_redis;

    cfg->fname = filename;
    cfg->fp = fp;
    
    cfg->seq = 0;
    cfg->depth = 0;
    cfg->valid_parser = 0;
    cfg->valid_event = 0;
    cfg->valid_token = 0;

    log_debug("open config '%s'", filename);

    return cfg;

error:
    log_error("initialize config failed");
    fclose(fp);
    config_destroy(cfg);
    return NULL;
}

static np_status_t
config_yaml_init(struct config *cfg)
{
    np_status_t status;
    int rv;
    
    rv = fseek(cfg->fp, 0L, SEEK_SET);
    if (rv < 0) {
        log_error("fail seek to the beginning of the config file '%s': '%s'", 
                    cfg->fname, strerror(errno));
        return NP_ERROR;
    }

    rv = yaml_parser_initialize(&cfg->parser);
    if (!rv) {
        log_error("fail (err %d) to initialize yaml parser", cfg->parser.error);
        return NP_ERROR;
    }

    yaml_parser_set_input_file(&cfg->parser, cfg->fp);
    cfg->valid_parser = 1;

    return NP_OK;
}

static void
config_yaml_destroy(struct config *cfg)
{
    if (cfg->valid_parser) {
        yaml_parser_delete(&cfg->parser);
        cfg->valid_parser = 0;
    }
}

static np_status_t
config_event_next(struct config *cfg)
{
    int rv;

    np_assert(cfg->valid_parser && !cfg->valid_event);
    
    rv = yaml_parser_parse(&cfg->parser, &cfg->event);
    if (!rv) {
        log_error("failed (err %d) to get next event", cfg->parser.error);
        return NP_ERROR;
    }
    cfg->valid_event = 1;
    
    return NP_OK;
}

static void
config_event_done(struct config *cfg)
{
    if (cfg->valid_event) {
        yaml_event_delete(&cfg->event);
        cfg->valid_event = 0;
    }
}

static np_status_t
config_begin_parse(struct config *cfg)
{
    np_status_t status;
    bool done;

    np_assert(cfg->depth == 0);

    status = config_yaml_init(cfg);
    if (status != NP_OK) {
        return status;
    }

    do {
        status = config_event_next(cfg);
        if (status != NP_OK) {
            return status;
        }

        log_debug("next begin event %d", cfg->event.type);

        switch (cfg->event.type) {
            case YAML_STREAM_START_EVENT:
            case YAML_DOCUMENT_START_EVENT:
                break;
            case YAML_MAPPING_START_EVENT:
                np_assert(cfg->depth < CONFIG_MAX_DEPTH);
                cfg->depth++;
                done = true;
                break;
            default:
                NOT_REACHED();
        }

        config_event_done(cfg);

    } while (!done);

    return NP_OK; 

}

static np_status_t
config_parse_core(struct config *cfg, void *data)
{
    np_status_t status;
    bool done, leaf, new_section;
    char *section;
    char *key;
    void *value;
    void *scalar;

    status = config_event_next(cfg);
    if (status != NP_OK) {
        return status;
    }

    log_debug("next event %d depth %d seq %d", 
                cfg->event.type, cfg->depth, cfg->seq);

    done = false;
    leaf = false;
    new_section = false;

    switch (cfg->event.type) {
        case YAML_MAPPING_END_EVENT:
            cfg->depth--;
            if (cfg->depth == 1) {
                //config_pop_scalar(cfg);
                printf("yaml mapping end event\n");
            } else if (cfg->depth == 0) {
                done = true;
            }
            break;

        case YAML_MAPPING_START_EVENT:
            cfg->depth++;
            printf("yaml mapping start event\n");
            break;

        case YAML_SEQUENCE_START_EVENT:
            cfg->seq = 1;
            break;

        case YAML_SEQUENCE_END_EVENT:
            cfg->seq = 0;
            break;

        case YAML_SCALAR_EVENT:
            scalar = cfg->event.data.scalar.value;
            if (cfg->seq) {
                break;
                //leaf = true;
                /* TODO
                 * list options not yet support.
                 */
            }  else if (cfg->depth == CONFIG_ROOT_DEPTH) {
                new_section = true;
                section = scalar;
                printf("seq:%d depth:%d  section: %s\n",cfg->seq, cfg->depth, section);
                /* new section */
                
            } else if (cfg->depth == CONFIG_MAX_DEPTH) {
                /* evaluation section*/
                printf("seq:%d depth:%d  data: %s\n",cfg->seq, cfg->depth, scalar);
            }
            break;
        
        default:
            NOT_REACHED();
            break;
    }

    config_event_done(cfg);

    return config_parse_core(cfg, data);

    
}

static np_status_t
config_parse(struct config *cfg)
{
    np_status_t status;
    
    status = config_begin_parse(cfg);
    if (status != NP_OK) {
        return status;
    }
    
    status = config_parse_core(cfg, NULL);
    if (status != NP_OK) {
        return status;
    }

    return NP_OK;
}

struct config *
config_creat(char *filename)
{
    struct config *cfg;
    np_status_t status;

    cfg = config_init(filename);
    if (cfg == NULL) {
        return NULL;
    }

    status = config_parse(cfg);
    if (status != NP_OK) {
        goto error;
    }
    

    fclose(cfg->fp);
    cfg->fp = NULL;

    return cfg;


error:
    fclose(cfg->fp);
    cfg->fp = NULL;
    config_destroy(cfg);
    return NULL;

}



