#include <stdio.h>
#include <unistd.h>

#include <errno.h>
#include <yaml.h>

#include "core.h"
#include "log.h"
#include "util.h"
#include "config.h"


static struct config_server *
config_server_init(void)
{ 
    struct config_server *server;

    server = np_malloc(sizeof(*server));
    if (server == NULL) {
        return NULL;
    }
    
    server->listen = string_create(NPROXY_DEFAULT_LISTEN);
    if (server->listen == NULL) {
        return NULL;
    }

    server->pfile = string_null();
    if (server->pfile == NULL) {
        return NULL;
    }

    server->redis_key = string_null();
    if (server->redis_key == NULL) {
        return NULL;
    }

    server->port = NPROXY_DEFAULT_PORT; 
    server->daemon = NPROXY_DEFAULT_DAEMONIZE;
    
    return server;
}

static void 
config_server_deinit(struct config_server *server)
{
    string_deinit(server->listen);
    string_deinit(server->pfile);
    string_deinit(server->redis_key);
    np_free(server);
}

static struct config_log *
config_log_init(void)
{
    struct config_log *log;

    log = np_malloc(sizeof(*log));
    if (log == NULL) {
        return NULL;
    }
    
    log->file = string_null();
    if (log->file == NULL) {
        return NULL;
    }

    log->level = string_null();
    if (log->level == NULL) {
        return NULL;
    }
    
    return log;
}


static void
config_log_deinit(struct config_log *log)
{
    string_deinit(log->file);
    string_deinit(log->level);
    np_free(log);
}

static struct config_redis *
config_redis_init(void)
{
    struct config_redis *redis;

    redis = np_malloc(sizeof(*redis));
    if (redis == NULL) {
        return NULL;
    }
    
    redis->server = string_create(NPROXY_DEFAULT_REDIS_SERVER);
    if (redis->server == NULL) {
        return NULL;
    }

    redis->password = string_null();
    if (redis->password == NULL) {
        return NULL;
    }

    redis->port = NPROXY_DEFAULT_REDIS_PORT;
    redis->db = 0;
    redis->timeout = 5;

    return redis;
}

static void
config_redis_deinit(struct config_redis *redis)
{
    string_deinit(redis->server);
    string_deinit(redis->password);
    np_free(redis);
}

static void 
config_destroy(struct config *cfg)
{
    if (cfg->args != NULL) {
        array_destroy(cfg->args);
    }

    if (cfg->server != NULL) {
        config_server_deinit(cfg->server);
    }
    
    if (cfg->log != NULL) {
        config_log_deinit(cfg->log);
    }

    if (cfg->redis != NULL) {
        config_redis_deinit(cfg->redis);
    }

    if (cfg != NULL) {
        np_free(cfg);
    }
}

static struct config *
config_init(char *filename)
{
    struct config *cfg;
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

    cfg->args = array_create(CONFIG_ARGS_LENGTH, sizeof(np_string));
    if (cfg->args == NULL) {
        goto error;
    }

    cfg->server = config_server_init();
    if (cfg->server == NULL) {
        goto error;
    }

    cfg->log = config_log_init();
    if (cfg->log == NULL) {
        goto error;
    }
    

    cfg->redis = config_redis_init();
    if (cfg->redis == NULL) {
        goto error;
    }
    
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
config_end_parse(struct config *cfg)
{
    np_status_t status;
    bool done;

    done = false;
    do {
        status = config_event_next(cfg);
        if (status != NP_OK) {
            return status;
        }

        switch (cfg->event.type) {
        case YAML_STREAM_END_EVENT:
            done = true;
            break;

        case YAML_DOCUMENT_END_EVENT:
            break;

        default:
            NOT_REACHED();
        }

        config_event_done(cfg);
    } while (!done);

    config_yaml_destroy(cfg);

    return NP_OK;
}


static np_status_t
config_push_scalar(struct config *cfg)
{
    yaml_char *scalar;
    yaml_len scalar_len;
    np_string *data;

    scalar = cfg->event.data.scalar.value;
    scalar_len = cfg->event.data.scalar.length;
    
    data = string_create((char *)scalar);
    if (data == NULL) {
        return NP_ERROR;
    }
    
    array_push(cfg->args, data);

    log_debug("push: '%s'", scalar);

    return NP_OK;
    
}

static void
config_pop_scalar(struct config *cfg)
{
    np_string *data;
    data = array_pop(cfg->args);
    log_debug("pop '%s'", data->data);
    string_deinit(data);
}


static bool
config_parse_bool(char *str)
{
    if (strcmp(str, "true") == 0) {
        return true;
    } else if (strcmp(str, "false") == 0) {
        return false;
    } else {
        //what should be return?
        return -1;
    }
}


static np_status_t
config_parse_mapping(struct config *cfg, np_string *section, np_string *key, np_string *value)
{
    if (strcmp(section->data, "server") == 0) {
        if (strcmp(key->data, "listen") == 0) {
            string_copy(cfg->server->listen, value);
        } else if (strcmp(key->data, "port") == 0) {
            cfg->server->port = atoi(value->data);
        } else if (strcmp(key->data, "daemon") == 0) {
            cfg->server->daemon = config_parse_bool(value->data);
        } else if (strcmp(key->data, "pfile") == 0) {
            string_copy(cfg->server->pfile, value);
        } else if (strcmp(key->data, "redis_key") == 0) {
            string_copy(cfg->server->redis_key, value);  
        } else {
            log_error("Unknow token: '%s: %s' in [server]", key->data, value->data);
            return NP_ERROR;
        }
    } else if (strcmp(section->data, "log") == 0) {
        if (strcmp(key->data, "file") == 0) {
            string_copy(cfg->log->file, value);
        } else if (strcmp(key->data, "level") == 0) {
            string_copy(cfg->log->level, value);
        } else {
            log_error("Unknow token: '%s: %s' in [log]", key->data, value->data);
            return NP_ERROR;
        }
    } else if (strcmp(section->data, "redis") == 0) {
        if (strcmp(key->data, "server") == 0) {
            string_copy(cfg->redis->server, value);
        } else if (strcmp(key->data, "port") == 0) {
            cfg->redis->port = atoi(value->data);
        } else if (strcmp(key->data, "db") == 0) {
            cfg->redis->db = atoi(value->data);
        } else if (strcmp(key->data, "password") == 0) {
            string_copy(cfg->redis->password, value);
        } else if (strcmp(key->data, "timeout") == 0) {
            cfg->redis->timeout = atoi(value->data);
        } else {
            log_error("Unknow token: '%s: %s' in [redis]", key->data, value->data);
            return NP_ERROR;
        }
    } else {
        log_error("Unknown section '%s'", section->data);
        return NP_ERROR;
    }

    return NP_OK;
}

static np_status_t
config_parse_handler(struct config *cfg)
{
    np_status_t status;
    np_string *section;
    np_string *key;
    np_string *value;
    
    value = array_pop(cfg->args);
    key = array_pop(cfg->args);
    section = array_head(cfg->args);

    status = config_parse_mapping(cfg, section, key, value);
    if (status != NP_OK) {
        return status;
    }

    log_debug("section: %s, %s: %s\n",section->data, key->data, value->data);
    
    string_deinit(key);
    string_deinit(value);

    return NP_OK;
    
}

static np_status_t
config_parse_core(struct config *cfg)
{
    np_status_t status;
    bool done, leaf;
    yaml_char *section;

    status = config_event_next(cfg);
    if (status != NP_OK) {
        return status;
    }

    done = false;
    leaf = false;

    switch (cfg->event.type) {
        case YAML_MAPPING_END_EVENT:
            cfg->depth--;
            if (cfg->depth == 1) {
                config_pop_scalar(cfg);
            } else if (cfg->depth == 0) {
                done = true;
            }
            break;

        case YAML_MAPPING_START_EVENT:
            /*new section start*/
            cfg->depth++;
            break;

        case YAML_SEQUENCE_START_EVENT:
            cfg->seq = 1;
            break;

        case YAML_SEQUENCE_END_EVENT:
            cfg->seq = 0;
            break;

        case YAML_SCALAR_EVENT:

            if (cfg->seq) {
                /* TODO
                 * list options not yet support.
                 */
                break;
            }  

            status = config_push_scalar(cfg);
                if (status != NP_OK) {
                break;
            }
            
            if (cfg->depth == CONFIG_ROOT_DEPTH) {
                /* new section */
                section = cfg->event.data.scalar.value;
                //printf("section: %s\n", section);
                
            } else if (cfg->depth == CONFIG_MAX_DEPTH) {
                if (cfg->args->nelts == cfg->depth + 1) {
                    leaf = true;
                }
                /* evaluation section*/
                log_debug("array_lenth:%d depth:%d  data: %s",
                        cfg->args->nelts, cfg->depth, cfg->event.data.scalar.value);
            }
            break;
        
        default:
            NOT_REACHED();
            break;
    }

    config_event_done(cfg);

    if (done) {
        return NP_OK;
    }

    if (leaf) {
        status = config_parse_handler(cfg);
    }

    if (status != NP_OK) {
        return status; 
    }

    return config_parse_core(cfg);
}


void 
config_dump(struct config *cfg)
{

    log_notice("[Nproxy Config]");
    
    log_notice("server");
    log_notice("\t listen: %s", cfg->server->listen->data);
    log_notice("\t port: %d", cfg->server->port);
    log_notice("\t daemon: %d", cfg->server->daemon);
    log_notice("\t pfile: %s", cfg->server->pfile->data);
    log_notice("\t redis_key: %s", cfg->server->redis_key->data);


    log_notice("log");
    log_notice("\t file: %s", cfg->log->file->data);
    log_notice("\t level: %s", cfg->log->level->data);

    log_notice("redis");
    log_notice("\t server: %s", cfg->redis->server->data);
    log_notice("\t port: %d", cfg->redis->port);
    log_notice("\t db: %d", cfg->redis->db);
    log_notice("\t password: %s", cfg->redis->password->data);
    log_notice("\t timeout: %d", cfg->redis->timeout);

}

static np_status_t
config_parse(struct config *cfg)
{
    np_status_t status;
    
    status = config_begin_parse(cfg);
    if (status != NP_OK) {
        return status;
    }
    
    status = config_parse_core(cfg);
    if (status != NP_OK) {
        return status;
    }

    status = config_end_parse(cfg);
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



