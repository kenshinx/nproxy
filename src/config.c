#include <stdio.h>
#include <unistd.h>

#include "config.h"

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
        fclose(fp);
        return NULL;
    }
    cfg->fname = filename;
    cfg->fp = fp;
    cfg->depth = 0;
    cfg->valid_parser = 0;
    cfg->valid_event = 0;
    cfg->valid_token = 0;

    log_debug("open config '%s'", filename);

    return cfg;
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
config_yaml_deinit(struct config *cfg)
{
    if (cfg->valid_parser) {
        yaml_parser_delete(&cfg->parser);
        cfg->valid_parser = 0;
    }
}

static np_status_t
config_begin_parse(struct config *cfg)
{
    np_status_t status;
    np_assert(cfg->depth == 0);

    status = config_yaml_init(cfg);
    if (status != NP_OK) {
        return status;
    }

    return NP_OK; 

}

static np_status_t
config_parse(struct config *cfg)
{
    np_status_t status;
    
    status = config_begin_parse(cfg);
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
    np_free(cfg);
    return NULL;

}



