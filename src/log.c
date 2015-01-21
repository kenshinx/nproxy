#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <sys/time.h>

#include "core.h"
#include "log.h"

static struct logger logger;

static const char *LOG_LEVEL_MAP[] = {
    "DEBUG",
    "VERBOSE", 
    "INFO", 
    "NOTICE", 
    "WARN", 
    "ERROR", 
    "CRITICAL"
};

void 
log_init()
{
    struct logger *l = &logger;
    l->level = LOG_NOTICE;
    l->fname = NULL;
    l->fd = stdout;
}

int
log_update(int level, const char *fname)
{
    struct logger *l = &logger;
    np_status_t status;
    
    status = log_set_level(level);
    if (status != NP_OK) {
        return status;
    }

    l->fname = fname;
    
    if (fname == NULL || fname[0] == '\0') {
        l->fd = stdout;
    } else {
        l->fd = fopen(fname, "a");
        if (l->fd == NULL) {
            log_stderr("opening log file '%s' failed", fname);
            return NP_ERROR;
        }
    }
    
    return NP_OK;
}


void
log_detroy(void)
{
    struct logger *l = &logger;

    if (l->fd == NULL || l->fd == stdout) {
        return;
    }

    fclose(l->fd);
}

int
log_set_level(int level)
{
    struct logger *l = &logger;

    if (level < LOG_LEVEL_MIN || level > LOG_LEVEL_MAX) {
        return NP_ERROR;
    }

    l->level = level;

    return NP_OK;
}

void
log_level_to_text(int level, char *text)
{
    int max_level;
    max_level = string_array_length(LOG_LEVEL_MAP);
    if (level >= max_level) {
        return;
    }
    
    const char *temp = LOG_LEVEL_MAP[level];
    strcpy(text, temp);
}

int 
log_level_to_int(const char *text)
{
    int i, max_level;

    max_level = string_array_length(LOG_LEVEL_MAP);
    for (i = 0; i < max_level; i++) {
        if (strcmp(LOG_LEVEL_MAP[i], text) == 0) {
            return i;
        }
    }

    return LOG_UNDEFINED_LEVEL;  
    
}


void
_log(int level, const char *file, int line, const char *fmt, ...)
{
    struct logger *l = &logger;
    va_list args;
    char msg[LOG_MAX_LENGTH];
    int off;
    char buf[64];
    char level_text[15];

    if (level < l->level) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    off = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S.", localtime(&tv.tv_sec));
    //snprintf(buf+off,sizeof(buf)-off,"%03d",(int)tv.tv_usec/1000);

    log_level_to_text(level, level_text);
    fprintf(l->fd, "%d [%s] %s:%d (%s): %s\n", 
            (int)getpid(), buf, file, line, level_text, msg);
    fflush(l->fd);
}


void
_log_stream(FILE *stream, const char *fmt, ...)
{
    char msg[LOG_MAX_LENGTH];
    va_list args;
    
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    fprintf(stream, "%s\n", msg);
}

#ifdef LOG_TEST_MAIN

int
main()
{
    log_init(LOG_DEBUG, "");
    log_debug("This is debug message: from %s", "ken");
    exit(1); 
}

#endif

