#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <sys/time.h>

#include "log.h"

static struct logger logger;

int
log_init(int level,const char *name)
{
    struct logger *l = &logger;
    l->level = level;
    l->name = name;
    if (name == NULL || name[0] == '\0') {
        l->fd = stdout;
    } else {
        l->fd = fopen(name, "a");
        if (l->fd == NULL) {
            log_stderr("opening log file '%s' failed", name);
            return -1;
        }
    }
    
    return 0;
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

void
log_set_level(int level)
{
    struct logger *l = &logger;
    l->level = level;
}

char *
log_level_to_text(int level)
{
    char *level_text;
    int max_level;
    const char *log_level_map[] = {"DEBUG",
                                   "VERBOSE", 
                                   "INFO", 
                                   "NOTICE", 
                                   "WARN", 
                                   "ERROR", 
                                   "CRITICAL"};
    
    max_level = string_array_length(log_level_map);
    if (level >= max_level) {
        return NULL;
    }
    
    const char *temp = log_level_map[level];
    level_text = malloc(strlen(temp) + 1);
    if (level_text == NULL) {
        return NULL;
    }
    strcpy(level_text, temp);
    return level_text;
}


void
_log(int level, const char *file, int line, const char *fmt, ...)
{
    struct logger *l = &logger;
    va_list args;
    char msg[LOG_MAX_LENGTH];
    int off;
    char buf[64];
    char *level_text;

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

    level_text = log_level_to_text(level);
    fprintf(l->fd, "%d [%s] %s:%d (%s): %s\n", 
            (int)getpid(), buf, file, line, level_text, msg);
    fflush(l->fd);
    np_free(level_text);
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

/*
int
main()
{
    log_init(LOG_DEBUG, "");
    log_debug("This is debug message: from %s", "ken");
    exit(1); 
}
*/
