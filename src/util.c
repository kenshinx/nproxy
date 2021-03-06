#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <assert.h>

#include "core.h"
#include "util.h"

char *
np_get_current_path(void)
{
    char *cwd;
    if ((cwd = malloc(1024)) == NULL) {
        return NULL;
    }
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        return cwd;
    }
    else {
        return NULL;
    }
}

char *
np_get_absolute_path(char *filename)
{
    //char buf[PATH_MAX + 1];
    char *buf;
    if ((buf = malloc(PATH_MAX + 1)) == NULL) {
        return NULL;
    }
    
    char *exists = realpath(filename, buf);
    if (exists) {
        return buf;
    } else {
        return NULL;
    }
}

void *
_np_malloc(size_t size, const char *fname, int line)
{
    void *ptr;

    np_assert(size != 0);
    ptr = malloc(size);
    if (ptr == NULL) {
        log_error("malloc(%zu) failed at %p @ %s:%d", size, ptr, fname, line);
    }

    return ptr;
}

void *
_np_realloc(void *ptr, size_t size, const char *fname, int line)
{
    void *p;
    
    p = realloc(ptr, size);
    if (p == NULL) {
        log_error("realloc(%zu) failed @ %s:%d", size, fname, line);
    }
    
    return p;
}


void
_np_free(void *ptr, const char *fname, int line)
{
    np_assert(ptr != NULL);
    log_debug("free(%p) @ %s:%d", ptr, fname, line);
    free(ptr);
    ptr = NULL;
}

void
_np_assert(const char *cond, const char *file, int line, int panic)
{
    log_error("assert '%s' failed @ (%s, %d)", cond, file, line);
    if (panic) {
        //nc_stacktrace(1);
        abort();
    }
}

int 
np_random(int max)
{
    srand(time(NULL));
    return rand() % max;
}

