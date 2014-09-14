#include <unistd.h>
#include <limits.h>
#include <stdlib.h>

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

