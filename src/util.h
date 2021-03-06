#ifndef _NPROXY_UTIL_H_
#define _NPROXY_UTIL_H_

#include "core.h"

#define np_malloc(size)                                 \
    _np_malloc((size_t)(size), __FILE__, __LINE__)      

#define np_realloc(ptr, size)                           \
    _np_realloc(ptr, size, __FILE__, __LINE__)

#define np_free(ptr) do {                               \
    if (ptr != NULL) {                                  \
        _np_free(ptr, __FILE__, __LINE__);               \
    }                                                   \
} while(0)

#define np_memcpy(dest, src, size)                      \
    memcpy(dest, src, (size_t)(size))
            

#define np_assert(_x) do {                              \
    if (!(_x)) {                                        \
        _np_assert(#_x, __FILE__, __LINE__, 1);         \
    }                                                   \
} while (0)

#define NOT_REACHED() np_assert(0)

#define UNUSED(x) do {((void)(x));} while (0)

char *np_get_current_path(void);
char *np_get_absolute_path(char *filename);
void *_np_malloc(size_t size, const char *fname, int line);
void *_np_realloc(void *ptr, size_t size, const char *fname, int line);
void _np_free(void *ptr, const char *fname, int line);
void _np_assert(const char *cond, const char *file, int line, int panic);
int np_random(int max);
#endif

