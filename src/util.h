#ifndef _NPROXY_UTIL_H_
#define _NPROXY_UTIL_H_

#define np_malloc(size)                                 \
    _np_malloc((size_t)(size), __FILE__, __LINE__)      

#define np_free(ptr)                                    \
    _np_free(ptr, __FILE__, __LINE__)      


#define np_assert(_x) do {                         \
    if (!(_x)) {                                \
        _np_assert(#_x, __FILE__, __LINE__, 1);  \
    }                                           \
} while (0)


char *np_get_current_path(void);
char *np_get_absolute_path(char *filename);
int string_array_length(char *arr[]);
void *_np_malloc(size_t size, const char *fname, int line);
void _np_free(void *ptr, const char *fname, int line);
void _np_assert(const char *cond, const char *file, int line, int panic);

#endif

