#ifndef _NPROXY_ARRAY_H_
#define _NPROXY_ARRAY_H_

#define array_is_empty(array)                   \
    ((array->nelts) == 0)

#define array_is_full(array)                    \
    ((array->nelts) == (array->nalloc))

typedef void (*array_each_func)(void *);

typedef struct np_array_s {
    void        *elts;
    uint32_t    nelts;
    uint32_t    nalloc;
    size_t      size;
} np_array;

np_array *array_create(uint32_t n, size_t size);

void array_destroy(np_array *array);

void *array_push(np_array *array, void *data);

void *array_pop(np_array *array);

void *array_head(np_array *array);

void *array_get(np_array *array, uint32_t idx);

void array_each(np_array *array, array_each_func func);


static inline void
array_init(np_array *array) {
    array->elts = NULL;
    array->nelts = 0;
    array->nalloc = 0;
    array->size = 0;
}

#endif
