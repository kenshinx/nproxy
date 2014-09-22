
#include <stdio.h>

#include "array.h"

np_array *
array_create(uint32_t n, size_t size)
{
    np_array *array;

    array = np_malloc(sizeof(*array));
    if (array == NULL) {
        return NULL;
    }

    array->elts = np_malloc(n * size);
    if (array->elts == NULL) {
        return NULL;
    } 

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;

    return array;
}

void 
array_destroy(np_array *array)
{
    if (array->elts != NULL) {
        np_free(array->elts);
    }   

    np_free(array);
}


void *
array_push(np_array *array, void *data)
{
    void *elt, *new;
    size_t size;


    if (array_is_full(array)) {
        size = array->size * array->nalloc;
        new = np_realloc(array->elts, size);
        if (new == NULL) {
            return NULL;
        }
        
        array->elts = new;
        array->nalloc *= 2;
    }

    elt = (uint8_t *)array->elts + (array->size * array->nelts);
    np_memcpy(elt, data, array->size);
    array->nelts++;
    
    return elt; 
}


void *
array_pop(np_array *array) 
{
    void *elt;
    if (array_is_empty(array)) {
        return NULL;
    }
    
    array->nelts--;
    elt = (uint8_t *)array->elts + (array->size * array->nelts);
    
    return elt;
}

void *
array_get(np_array *array, uint32_t idx)
{
    void *elt;
    if (array_is_empty(array)) {
        return NULL;
    }

    if (idx >= array->nelts) {
        return NULL;
    }

    elt = (uint8_t *)array->elts + (array->size * idx);

    return elt;
    
}


void *
array_head(np_array *array)
{
    if (array_is_empty(array)) {
        return NULL;
    }

    return array_get(array, array->nelts - 1);
}







