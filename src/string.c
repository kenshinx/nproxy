
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>

#include "core.h"
#include "string.h"

np_string *
string_create(const char *data)
{
    size_t len = (data == NULL) ? 0 : strlen(data);
    return string_create_with_len(data, (uint32_t)len);
}

np_string *
string_create_with_len(const char *data, uint32_t len)
{
    np_string *str;

    str = np_malloc(sizeof(*str));
    if (str == NULL) {
        return NULL;
    }

    str->len = len;
    
    str->data = np_malloc(len + 1);
    if (str->data == NULL) {
        return NULL;
    }
    strcpy(str->data, data);

    return str; 
}

void
string_update(np_string *str, const char *data)
{
    str->len = (uint32_t)strlen(data);
    str->data = np_realloc(str->data, str->len + 1);
    np_memcpy(str->data, data, str->len + 1);
}


void 
string_destroy(np_string *str)
{
    np_assert(str != NULL);

    if (str->data != NULL) {
        np_free(str->data);
    }

    np_free(str);
}

bool
string_compare(np_string *str1, np_string *str2)
{
    np_assert(str1 != NULL);
    np_assert(str2 != NULL);

    if (str1->len != str2->len) {
        return false;
    }

    if (strcmp(str1->data, str2->data) != 0) {
        return false;
    }

    return true;
}


np_string *
string_null(void)
{
    np_string *str;
    
    str = np_malloc(sizeof(*str));
    if (str == NULL) {
        return NULL;
    }

    str->len = 0;
    str->data = NULL;

    return str;
}

np_status_t
string_copy(np_string *dst, np_string *src)
{
    dst->data = np_realloc(dst->data, src->len + 1);
    if (dst->data == NULL) {
        return NP_ERROR;
    }
    
    memcpy(dst->data, src->data, src->len);
    dst->data[src->len] = '\0';
    dst->len = src->len;

    return NP_OK;
}

int 
string_array_length(const char *arr[])
{
    int count = 0;
    while (arr[count] != NULL) {
        count++;
    }
    return count;
}

