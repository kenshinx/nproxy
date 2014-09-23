
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>

#include "core.h"
#include "string.h"

np_string *
string_create(const char *data)
{
    np_string *str;

    str = np_malloc(sizeof(*str));
    if (str == NULL) {
        return NULL;
    }

    str->len = strlen(data);
    
    str->data = np_malloc(str->len + 1);
    if (str->data == NULL) {
        return NULL;
    }
    strcpy(str->data, data);

    return str;
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
    np_assert(str1 != NULL)
    np_assert(str2 != NULL)

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
