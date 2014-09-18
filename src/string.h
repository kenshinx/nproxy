#ifndef _NPROXY_STRING_H_
#define _NPROXY_STRING_H_

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>

#include "util.h"

typedef struct np_string {
    uint32_t    len;
    char        *data;
} np_string;

#define np_string(_str) {sizeof(_str) - 1, (char *)(_str)}


np_string *string_create(const char *data);
np_string *string_null(void);
void string_destroy(np_string *str);
bool string_compare(np_string *str1, np_string *str2);



static inline void
string_init(np_string *str)
{
    str->len = 0;
    str->data = NULL;
}

static inline void
string_deinit(np_string *str)
{
    if (str->data != NULL) {
        np_free(str->data);
        string_init(str);
    }
}

#endif
