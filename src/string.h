#ifndef _NPROXY_STRING_H_
#define _NPROXY_STRING_H_

#include <stdbool.h>
#include <sys/types.h>
#include <stdint.h>

#include "core.h"

typedef struct np_string {
    uint32_t    len;
    char        *data;
} np_string;

#define np_string(_str, _len) {(uint32_t)(_len), (char *)(_str)}


np_string *string_create(const char *data);

np_string *string_create_with_len(const char *data, uint32_t len);

np_string *string_null(void);

void string_destroy(np_string *str);

bool string_compare(np_string *str1, np_string *str2);

int string_copy(np_string *dst, np_string *src);



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
