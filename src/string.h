#ifndef _NPROXY_STRING_H_
#define _NPROXY_STRING_H_

#include <sys/types.h>

typedef struct np_string {
    uint32_t len;
    uint8_t *data;
} np_string;


#endif
