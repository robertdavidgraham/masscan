#ifndef PROTO_HTTP_H
#define PROTO_HTTP_H
#include "proto-banner1.h"

extern struct Patterns http_fields[];


unsigned
banner_http(  struct Banner1 *banner1,
        unsigned state,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max);

#endif

