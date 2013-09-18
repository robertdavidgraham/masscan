#ifndef PROTO_HTTP_H
#define PROTO_HTTP_H
#include "proto-banner1.h"


void
http_init(struct Banner1 *b);

unsigned
banner_http(  struct Banner1 *banner1,
        unsigned state,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max);

#endif

