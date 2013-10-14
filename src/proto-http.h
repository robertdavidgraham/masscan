#ifndef PROTO_HTTP_H
#define PROTO_HTTP_H
#include "proto-banner1.h"

extern struct Banner1Stream banner_http;

unsigned
http_change_field(unsigned char **inout_header, unsigned header_length,
                    const char *field_name,
                    const unsigned char *field_value, unsigned field_value_len);

#endif

