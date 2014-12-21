#ifndef PROTO_STREAM_DEFAULT_H
#define PROTO_STREAM_DEFAULT_H
#include "proto-banner1.h"

void
default_set_parameter(
        const struct Banner1 *banner1,
        struct ProtocolParserStream *self,
        const char *name,
        size_t value_length,
        const void *value);

void 
default_hello(const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *stream_state,
        struct TCP_Control_Block *tcb);

extern const struct ProtocolParserStream banner_default;


#endif
