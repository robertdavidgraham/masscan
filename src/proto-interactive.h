#ifndef PROTO_INTERACTIVE_H
#define PROTO_INTERACTIVE_H
#include <stdio.h>

struct InteractiveData {
    const void *payload;
    unsigned length;
};

void
tcp_transmit(struct InteractiveData *more, const void *data, size_t length);

#endif
