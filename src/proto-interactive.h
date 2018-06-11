#ifndef PROTO_INTERACTIVE_H
#define PROTO_INTERACTIVE_H
#include <stdio.h>

struct InteractiveData {
    const void *m_payload;
    unsigned m_length;
    unsigned is_payload_dynamic:1;
};
enum {
    TCPTRAN_DYNAMIC = 0x0001,
};
void
tcp_transmit(struct InteractiveData *more, const void *data, size_t length, unsigned flags);

#endif
