#ifndef PROTO_TCP_TRANSMIT_H
#define PROTO_TCP_TRANSMIT_H

struct TCP_Control_Block;

enum {
    XMIT_STATIC=1,
    XMIT_DYNAMIC=2,
};

void
tcp_add_xmit(struct TCP_Control_Block *tcb, const void *data, size_t length, int type);

#endif