#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H
#include "rte-ring.h"
#include <limits.h>
struct stack_src_t;

typedef struct rte_ring PACKET_QUEUE;

struct PacketBuffer {
    size_t length;
    unsigned char px[2040];
};

struct stack_t {
    PACKET_QUEUE *packet_buffers;
    PACKET_QUEUE *transmit_queue;
    const unsigned char *mac_address;
    struct stack_src_t *src;
};


#endif
