#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H
#include "rte-ring.h"
#include <limits.h>

typedef struct rte_ring PACKET_QUEUE;

struct PacketBuffer {
    size_t length;
    unsigned char px[2040];
};


#endif
