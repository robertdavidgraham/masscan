#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H
#include "rte-ring.h"
#include "massip-addr.h"
#include <limits.h>
struct stack_src_t;
struct Adapter;

typedef struct rte_ring PACKET_QUEUE;

struct PacketBuffer {
    size_t length;
    unsigned char px[2040];
};

struct stack_t {
    PACKET_QUEUE *packet_buffers;
    PACKET_QUEUE *transmit_queue;
    macaddress_t source_mac;
    struct stack_src_t *src;
};

/**
 * Get a packet-buffer that we can use to create a packet before
 * sending
 */
struct PacketBuffer *
stack_get_packetbuffer(struct stack_t *stack);

/**
 * Queue up the packet for sending. This doesn't send the packet immediately,
 * but puts it into a queue to be sent later, when the throttler allows it
 * to be sent.
 */
void
stack_transmit_packetbuffer(struct stack_t *stack, struct PacketBuffer *response);

void
stack_flush_packets(
    struct stack_t *stack,
    struct Adapter *adapter,
    uint64_t *packets_sent,
    uint64_t *batchsize);

struct stack_t *
stack_create(macaddress_t source_mac, struct stack_src_t *src);

#endif
