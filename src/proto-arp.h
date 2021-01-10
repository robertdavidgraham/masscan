#ifndef PROTO_ARP_H
#define PROTO_ARP_H
#include <time.h>
#include "stack-queue.h"
#include "massip-addr.h"
struct Output;
struct PreprocessedInfo;

/**
 * Response to an ARP request for our IP address.
 *
 * @param my_ip
 *      My IP address
 * @param my_mac
 *      My Ethernet MAC address that matches this IP address.
 * @param px
 *      The incoming ARP request
 * @param length
 *      The length of the incoming ARP request.
 * @param packet_buffers
 *      Free packet buffers I can use to format the request
 * @param transmit_queue
 *      I put the formatted response onto this queue for later
 *      transmission by a transmit thread.
 */
int stack_handle_arp(struct stack_t *stack,
        unsigned my_ip, const unsigned char *my_mac,
        const unsigned char *px, unsigned length);




void
arp_recv_response(struct Output *out, time_t timestamp, const unsigned char *px, unsigned length, struct PreprocessedInfo *parsed);

#endif
