#ifndef PROTO_ARP_H
#define PROTO_ARP_H
#include "packet-queue.h"

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
int arp_response(
        unsigned my_ip, const unsigned char *my_mac, 
        const unsigned char *px, unsigned length, 
        PACKET_QUEUE *packet_buffers,
        PACKET_QUEUE *transmit_queue);

#endif
