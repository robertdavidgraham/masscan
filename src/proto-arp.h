#ifndef PROTO_ARP_H
#define PROTO_ARP_H

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
        struct rte_ring *packet_buffers,
        struct rte_ring *transmit_queue);

#endif
