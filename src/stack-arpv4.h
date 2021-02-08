#ifndef STACK_ARP_H
#define STACK_ARP_H
struct Adapter;
#include "stack-queue.h"
#include "massip-addr.h"

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
int stack_arp_incoming_request(struct stack_t *stack,
        ipv4address_t my_ip, macaddress_t my_mac,
        const unsigned char *px, unsigned length);

/**
 * Send an ARP request in order to resolve an IPv4 address into a
 * MAC address. Usually done in order to find the local router's 
 * MAC address when given the IPv4 address of the router.
 */
int stack_arp_resolve(struct Adapter *adapter,
    ipv4address_t my_ipv4, macaddress_t my_mac_address,
    ipv4address_t your_ipv4, macaddress_t *your_mac_address);

#endif
