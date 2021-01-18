/*
    IPv6 Neighbor Discovery Protocol
 
    This module is needed to talk to the local IPv6 router.
    It does two things:
 
    1. find the local router, so that we can send packets to
       it
    2. response to Neighbor Discovery Requests, to the router
       can find us
 */
#ifndef STACK_NDPV6_H
#define STACK_NDPV6_H
#include <stddef.h>
#include <time.h>
#include "stack-queue.h"
#include "massip-addr.h"
struct PreprocessedInfo;

/**
 * Handle an incoming IPv6 neighbor notification request. We must send
 * back our MAC address.
 */
int
stack_ndpv6_incoming_request(struct stack_t *stack, struct PreprocessedInfo *parsed,  const unsigned char *px, size_t length);

/**
 * Find the MAC address for the local router.
 */
int
stack_ndpv6_resolve(struct Adapter *adapter,
    ipv6address my_ipv6,
    macaddress_t my_mac_address,
    macaddress_t *your_mac_address);

#endif

