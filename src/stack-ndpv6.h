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

int
stack_ndpv6_resolve(struct Adapter *adapter, 
    const unsigned char *my_mac_address, 
    unsigned char *your_mac_address);

#endif

