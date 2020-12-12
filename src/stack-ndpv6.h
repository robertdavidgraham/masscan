#ifndef STACK_NDPV6_H
#define STACK_NDPV6_H
#include <stddef.h>
#include <time.h>
#include "packet-queue.h"
#include "ipv6address.h"
struct PreprocessedInfo;

int
stack_handle_ndpv6_neighbor_notification(
            ipaddress ip_me, ipaddress ip_them,
            const unsigned char *buf, size_t length,
            const unsigned char *mac_them,
            struct stack_t *stack);

#endif

