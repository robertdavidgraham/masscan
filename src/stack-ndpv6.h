#ifndef STACK_NDPV6_H
#define STACK_NDPV6_H
#include <stddef.h>
#include <time.h>
#include "stack-queue.h"
#include "ipv6address.h"
struct PreprocessedInfo;

int
stack_handle_ndpv6_neighbor_notification(
            ipaddress ip_me, ipaddress ip_them,
            const unsigned char *buf, size_t length,
            const unsigned char *mac_them,
            struct stack_t *stack);

int
stack_handle_neighbor_solicitation(struct stack_t *stack, struct PreprocessedInfo *parsed,  const unsigned char *px, size_t length);

#endif

