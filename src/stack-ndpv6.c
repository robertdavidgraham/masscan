#include "stack-ndpv6.h"

int
stack_handle_ndpv6_neighbor_notification(
            ipaddress ip_me, ipaddress ip_them,
            const unsigned char *buf, size_t length,
            const unsigned char *mac_them,
            struct stack_t *stack)
{
    return 0;
}
