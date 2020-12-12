#include "stack-src.h"

int is_myself(const struct stack_src_t *src, ipaddress ip, unsigned port)
{
    return is_my_ip(src, ip) && is_my_port(src, port);
}

int is_my_ip(const struct stack_src_t *src, ipaddress ip)
{
    switch (ip.version) {
    case 4:
        return src->ipv4.first <= ip.ipv4 && ip.ipv4 <= src->ipv4.last;
    case 6:
        return src->ipv6.first.hi == ip.ipv6.hi && src->ipv6.first.lo == ip.ipv6.lo;
    default:
        return 0;
    }
}

int is_my_port(const struct stack_src_t *src, unsigned port)
{
    return src->port.first <= port && port <= src->port.last;
}
