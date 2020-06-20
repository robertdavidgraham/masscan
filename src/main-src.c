#include "main-src.h"

int is_myself(const struct Source *src, ipaddress ip, unsigned port)
{
    return is_my_ip(src, ip) && is_my_port(src, port);
}

int is_my_ip(const struct Source *src, ipaddress ip)
{
    switch (ip.version) {
    case 4:
        return src->ip.first <= ip.ipv4 && ip.ipv4 <= src->ip.last;
    case 6:
        return src->ipv6.first.hi == ip.ipv6.hi && src->ipv6.first.lo == ip.ipv6.lo;
    default:
        return 0;
    }
}

int is_my_port(const struct Source *src, unsigned port)
{
    return src->port.first <= port && port <= src->port.last;
}
