#include "main-src.h"

int is_myself(const struct Source *src, unsigned ip, unsigned port)
{
    return is_my_ip(src, ip) && is_my_port(src, port);
}

int is_my_ip(const struct Source *src, unsigned ip)
{
    return src->ip.first <= ip && ip <= src->ip.last;
}

int is_my_port(const struct Source *src, unsigned port)
{
    return src->port.first <= port && port <= src->port.last;
}
