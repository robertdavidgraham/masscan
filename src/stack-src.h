#ifndef STACK_SOURCE_H
#define STACK_SOURCE_H
#include "massip-addr.h"

/**
 * These the source IP addresses that we'll be spoofing. IP addresses
 * and port numbers come from this list.
 */
struct stack_src_t
{
    struct {
        unsigned first;
        unsigned last;
        unsigned range;
    } ipv4;
    struct {
        unsigned first;
        unsigned last;
        unsigned range;
    } port;
 
    struct {
        ipv6address first;
        ipv6address last;
        unsigned range;
    } ipv6;
};

int is_myself(const struct stack_src_t *src, ipaddress ip, unsigned port);
int is_my_ip(const struct stack_src_t *src, ipaddress ip);
int is_my_port(const struct stack_src_t *src, unsigned ip);



#endif
