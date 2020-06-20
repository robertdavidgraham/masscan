#ifndef MAIN_SRC_H
#define MAIN_SRC_H
#include "ipv6address.h"

/**
 * These the source IP addresses that we'll be spoofing. IP addresses
 * and port numbers come from this list.
 */
struct Source
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

int is_myself(const struct Source *src, ipaddress ip, unsigned port);
int is_my_ip(const struct Source *src, ipaddress ip);
//int is_my_ipv6(const struct Source *src, ipv6address ipv6);
int is_my_port(const struct Source *src, unsigned ip);



#endif
