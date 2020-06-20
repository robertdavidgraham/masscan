/*
    Simple module that contains the IPv6 type (consisting of two 64-bit
    integers), and for pretty-printing the address.
*/
#ifndef IPV6ADDRESS_H
#define IPV6ADDRESS_H
#include <stdint.h>
#include <stddef.h>

#if defined(_MSC_VER) && !defined(inline)
#define inline __inline
#endif
#if defined(_MSC_VER)
#pragma warning(disable: 4201)
#endif

struct ipv6address {uint64_t hi; uint64_t lo;};
typedef struct ipv6address ipv6address;
typedef unsigned ipv4address;


struct ipaddress {
    union {
        unsigned ipv4;
        ipv6address ipv6;
    };
    unsigned char version;
};
typedef struct ipaddress ipaddress;

static inline int ipv6address_is_zero(ipv6address a) {
    return a.hi == 0 && a.lo == 0;
}
static inline int ipv6address_is_equal(ipv6address a, ipv6address b) {
    return a.hi == b.hi && a.lo == b.lo;
}

/**
 * Return a buffer with the formatted address
 */
struct ipaddress_formatted {
    char string[48];
};

struct ipaddress_formatted ipv6address_fmt(ipv6address a);
struct ipaddress_formatted ipaddress_fmt(ipaddress a);

/**
 * @return 0 on success, 1 on failure
 */
int ipv6address_selftest(void);

#endif
