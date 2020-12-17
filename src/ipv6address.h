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
static inline int ipv6address_is_invalid(ipv6address a) {
    return a.hi == ~0ULL && a.lo == ~0ULL;
}
static inline int ipv6address_is_equal(ipv6address a, ipv6address b) {
    return a.hi == b.hi && a.lo == b.lo;
}

static inline ipv6address ipv6address_from_bytes(const unsigned char *buf) {
    ipv6address addr;
    addr.hi = (uint64_t)buf[ 0] << 56
            | (uint64_t)buf[ 1] << 48
            | (uint64_t)buf[ 2] << 40
            | (uint64_t)buf[ 3] << 32
            | (uint64_t)buf[ 4] << 24
            | (uint64_t)buf[ 5] << 16
            | (uint64_t)buf[ 6] <<  8
            | (uint64_t)buf[ 7] <<  0;
    addr.lo = (uint64_t)buf[ 8] << 56
            | (uint64_t)buf[ 9] << 48
            | (uint64_t)buf[10] << 40
            | (uint64_t)buf[11] << 32
            | (uint64_t)buf[12] << 24
            | (uint64_t)buf[13] << 16
            | (uint64_t)buf[14] <<  8
            | (uint64_t)buf[15] <<  0;
    return addr;
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
