/*
    Simple module for handling addresses (IPv6, IPv4, MAC).
    Also implements a 128-bit type for dealing with addresses.
 
    This is the module that almost all the other code depends
    upon, because everything else deals with the IP address
    types defined here.
    
*/
#ifndef MASSIP_ADDR_H
#define MASSIP_ADDR_H
#include <stdint.h>
#include <stddef.h>

#if defined(_MSC_VER) && !defined(inline)
#define inline __inline
#endif
#if defined(_MSC_VER)
#pragma warning(disable: 4201)
#endif

/**
 * An IPv6 address is represented as two 64-bit integers instead of a single
 * 128-bit integer. This is because currently (year 2020) most compilers
 * do not support the `uint128_t` type, but all relevant ones do support
 * the `uint64_t` type.
 */
struct ipv6address {uint64_t hi; uint64_t lo;};
typedef struct ipv6address ipv6address;
typedef struct ipv6address ipv6address_t;

/**
 * IPv4 addresses are represented simply with an integer.
 */
typedef unsigned ipv4address;
typedef ipv4address ipv4address_t;

/**
 * MAC address (layer 2).  Since we have canonical types for IPv4/IPv6
 * addresses, we may as well have a canonical type for MAC addresses,
 * too.
 */
struct macaddress_t {unsigned char addr[6];};
typedef struct macaddress_t macaddress_t;

/**
 * In many cases we need to do arithmetic on IPv6 addresses, treating
 * them as a large 128-bit integer. Thus, we declare our own 128-bit
 * integer type (and some accompanying math functions). But it's
 * still just the same as a 128-bit integer.
 */
typedef ipv6address massint128_t;


/**
 * Most of the code in this project is agnostic to the version of IP
 * addresses (IPv4 or IPv6). Therefore, we represent them as a union
 * distinguished by a version number. The `version` is an integer
 * with a value of either 4 or 6.
 */
struct ipaddress {
    union {
        unsigned ipv4;
        ipv6address ipv6;
    };
    unsigned char version;
};
typedef struct ipaddress ipaddress;

static inline int ipv6address_is_zero(ipv6address_t a) {
    return a.hi == 0 && a.lo == 0;
}
#define massint128_is_zero ipv6address_is_zero

static inline int ipv6address_is_invalid(ipv6address_t a) {
    return a.hi == ~0ULL && a.lo == ~0ULL;
}
static inline int ipv6address_is_equal(ipv6address_t a, ipv6address_t b) {
    return a.hi == b.hi && a.lo == b.lo;
}
static inline int ipv6address_is_lessthan(ipv6address_t a, ipv6address_t b) {
    return (a.hi == b.hi)?(a.lo < b.lo):(a.hi < b.hi);
}

int ipv6address_is_equal_prefixed(ipv6address_t lhs, ipv6address_t rhs, unsigned prefix);


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
static inline macaddress_t macaddress_from_bytes(const void *vbuf)
{
    const unsigned char *buf = (const unsigned char *)vbuf;
    macaddress_t result;
    result.addr[0] = buf[0];
    result.addr[1] = buf[1];
    result.addr[2] = buf[2];
    result.addr[3] = buf[3];
    result.addr[4] = buf[4];
    result.addr[5] = buf[5];
    return result;
}
static inline int macaddress_is_zero(macaddress_t mac)
{
    return mac.addr[0] == 0
    && mac.addr[1] == 0
    && mac.addr[2] == 0
    && mac.addr[3] == 0
    && mac.addr[4] == 0
    && mac.addr[5] == 0;
}
static inline int macaddress_is_equal(macaddress_t lhs, macaddress_t rhs)
{
    return lhs.addr[0] == rhs.addr[0]
    && lhs.addr[1] == rhs.addr[1]
    && lhs.addr[2] == rhs.addr[2]
    && lhs.addr[3] == rhs.addr[3]
    && lhs.addr[4] == rhs.addr[4]
    && lhs.addr[5] == rhs.addr[5];
}

/**
 * Return a buffer with the formatted address
 */
typedef struct ipaddress_formatted {
    char string[48];
} ipaddress_formatted_t;

struct ipaddress_formatted ipv6address_fmt(ipv6address a);
struct ipaddress_formatted ipv4address_fmt(ipv4address a);
struct ipaddress_formatted ipaddress_fmt(ipaddress a);
struct ipaddress_formatted macaddress_fmt(macaddress_t a);

unsigned massint128_bitcount(massint128_t num);

/**
 * @return 0 on success, 1 on failure
 */
int ipv6address_selftest(void);

#endif
