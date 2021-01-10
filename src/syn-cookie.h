#ifndef SYN_COOKIE_H
#define SYN_COOKIE_H
#include <stdint.h>
#include "massip-addr.h"

/**
 * Create a hash of the src/dst IP/port combination. This allows us to match
 * incoming responses with their original requests
 */
uint64_t
syn_cookie_ipv4( unsigned ip_dst, unsigned port_dst,
            unsigned ip_src, unsigned port_src,
            uint64_t entropy);

uint64_t
syn_cookie( ipaddress ip_dst, unsigned port_dst,
            ipaddress ip_src, unsigned port_src,
            uint64_t entropy);

uint64_t
syn_cookie_ipv6( ipv6address ip_dst, unsigned port_dst,
            ipv6address ip_src, unsigned port_src,
            uint64_t entropy);


/**
 * Called on startup to set a secret key
 */
uint64_t get_entropy(void);


#endif
