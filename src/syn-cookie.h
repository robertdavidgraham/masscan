#ifndef SYN_COOKIE_H
#define SYN_COOKIE_H
#include <stdint.h>

/**
 * Create a hash of the src/dst IP/port combination. This allows us to match
 * incoming responses with their original requests
 */
uint64_t
syn_cookie( unsigned ip_dst, unsigned port_dst,
            unsigned ip_src, unsigned port_src,
            uint64_t entropy);


/**
 * Called on startup to set a secret key
 */
uint64_t get_entropy(void);


#endif
