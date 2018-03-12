#ifndef PROTO_UDP_H
#define PROTO_UDP_H
#include <time.h>
#include <stdint.h>
struct PreprocessedInfo;
struct Output;

/**
 * Parse an incoming UDP response. We parse the basics, then hand it off
 * to a protocol parser (SNMP, NetBIOS, NTP, etc.)
 * @param entropy
 *      The random seed, used in calculating syn-cookies.
 */
void 
handle_udp(struct Output *out, time_t timestamp,
    const unsigned char *px, unsigned length,
    struct PreprocessedInfo *parsed,
    uint64_t entropy);

/**
 * Default banner for UDP, consisting of the first 64 bytes, when it isn't
 * detected as the appropriate protocol
 */
unsigned
default_udp_parse(struct Output *out, time_t timestamp,
                  const unsigned char *px, unsigned length,
                  struct PreprocessedInfo *parsed,
                  uint64_t entropy);


#endif
