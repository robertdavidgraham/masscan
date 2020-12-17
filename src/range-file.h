/*
    massip-parse

    This module parses IPv4 and IPv6 addresses.

    It's not a typical parser. It's optimized around parsing large files
    containing millions of addresses using a "state-machine parser".
*/
#ifndef MASSIP_PARSE_H
#define MASSIP_PARSE_H
#include "ipv6address.h"

struct RangeList;
struct Range6List;
struct Range;
struct Range6;

/**
 * Parse a file, extracting all the IPv4 and IPv6 addresses and ranges.
 * This is optimized for speed, handling millions of entries in under
 * a second. This is especially tuned for IPv6 addresses, as while IPv4
 * scanning is mostly done with target rnages, IPv6 scanning is mostly
 * done with huge lists of target addresses.
 * @param filename
 *      The name of the file that we'll open, parse, and close.
 * @param targets_ipv4
 *      The list of IPv4 targets that we append any IPv4 addresses to.
 * @param targets_ipv6
 *      The list of IPv6 targets that we append any IPv6 addresses/ranges to.
 * @return 
        0 on success, any other number on failure.
 */
int
massip_parse_file(const char *filename, struct RangeList *targets_ipv4, struct Range6List *targets_ipv6);


enum RangeParseResult {
    Bad_Address,
    Ipv4_Address=4,
    Ipv6_Address=6,
};

/**
 * Parse the next IPv4/IPv6 range from a string.
 */
enum RangeParseResult
massip_parse_range(const char *line, size_t *inout_offset, size_t max, struct Range *ipv4, struct Range6 *ipv6);

/**
 * Parse a single IPv6 address.
 */
ipv6address
massip_parse_ipv6(const char *buf);


int
massip_selftest(void);

#endif

