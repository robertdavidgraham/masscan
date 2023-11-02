/*
    Calculates Internet checksums for protocols like TCP/IP.

    Author: Robert David Graham
    Copyright: 2020
    License: The MIT License (MIT)
    Dependencies: none
*/
#ifndef UTIL_CHECKSUM_H
#define UTIL_CHECKSUM_H
#include <stddef.h>

/**
 * Calculate a checksum for IPv4 packets.
 * @param ip_src
 *      The source IPv4 address, represented a standard way,
 *      as a 32-bit integer in host byte order.
 * @param ip_dst
 *      The destination IPv4 address, represented as a 32-bit integer in host byte order.
 * @param ip_proto
 *      A value of 6 for TCP or 17 for UDP.
 * @param payload_length
 *      The length of the IP packet payload, meaning, everything after the IPv4 header.
 *      In other words, it's the "total length" field of the IP packet minus the
 *      length of the IP header.
 * @param payload
 *      A pointer to the aforementioned payload (a pointer to the first byte past the
 *      IP header). Note that the calculation skips the checksum field, so the payload
 *      we use is everything but the 2 bytes in the checksum field. Thus, due to the 
 *      quirkiness of Internet protocols, the result of this calculation should end
 *      up equally the value of the checksum field.
 * @return
 *      the calculated checksum, which should equal the checksum found in the payload
 */
unsigned 
checksum_ipv4(unsigned ip_src, unsigned ip_dst, unsigned ip_proto, size_t payload_length, const void *payload);

unsigned 
checksum_ipv6(const unsigned char *ip_src, const unsigned char *ip_dst, unsigned ip_proto, size_t payload_length, const void *payload);


/**
 * Simple unit tests.
 * @return
 *      1 if failure, 0 if success
 */
int checksum_selftest(void);

#endif
