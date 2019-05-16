/*
 Other IP protocol (not TCP, UDP, TCP, ICMP
 Specificaly for scanning things like GRE.
 */
#ifndef PROTO_OPROTO_H
#define PROTO_OPROTO_H
#include <stdint.h>
#include <time.h>
struct Output;
struct PreprocessedInfo;


/**
 * Parse an incoming response.
 * @param entropy
 *      The random seed, used in calculating syn-cookies.
 */
void
handle_oproto(struct Output *out, time_t timestamp,
           const unsigned char *px, unsigned length,
           struct PreprocessedInfo *parsed,
           uint64_t entropy);

#endif

