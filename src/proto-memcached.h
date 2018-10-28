#ifndef PROTO_MEMCACHED_H
#define PROTO_MEMCACHED_H
#include "proto-banner1.h"
struct Output;
struct PreprocessedInfo;

/*
 * For sending TCP requests and parsing TCP responses.
 */
extern const struct ProtocolParserStream banner_memcached;

/*
 * For parsing UDP responses
 */
unsigned
memcached_udp_parse(struct Output *out, time_t timestamp,
            const unsigned char *px, unsigned length,
            struct PreprocessedInfo *parsed,
            uint64_t entropy
            );

/* 
 * For creating UDP request
 */
unsigned
memcached_udp_set_cookie(unsigned char *px, size_t length, uint64_t seqno);

#endif
