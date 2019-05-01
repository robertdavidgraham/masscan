#ifndef PROTO_COAP_H
#define PROTO_COAP_H
#include "proto-banner1.h"
struct Output;
struct PreprocessedInfo;

/*
 * For sending TCP requests and parsing TCP responses.
 */
extern const struct ProtocolParserStream banner_coap;

/*
 * For parsing UDP responses
 */
unsigned
coap_handle_response(struct Output *out, time_t timestamp,
            const unsigned char *px, unsigned length,
            struct PreprocessedInfo *parsed,
            uint64_t entropy
            );

/* 
 * For creating UDP request
 */
unsigned
coap_udp_set_cookie(unsigned char *px, size_t length, uint64_t seqno);

int
proto_coap_selftest(void);

#endif
