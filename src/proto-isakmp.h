#ifndef PROTO_ISAKMP_H
#define PROTO_ISAKMP_H
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
struct Output;
struct PreprocessedInfo;

unsigned isakmp_parse(struct Output *out, time_t timestamp,
    const unsigned char *px, unsigned length,
    struct PreprocessedInfo *parsed, uint64_t entropy);

unsigned isakmp_set_cookie(unsigned char *px, size_t length, uint64_t seqno);

int
proto_isakmp_selftest(void);

#endif
