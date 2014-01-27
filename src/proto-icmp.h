#ifndef PROTO_ICMP_H
#define PROTO_ICMP_H
#include <time.h>
#include <stdint.h>
struct PreprocessedInfo;
struct Output;

void handle_icmp(struct Output *out, time_t timestamp,
        const unsigned char *px, unsigned length, 
        struct PreprocessedInfo *parsed,
        uint64_t entropy);

#endif
