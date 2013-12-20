#ifndef PROTO_ICMP_H
#define PROTO_ICMP_H
#include <time.h>
struct PreprocessedInfo;
struct Output;

void handle_icmp(struct Output *out, time_t timestamp,
    const unsigned char *px, unsigned length, struct PreprocessedInfo *parsed);

#endif
