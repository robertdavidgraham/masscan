#ifndef PROTO_DNS_H
#define PROTO_DNS_H
#include <time.h>
struct PreprocessedInfo;
struct Output;

unsigned handle_dns(struct Output *out, time_t timestamp, const unsigned char *px, unsigned length, struct PreprocessedInfo *parsed);

#endif
