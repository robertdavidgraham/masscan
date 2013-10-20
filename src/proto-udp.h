#ifndef PROTO_UDP_H
#define PROTO_UDP_H
#include <time.h>
struct PreprocessedInfo;
struct Output;

void handle_udp(struct Output *out, time_t timestamp, const unsigned char *px, unsigned length, struct PreprocessedInfo *parsed);

#endif
