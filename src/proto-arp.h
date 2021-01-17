#ifndef PROTO_ARP_H
#define PROTO_ARP_H
#include <time.h>
struct Output;
struct PreprocessedInfo;


void
arp_recv_response(struct Output *out, time_t timestamp, const unsigned char *px, unsigned length, struct PreprocessedInfo *parsed);

#endif
