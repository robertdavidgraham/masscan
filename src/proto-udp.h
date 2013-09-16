#ifndef PROTO_UDP_H
#define PROTO_UDP_H
struct PreprocessedInfo;
struct Output;

void handle_udp(struct Output *out, const unsigned char *px, unsigned length, struct PreprocessedInfo *parsed);

#endif
