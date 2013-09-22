#ifndef PROTO_NETBIOS_H
#define PROTO_NETBIOS_H

struct PreprocessedInfo;
struct Output;

unsigned handle_nbtstat(struct Output *out, const unsigned char *px, unsigned length, struct PreprocessedInfo *parsed);

#endif
