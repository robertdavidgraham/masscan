#ifndef PROTO_ZEROACCESS_H
#define PROTO_ZEROACCESS_H
#include <time.h>
struct PreprocessedInfo;
struct Output;

unsigned
handle_zeroaccess(  struct Output *out, time_t timestamp, 
                    const unsigned char *px, unsigned length, 
                    struct PreprocessedInfo *parsed);

extern const unsigned char zeroaccess_getL[];
#define zeroaccess_getL_length 16


int
zeroaccess_selftest();

#endif
