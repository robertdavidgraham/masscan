#ifndef PROTO_ISAKMP_H
#define PROTO_ISAKMP_H

#include <stdint.h>
#include <stdlib.h>

unsigned isakmp_set_cookie(unsigned char *px, size_t length, uint64_t seqno);

#endif
