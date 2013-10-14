#ifndef SIPHASH24_H
#define SIPHASH24_H

uint64_t
siphash24(const void *in, size_t inlen, uint64_t key[2]);

#endif

