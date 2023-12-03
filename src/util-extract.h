#ifndef UTIL_EXTRACT_H
#define UTIL_EXTRACT_H
#include <stdio.h>

struct ebuf_t {
    const unsigned char *buf;
    size_t offset;
    size_t max;
};

enum {
    EBUF_BE,
    EBUG_LE,
};

unsigned char e_next_byte(struct ebuf_t *ebuf);
unsigned short e_next_short16(struct ebuf_t *ebuf, int endian);
unsigned e_next_int32(struct ebuf_t *ebuf, int endian);
unsigned long long e_next_long64(struct ebuf_t *ebuf, int endian);


#endif
