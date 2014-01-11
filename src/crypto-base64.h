#ifndef CRYPTO_BASE64_H
#define CRYPTO_BASE64_H
#include <stdio.h>

size_t base64_decode(void *dst, size_t sizeof_dst, const void *src, size_t sizeof_src);
size_t base64_encode(void *dst, size_t sizeof_dst, const void *src, size_t sizeof_src);

int base64_selftest(void);

#endif
