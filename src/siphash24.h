#ifndef SIPHASH24_H
#define SIPHASH24_H
#include <stdint.h>

uint64_t
siphash24(const void *in, size_t inlen, const uint64_t key[2]);

/**
 * Regression-test this module.
 * @return
 *      0 on success, a positive integer otherwise.
 */
int
siphash24_selftest(void);

#endif

