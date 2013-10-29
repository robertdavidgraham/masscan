#ifndef RAND_LCG_H
#define RAND_LCG_H
#include <stdint.h>


void
lcg_calculate_constants(uint64_t m, uint64_t *out_a, uint64_t *inout_c, int is_debug);

uint64_t
lcg_rand(uint64_t index, uint64_t a, uint64_t c, uint64_t range);

/**
 * Performs a regression test on this module.
 * @return
 *      0 on success, or a positive integer on failure
 */
int
lcg_selftest(void);

#endif
