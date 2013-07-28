#ifndef RAND_LCG_H
#define RAND_LCG_H
#include <stdint.h>

/**
 * @return
 *      1 on failure
 *      0 on success
 */
int randlcg_selftest();


void
lcg_calculate_constants(uint64_t m, uint64_t *out_a, uint64_t *out_c, int is_debug);

uint64_t
lcg_rand(uint64_t index, uint64_t a, uint64_t c, uint64_t range);

int
lcg_selftest();

#endif
