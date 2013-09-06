#ifndef RAND_BLACKROCK_H
#define RAND_BLACKROCK_H
#include <stdint.h>

struct BlackRock {
    uint64_t range;
    uint64_t a;
    uint64_t b;
    unsigned rounds;
};

/**
 * Initializes a structure for shuffling numbers within
 * a range.
 *
 * @param range
 *      The size of the range of numbers needing to be
 *      shuffled/randomized.
 */
void blackrock_init(struct BlackRock *br, uint64_t range);

/**
 * Given a number within a range, produce a different number with
 * the same range. There is a 1-to-1 mapping between the two,
 * so when linearly incrementing through the range, the output
 * of this function won't repeat
 */
uint64_t blackrock_shuffle(const struct BlackRock *br, uint64_t index);

int blackrock_selftest();

#endif
