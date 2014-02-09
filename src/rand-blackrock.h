#ifndef RAND_BLACKROCK_H
#define RAND_BLACKROCK_H
#include <stdint.h>

struct BlackRock {
    uint64_t range;
    uint64_t a;
    uint64_t b;
    uint64_t seed;
    unsigned rounds;
    uint64_t a_bits;
    uint64_t a_mask;
    uint64_t b_bits;
    uint64_t b_mask;
};

/**
 * Initializes a structure for shuffling numbers within
 * a range.
 *
 * @param range
 *      The size of the range of numbers needing to be
 *      shuffled/randomized.
 */
void
blackrock_init(struct BlackRock *br, uint64_t range, uint64_t seed, unsigned rounds);
void
blackrock2_init(struct BlackRock *br, uint64_t range, uint64_t seed, unsigned rounds);

/**
 * Given a number within a range, produce a different number with
 * the same range. There is a 1-to-1 mapping between the two,
 * so when linearly incrementing through the range, the output
 * of this function won't repeat. In other words, encrypt the index variable.
 * @param br
 *      The randomization parameters created with 'blackrock_init()'
 * @param index
 *      An input within the specified range. We call it an 'index' variable
 *      because that's how we intend to use this function, shuffling a
 *      monotonically increasing index variable, but in truth, any sort
 *      of integer can be used. This must be within the 'range' specified
 *      during the call to blackrock_init(), or the results are undefined.
 * @return
 *      A one-to-one matching index that's in the same range.
 */
uint64_t
blackrock_shuffle(const struct BlackRock *br, uint64_t index);
uint64_t
blackrock2_shuffle(const struct BlackRock *br, uint64_t index);

/**
 * The reverse of the shuffle function above: given the shuffled/ecnrypted
 * integer, return the original index value before the shuffling/encryption.
 */
uint64_t
blackrock_unshuffle(const struct BlackRock *br, uint64_t m);
uint64_t
blackrock2_unshuffle(const struct BlackRock *br, uint64_t m);


/**
 * Do a regression test.
 * @return
 *      0 of the regression test succeeds or non-zero if it fails
 */
int
blackrock_selftest(void);
int
blackrock2_selftest(void);

/**
 * Do a benchmark of this module regression test.
 */
void
blackrock_benchmark(unsigned rounds);
void
blackrock2_benchmark(unsigned rounds);

#endif
