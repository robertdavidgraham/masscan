/*
    BlackRock cipher

    (h/t Marsh Ray @marshray for this idea)

    This is a randomization/reshuffling function based on a crypto
    "Feistal network" as describ ed in the paper:

    'Ciphers with Arbitrary Finite Domains' 
        by John Black and Phillip Rogaway 
        http://www.cs.ucdavis.edu/~rogaway/papers/subset.pdf

    This is a crypto-like construction that encrypts an arbitrary sized
    range. Given a number in the range [0..9999], it'll produce a mapping 
    to a distinct different number in the same range (and back again).
    In other words, it randomizes the order of numbers in a sequence.

    For example, it can be used to  randomize the sequence [0..9]:
    
     0 ->      6
     1 ->      4
     2 ->      8
     3 ->      1
     4 ->      9
     5 ->      3
     6 ->      0
     7 ->      5
     8 ->      2
     9 ->      7

    As you can see on the right hand side, the numbers are in random
    order, and they don't repeaet.

    This is create for port scanning. We can take an index variable
    and increment it during a scan, then use this function to
    randomize it, yet be assured that we've probed every IP and port
    within the range.

    The cryptographic strength of this construction depends upon the 
    number of rounds, and the exact nature of the inner "F()" function.
    Because it's a Feistal network, that "F()" function can be almost
    anything.

    We don't care about cryptographic strength, just speed, so we are
    using a trivial F() function.

    This is a class of "format-preserving encryption". There are 
    probably better constructions than what I'm using.
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>

#if defined(_MSC_VER)
#define inline _inline
#endif

struct BlackRock {
    uint64_t range;
    uint64_t a;
    uint64_t b;
    unsigned rounds;
};


/***************************************************************************
 ***************************************************************************/
void
blackrock_init(struct BlackRock *br, uint64_t range)
{
    double foo = sqrt(range * 1.0);

    br->range = range;
    br->a = (uint64_t)(foo - 1);
    br->b = (uint64_t)(foo + 1);

    while (br->a * br->b <= range)
        br->b++;

    br->rounds = 3;
}


/***************************************************************************
 ***************************************************************************/
uint64_t
F(uint64_t j, uint64_t R)
{
    static const uint64_t primes[] = {
        961752031, 982324657, 15485843, 961752031,  };

    R = (R << (R&0x4)) + R;

    /* some random and meaningless function */
    return (((primes[j] * R + 25ULL) ^ R) + j);
}


/***************************************************************************
 *
 * NOTE:
 *  the names in this function are cryptic in order to match as closely
 *  as possible the pseudocode in the following paper:
 *      http://www.cs.ucdavis.edu/~rogaway/papers/subset.pdf
 ***************************************************************************/
static inline uint64_t
fe(unsigned r, uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t L, R;
    unsigned j;
    uint64_t tmp;

    L = m % a;
    R = m / a;
    
    for (j=1; j<=r; j++) {
        if (j & 1) {
            tmp = (L + F(j, R)) % a;
        } else {
            tmp = (L + F(j, R)) % b;
        }
        L = R;
        R = tmp;
    }
    if (r & 1) {
        return a * L + R;
    } else {
        return a * R + L;
    }
}

/***************************************************************************
 ***************************************************************************/
uint64_t
blackrock_shuffle(const struct BlackRock *br, uint64_t m)
{
    uint64_t c;

    c = fe(br->rounds, br->a, br->b, m);
    while (c >= br->range)
        c = fe(br->rounds, br->a, br->b,  c);

    return c;
}

/***************************************************************************
 ***************************************************************************/
static unsigned
blackrock_verify(struct BlackRock *br, uint64_t max)
{
    unsigned char *list;
    uint64_t i;
    unsigned is_success = 1;
    uint64_t range = br->range;

    /* Allocate a list of 1-byte counters */
    list = (unsigned char *)malloc((size_t)((range<max)?range:max));
    memset(list, 0, (size_t)((range<max)?range:max));

    /* For all numbers in the range, verify increment the counter for the
     * the output. */
    for (i=0; i<range; i++) {
        uint64_t x = blackrock_shuffle(br, i);
        if (x < max)
            list[x]++;
    }

    /* Now check the output to make sure that every counter is set exactly
     * to the value of '1'. */
    for (i=0; i<max && i<range; i++) {
        if (list[i] != 1)
            is_success = 0;
    }

    free(list);

    return is_success;
}

/***************************************************************************
 ***************************************************************************/
int
blackrock_selftest()
{
    unsigned i;
    int is_success = 0;
    uint64_t range;


    range = 3015 * 3;

    for (i=0; i<5; i++) {
        struct BlackRock br;

        range += 10 + i;
        range *= 2;

        blackrock_init(&br, range);

        is_success = blackrock_verify(&br, range);

        if (!is_success) {
            fprintf(stderr, "BLACKROCK: randomization failed\n");
            return 1; /*fail*/
        }
    }

    return 0; /*success*/
}
