/*
    BlackRock cipher

    (h/t Marsh Ray @marshray for this idea)

    This is a randomization/reshuffling function based on a crypto
    "Feistel network" as describ ed in the paper:

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
    number of rounds, and the exact nature of the inner "READ()" function.
    Because it's a Feistel network, that "READ()" function can be almost
    anything.

    We don't care about cryptographic strength, just speed, so we are
    using a trivial READ() function.

    This is a class of "format-preserving encryption". There are
    probably better constructions than what I'm using.
*/
#include "rand-blackrock.h"
#include "pixie-timer.h"
#include "util-malloc.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>
#include <time.h>

#if defined(_MSC_VER)
#define inline _inline
#endif

/***************************************************************************
 * It's an s-box. You gotta have an s-box
 ***************************************************************************/
const unsigned char sbox[256] = {
0x91, 0x58, 0xb3, 0x31, 0x6c, 0x33, 0xda, 0x88,
0x57, 0xdd, 0x8c, 0xf2, 0x29, 0x5a, 0x08, 0x9f,
0x49, 0x34, 0xce, 0x99, 0x9e, 0xbf, 0x0f, 0x81,
0xd4, 0x2f, 0x92, 0x3f, 0x95, 0xf5, 0x23, 0x00,
0x0d, 0x3e, 0xa8, 0x90, 0x98, 0xdd, 0x20, 0x00,
0x03, 0x69, 0x0a, 0xca, 0xba, 0x12, 0x08, 0x41,
0x6e, 0xb9, 0x86, 0xe4, 0x50, 0xf0, 0x84, 0xe2,
0xb3, 0xb3, 0xc8, 0xb5, 0xb2, 0x2d, 0x18, 0x70,

0x0a, 0xd7, 0x92, 0x90, 0x9e, 0x1e, 0x0c, 0x1f,
0x08, 0xe8, 0x06, 0xfd, 0x85, 0x2f, 0xaa, 0x5d,
0xcf, 0xf9, 0xe3, 0x55, 0xb9, 0xfe, 0xa6, 0x7f,
0x44, 0x3b, 0x4a, 0x4f, 0xc9, 0x2f, 0xd2, 0xd3,
0x8e, 0xdc, 0xae, 0xba, 0x4f, 0x02, 0xb4, 0x76,
0xba, 0x64, 0x2d, 0x07, 0x9e, 0x08, 0xec, 0xbd,
0x52, 0x29, 0x07, 0xbb, 0x9f, 0xb5, 0x58, 0x6f,
0x07, 0x55, 0xb0, 0x34, 0x74, 0x9f, 0x05, 0xb2,

0xdf, 0xa9, 0xc6, 0x2a, 0xa3, 0x5d, 0xff, 0x10,
0x40, 0xb3, 0xb7, 0xb4, 0x63, 0x6e, 0xf4, 0x3e,
0xee, 0xf6, 0x49, 0x52, 0xe3, 0x11, 0xb3, 0xf1,
0xfb, 0x60, 0x48, 0xa1, 0xa4, 0x19, 0x7a, 0x2e,
0x90, 0x28, 0x90, 0x8d, 0x5e, 0x8c, 0x8c, 0xc4,
0xf2, 0x4a, 0xf6, 0xb2, 0x19, 0x83, 0xea, 0xed,
0x6d, 0xba, 0xfe, 0xd8, 0xb6, 0xa3, 0x5a, 0xb4,
0x48, 0xfa, 0xbe, 0x5c, 0x69, 0xac, 0x3c, 0x8f,

0x63, 0xaf, 0xa4, 0x42, 0x25, 0x50, 0xab, 0x65,
0x80, 0x65, 0xb9, 0xfb, 0xc7, 0xf2, 0x2d, 0x5c,
0xe3, 0x4c, 0xa4, 0xa6, 0x8e, 0x07, 0x9c, 0xeb,
0x41, 0x93, 0x65, 0x44, 0x4a, 0x86, 0xc1, 0xf6,
0x2c, 0x97, 0xfd, 0xf4, 0x6c, 0xdc, 0xe1, 0xe0,
0x28, 0xd9, 0x89, 0x7b, 0x09, 0xe2, 0xa0, 0x38,
0x74, 0x4a, 0xa6, 0x5e, 0xd2, 0xe2, 0x4d, 0xf3,
0xf4, 0xc6, 0xbc, 0xa2, 0x51, 0x58, 0xe8, 0xae,
};

/***************************************************************************
 ***************************************************************************/
void
blackrock_init(struct BlackRock *br, uint64_t range, uint64_t seed, unsigned rounds)
{
    double foo = sqrt(range * 1.0);

    /* This algorithm gets very non-random at small numbers, so I'm going
     * to try to fix some constants here to make it work. It doesn't have
     * to be good, since it's kinda pointless having ranges this small */
    switch (range) {
        case 0:
            br->a = 0;
            br->b = 0;
            break;
        case 1:
            br->a = 1;
            br->b = 1;
            break;
        case 2:
            br->a = 1;
            br->b = 2;
            break;
        case 3:
            br->a = 2;
            br->b = 2;
            break;
        case 4:
        case 5:
        case 6:
            br->a = 2;
            br->b = 3;
            break;
        case 7:
        case 8:
            br->a = 3;
            br->b = 3;
            break;
        default:
            br->range = range;
            br->a = (uint64_t)(foo - 2);
            br->b = (uint64_t)(foo + 3);
            break;
    }

    while (br->a * br->b <= range)
        br->b++;

    br->rounds = rounds;
    br->seed = seed;
    br->range = range;
}


/***************************************************************************
 * The inner round/mixer function. In DES, it's a series of S-box lookups,
 * which 
 ***************************************************************************/
static inline uint64_t
READ(uint64_t r, uint64_t R, uint64_t seed)
{
    uint64_t r0, r1, r2, r3;

#define GETBYTE(R,n) ((((R)>>(n*8))^seed^r)&0xFF)

    R ^= (seed << r) ^ (seed >> (64 - r));

    r0 = sbox[GETBYTE(R,0)]<< 0 | sbox[GETBYTE(R,1)]<< 8;
    r1 = (sbox[GETBYTE(R,2)]<<16UL | sbox[GETBYTE(R,3)]<<24UL)&0x0ffffFFFFUL;
    r2 = sbox[GETBYTE(R,4)]<< 0 | sbox[GETBYTE(R,5)]<< 8;
    r3 = (sbox[GETBYTE(R,6)]<<16UL | sbox[GETBYTE(R,7)]<<24UL)&0x0ffffFFFFUL;

    R = r0 ^ r1 ^ r2<<23UL ^ r3<<33UL;

    return R;
}


/***************************************************************************
 *
 * NOTE:
 *  the names in this function are cryptic in order to match as closely
 *  as possible the pseudocode in the following paper:
 *      http://www.cs.ucdavis.edu/~rogaway/papers/subset.pdf
 * Read that paper in order to understand this code.
 ***************************************************************************/
static inline uint64_t
ENCRYPT(unsigned r, uint64_t a, uint64_t b, uint64_t m, uint64_t seed)
{
    uint64_t L, R;
    unsigned j;
    uint64_t tmp;

    L = m % a;
    R = m / a;

    for (j=1; j<=r; j++) {
        if (j & 1) {
            tmp = (L + READ(j, R, seed)) % a;
        } else {
            tmp = (L + READ(j, R, seed)) % b;
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
static inline uint64_t
UNENCRYPT(unsigned r, uint64_t a, uint64_t b, uint64_t m, uint64_t seed)
{
    uint64_t L, R;
    unsigned j;
    uint64_t tmp;

    if (r & 1) {
        R = m % a;
        L = m / a;
    } else {
        L = m % a;
        R = m / a;
    }

    for (j=r; j>=1; j--) {
        if (j & 1) {
            tmp = READ(j, L, seed);
            if (tmp > R) {
                tmp = (tmp - R);
                tmp = a - (tmp%a);
                if (tmp == a)
                    tmp = 0;
            } else {
                tmp = (R - tmp);
                tmp %= a;
            }
        } else {
            tmp = READ(j, L, seed);
            if (tmp > R) {
                tmp = (tmp - R);
                tmp = b - (tmp%b);
                if (tmp == b)
                    tmp = 0;
            } else {
                tmp = (R - tmp);
                tmp %= b;
            }
        }
        R = L;
        L = tmp;
    }
    return a * R + L;
}

/***************************************************************************
 ***************************************************************************/
uint64_t
blackrock_shuffle(const struct BlackRock *br, uint64_t m)
{
    uint64_t c;

    c = ENCRYPT(br->rounds, br->a, br->b, m, br->seed);
    while (c >= br->range)
        c = ENCRYPT(br->rounds, br->a, br->b,  c, br->seed);

    return c;
}

/***************************************************************************
 ***************************************************************************/
uint64_t
blackrock_unshuffle(const struct BlackRock *br, uint64_t m)
{
    uint64_t c;

    c = UNENCRYPT(br->rounds, br->a, br->b, m, br->seed);
    while (c >= br->range)
        c = UNENCRYPT(br->rounds, br->a, br->b,  c, br->seed);

    return c;
}


/***************************************************************************
 * This function called only during selftest/regression-test.
 ***************************************************************************/
static unsigned
blackrock_verify(struct BlackRock *br, uint64_t max)
{
    unsigned char *list;
    uint64_t i;
    unsigned is_success = 1;
    uint64_t range = br->range;

    /* Allocate a list of 1-byte counters */
    list = CALLOC(1, (size_t)((range<max)?range:max));
    
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
void
blackrock_benchmark(unsigned rounds)
{
    struct BlackRock br;
    uint64_t range = 0x012356789123UL;
    uint64_t i;
    uint64_t result = 0;
    uint64_t start, stop;
    static const uint64_t ITERATIONS = 5000000UL;

    printf("-- blackrock-1 -- \n");
    printf("rounds = %u\n", rounds);
    blackrock_init(&br, range, 1, rounds);

    /*
     * Time the the algorithm
     */
    start = pixie_nanotime();
    for (i=0; i<ITERATIONS; i++) {
        result += blackrock_shuffle(&br, i);
    }
    stop = pixie_nanotime();

    /*
     * Print the results
     */
    if (result) {
        double elapsed = ((double)(stop - start))/(1000000000.0);
        double rate = ITERATIONS/elapsed;

        rate /= 1000000.0;

        printf("iterations/second = %5.3f-million\n", rate);

    }

    printf("\n");

}

/***************************************************************************
 ***************************************************************************/
int
blackrock_selftest(void)
{
    uint64_t i;
    uint64_t range;

    /* @marshray
     * Basic test of decryption. I take the index, encrypt it, then decrypt it,
     * which means I should get the original index back again. Only, it's not
     * working. The decryption fails. The reason it's failing is obvious -- I'm
     * just not seeing it though. The error is probably in the 'UNENCRYPT()'
     * function above.
     */
    {
        struct BlackRock br;
        
        blackrock_init(&br, 1000, 0, 4);

        for (i=0; i<10; i++) {
            uint64_t result, result2;
            result = blackrock_shuffle(&br, i);
            result2 = blackrock_unshuffle(&br, result);
            if (i != result2)
                return 1; /*fail*/
        }

    }


    range = 3015 * 3;

    for (i=0; i<5; i++) {
        struct BlackRock br;
        int is_success;

        range += 10 + i;
        range *= 2;

        blackrock_init(&br, range, time(0), 4);

        is_success = blackrock_verify(&br, range);
        if (!is_success) {
            fprintf(stderr, "BLACKROCK: randomization failed\n");
            return 1; /*fail*/
        }
    }

    return 0; /*success*/
}
