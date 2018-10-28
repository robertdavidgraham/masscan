#include "rand-blackrock.h"
#include "pixie-timer.h"
#include "unusedparm.h"
#include "string_s.h"
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

/*
 * Expanded DES S-boxes
 */
static const uint32_t SB1[64] =
{
    0x01010400, 0x00000000, 0x00010000, 0x01010404,
    0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400,
    0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400,
    0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004,
    0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000,
    0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004,
    0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404,
    0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000,
    0x00010004, 0x00010400, 0x00000000, 0x01010004
};

static const uint32_t SB2[64] =
{
    0x80108020, 0x80008000, 0x00008000, 0x00108020,
    0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000,
    0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000,
    0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000,
    0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000,
    0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020,
    0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020,
    0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020,
    0x80000000, 0x80100020, 0x80108020, 0x00108000
};

static const uint32_t SB3[64] =
{
    0x00000208, 0x08020200, 0x00000000, 0x08020008,
    0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000,
    0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200,
    0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208,
    0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208,
    0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200,
    0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208,
    0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000,
    0x00020208, 0x00000008, 0x08020008, 0x00020200
};

static const uint32_t SB4[64] =
{
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080,
    0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001,
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000,
    0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002000, 0x00802080
};

static const uint32_t SB5[64] =
{
    0x00000100, 0x02080100, 0x02080000, 0x42000100,
    0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100,
    0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000,
    0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000,
    0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000,
    0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100,
    0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100,
    0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000,
    0x00000000, 0x40080000, 0x02080100, 0x40000100
};

static const uint32_t SB6[64] =
{
    0x20000010, 0x20400000, 0x00004000, 0x20404010,
    0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010,
    0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000,
    0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000,
    0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000,
    0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010,
    0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010,
    0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000,
    0x20404000, 0x20000000, 0x00400010, 0x20004010
};

static const uint32_t SB7[64] =
{
    0x00200000, 0x04200002, 0x04000802, 0x00000000,
    0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002,
    0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800,
    0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802,
    0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802,
    0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000,
    0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000,
    0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800,
    0x04000002, 0x04000800, 0x00000800, 0x00200002
};

static const uint32_t SB8[64] =
{
    0x10001040, 0x00001000, 0x00040000, 0x10041040,
    0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000,
    0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040,
    0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040,
    0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000,
    0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000,
    0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040,
    0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040,
    0x00001040, 0x00040040, 0x10000000, 0x10041000
};
/***************************************************************************
 * It's an s-box. You gotta have an s-box
 ***************************************************************************/
const unsigned char sbox2[] = {
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

0x91, 0x58, 0xb3, 0x31, 0x6c, 0x33, 0xda, 0x88,
};


/****************************************************************************
 * Given a number, figure out the nearest power-of-two (16,32,64,128,etc.)
 * that can hold that number. We do this so that we can convert multiplies
 * into shifts.
 ****************************************************************************/
static uint64_t
next_power_of_two(uint64_t num)
{
    uint64_t power_of_two = 1;

    num++;

    while ((uint64_t)(1ULL << power_of_two) < num)
        power_of_two++;

    return (1ULL << power_of_two);
}
static uint64_t
bit_count(uint64_t num)
{
    uint64_t bits = 0;

    while ((num >> bits) > 1)
        bits++;

    return bits;
}

/***************************************************************************
 ***************************************************************************/
void
blackrock2_init(struct BlackRock *br, uint64_t range, uint64_t seed, unsigned rounds)
{
    uint64_t a;
    uint64_t b;

    a = next_power_of_two(
                                (uint64_t)sqrt(range * 1.0)
                          );
    b = next_power_of_two(range/a);

    //printf("a=%llu b=%llu seed = 0x%llu\n", a, b, seed);

    br->range = range;

    br->a = a;
    br->a_bits = bit_count(br->a);
    br->a_mask = br->a - 1ULL;

    br->b = b;
    br->b_bits = bit_count(br->b);
    br->b_mask = br->b - 1ULL;

    //printf("a: 0x%llx / %llu\n", br->a_mask, br->a_bits);
    //printf("b: 0x%llx / %llu\n", br->b_mask, br->b_bits);

    br->rounds = rounds;
    br->seed = seed;
    br->range = range;
}


/***************************************************************************
 * The inner round/mixer function. In DES, it's a series of S-box lookups,
 * which 
 ***************************************************************************/
static inline uint64_t
ROUND(uint64_t r, uint64_t R, uint64_t seed)
{
#define GETBYTE(R,n) ((uint64_t)(((((R)>>(n*8ULL)))&0xFFULL)))
#if 0    
    uint64_t r0, r1, r2, r3;
#endif
    uint64_t T, Y;

    T = R ^ ((seed>>r) | (seed<<(64-r)));


    if (r & 1) {
        Y = SB8[ (T      ) & 0x3F ] ^              \
             SB6[ (T >>  8) & 0x3F ] ^              \
             SB4[ (T >> 16) & 0x3F ] ^              \
             SB2[ (T >> 24) & 0x3F ];               \
    } else {
        Y = SB7[ (T      ) & 0x3F ] ^              \
             SB5[ (T >>  8) & 0x3F ] ^              \
             SB3[ (T >> 16) & 0x3F ] ^              \
             SB1[ (T >> 24) & 0x3F ]; 
    }
    return Y;
#if 0
    r0 = sbox2[GETBYTE(R,0)]<< 6 | sbox2[GETBYTE(R,1)]<< 0;
    r1 = sbox2[GETBYTE(R,2)]<< 6 | sbox2[GETBYTE(R,5)]<< 0;
    r2 = sbox2[GETBYTE(R,4)]<< 6 | sbox2[GETBYTE(R,5)]<< 0;
    r3 = sbox2[GETBYTE(R,6)]<< 6 | sbox2[GETBYTE(R,7)]<< 0;

    R = r0 ^ (r1<<12) * (r2 << 24) ^ (r3 << 36) * r;

    return R;
    /*return((uint64_t)sbox2[GETBYTE(R,7ULL)]<< 0ULL)
        | ((uint64_t)sbox2[GETBYTE(R,6ULL)]<< 8ULL)
        | ((uint64_t)sbox2[GETBYTE(R,5ULL)]<<16ULL)
        | ((uint64_t)sbox2[GETBYTE(R,4ULL)]<<24ULL)
        | ((uint64_t)sbox2[GETBYTE(R,3ULL)]<<32ULL)
        | ((uint64_t)sbox2[GETBYTE(R,2ULL)]<<40ULL)
        | ((uint64_t)sbox2[GETBYTE(R,1ULL)]<<48ULL)
        | ((uint64_t)sbox2[GETBYTE(R,0ULL)]<<56ULL)
        ;*/
    return R;
#endif
}


/***************************************************************************
 ***************************************************************************/
static inline uint64_t
ENCRYPT(unsigned r, uint64_t a_bits, uint64_t a_mask, uint64_t b_bits, uint64_t b_mask, uint64_t m, uint64_t seed)
{
    uint64_t L, R;
    unsigned j = 1;
    uint64_t tmp;

    UNUSEDPARM(b_bits);

    L = m & a_mask;
    R = m >> a_bits;

    for (j=1; j<=r; j++) {
        tmp = (L + ROUND(j, R, seed)) & a_mask;
        L = R;
        R = tmp;
        j++;

        tmp = (L + ROUND(j, R, seed)) & b_mask;
        L = R;
        R = tmp;
    }

    if ((j-1) & 1) {
        return (L << (a_bits)) + R;
    } else {
        return (R << (a_bits)) + L;
    }
}
static inline uint64_t
DECRYPT(unsigned r, uint64_t a, uint64_t b, uint64_t m, uint64_t seed)
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
            tmp = ROUND(j, L, seed);
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
            tmp = ROUND(j, L, seed);
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
blackrock2_shuffle(const struct BlackRock *br, uint64_t m)
{
    uint64_t c;

    c = ENCRYPT(br->rounds, br->a_bits, br->a_mask, br->b_bits, br->b_mask, m, br->seed);
    while (c >= br->range)
        c = ENCRYPT(br->rounds, br->a_bits, br->a_mask, br->b_bits, br->b_mask, c, br->seed);

    return c;
}

/***************************************************************************
 ***************************************************************************/
uint64_t
blackrock2_unshuffle(const struct BlackRock *br, uint64_t m)
{
    uint64_t c;

    c = DECRYPT(br->rounds, br->a, br->b, m, br->seed);
    while (c >= br->range)
        c = DECRYPT(br->rounds, br->a, br->b,  c, br->seed);

    return c;
}


/***************************************************************************
 * This function called only during selftest/regression-test.
 ***************************************************************************/
static unsigned
verify(struct BlackRock *br, uint64_t max)
{
    unsigned char *list;
    uint64_t i;
    unsigned is_success = 1;
    uint64_t range = br->range;

    /* Allocate a list of 1-byte counters */
    list = (unsigned char *)malloc((size_t)((range<max)?range:max));
    if (list == NULL)
        exit(1);
    memset(list, 0, (size_t)((range<max)?range:max));

    /* For all numbers in the range, verify increment the counter for the
     * the output. */
    for (i=0; i<range; i++) {
        uint64_t x = blackrock2_shuffle(br, i);
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
 * Benchmarks the crypto function.
 ***************************************************************************/
void
blackrock2_benchmark(unsigned rounds)
{
    struct BlackRock br;
    uint64_t range = 0x010356789123UL;
    uint64_t i;
    uint64_t result = 0;
    uint64_t start, stop;
    static const uint64_t ITERATIONS = 5000000UL;

    printf("-- blackrock-2 -- \n");
    printf("rounds = %u\n", rounds);
    blackrock2_init(&br, range, 1, rounds);
/*printf("range = 0x%10" PRIx64 "\n", range);
printf("rangex= 0x%10" PRIx64 "\n", br.a*br.b);
printf("    a = 0x%10" PRIx64 "\n", br.a);
printf("    b = 0x%10" PRIx64 "\n", br.b);*/

    /*
     * Time the the algorithm
     */
    start = pixie_nanotime();
    for (i=0; i<ITERATIONS; i++) {
        result += blackrock2_shuffle(&br, i);
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
blackrock2_selftest(void)
{
    uint64_t i;
    int is_success = 0;
    uint64_t range;

    /* @marshray
     * Basic test of decryption. I take the index, encrypt it, then decrypt it,
     * which means I should get the original index back again. Only, it's not
     * working. The decryption fails. The reason it's failing is obvious -- I'm
     * just not seeing it though. The error is probably in the 'unfe()'
     * function above.
     */
    {
        struct BlackRock br;
        uint64_t result, result2;
        blackrock2_init(&br, 1000, 0, 6);

        for (i=0; i<10; i++) {
            result = blackrock2_shuffle(&br, i);
            result2 = blackrock2_unshuffle(&br, result);
            if (i != result2)
                return 1; /*fail*/
        }

    }


    range = 3015 * 3;

    for (i=0; i<5; i++) {
        struct BlackRock br;

        range += 11 + i;
        range *= 1 + i;

        blackrock2_init(&br, range, time(0), 6);

        is_success = verify(&br, range);

        if (!is_success) {
            fprintf(stderr, "BLACKROCK: randomization failed\n");
            return 1; /*fail*/
        }
    }

    return 0; /*success*/
}
