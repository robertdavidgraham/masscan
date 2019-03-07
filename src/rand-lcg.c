/*
    This is a "linear-congruent-generator", a type of random number
    generator.
*/

#include "rand-lcg.h"
#include "rand-primegen.h" /* DJB's prime factoring code */
#include "string_s.h"
#include "util-malloc.h"

#include <math.h>  /* for 'sqrt()', may need -lm for gcc */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>



/**
 * A 64 bit number can't have more than 16 prime factors. The first factors
 * are:
 * 2*3*5*7*11*13*17*19*23*29*31*37*41*43*47*53 = 0xC443F2F861D29C3A
 *                                                 0123456789abcdef
 * We zero termiante this list, so we are going to reserve 20 slots.
 */
typedef uint64_t PRIMEFACTORS[20];


/****************************************************************************
 * Break down the number into prime factors using DJB's sieve code, which
 * is about 5 to 10 times faster than the Seive of Eratosthenes.
 *
 * @param number
 *      The integer that we are factoring. It can be any value up to 64 bits
 *      in size.
 * @param factors
 *      The list of all the prime factors, zero terminated.
 * @param non_factors
 *      A list of smallest numbers that aren't prime factors. We return
 *      this because we are going to use prime non-factors for finding
 *      interesting numbers.
 ****************************************************************************/
static unsigned
sieve_prime_factors(uint64_t number, PRIMEFACTORS factors,
                    PRIMEFACTORS non_factors, double *elapsed)
{
    primegen pg;
    clock_t start;
    clock_t stop;
    uint64_t prime;
    uint64_t max;
    unsigned factor_count = 0;
    unsigned non_factor_count = 0;

    /*
     * We only need to seive up to the square-root of the target number. Only
     * one prime factor can be bigger than the square root, so once we find
     * all the other primes, the square root is the only one left.
     * Note: you have to link to the 'm' math library for some gcc platforms.
     */
    max = (uint64_t)sqrt(number + 1.0);

    /*
     * Init the DJB primegen library.
     */
    primegen_init(&pg);

    /*
     * Enumerate all the primes starting with 2
     */
    start = clock();
    for (;;) {

        /* Seive the next prime */
        prime = primegen_next(&pg);

        /* If we've reached the square root, then that's as far as we need
         * to go */
        if (prime > max)
            break;

        /* If this prime is not a factor (evenly divisible with no remainder)
         * then loop back and get the next prime */
        if ((number % prime) != 0) {
            if (non_factor_count < 12)
                non_factors[non_factor_count++] = prime;
            continue;
        }

        /* Else we've found a prime factor, so add this to the list of primes */
        factors[factor_count++] = prime;

        /* At the end, we may have one prime factor left that's bigger than the
         * sqrt. Therefore, as we go along, divide the original number
         * (possibly several times) by the prime factor so that this large
         * remaining factor will be the only one left */
        while ((number % prime) == 0)
            number /= prime;

        /* exit early if we've found all prime factors. comment out this
         * code if you want to benchmark it */
        if (number == 1 && non_factor_count > 10)
            break;
    }

    /*
     * See if there is one last prime that's bigger than the square root.
     * Note: This is the only number that can be larger than 32-bits in the
     * way this code is written.
     */
    if (number != 1)
        factors[factor_count++] = number;

    /*
     * Zero terminate the results.
     */
    factors[factor_count] = 0;
    non_factors[non_factor_count] = 0;

    /*
     * Since prime factorization takes a long time, especially on slow
     * CPUs, we benchmark it to keep track of performance.
     */
    stop = clock();
    if (elapsed)
        *elapsed = ((double)stop - (double)start)/(double)CLOCKS_PER_SEC;

    /* should always be at least 1, because if the number itself is prime,
     * then that's it's only prime factor */
    return factor_count;
}



/****************************************************************************
 * Do a pseudo-random 1-to-1 translation of a number within a range to
 * another number in that range.
 *
 * The constants 'a' and 'c' must be chosen to match the LCG algorithm
 * to fit 'm' (range).
 *
 * This the same as the function 'rand()', except all the constants and
 * seeds are specified as parameters.
 *
 * @param index
 *      The index within the range that we are randomizing.
 * @param a
 *      The 'multiplier' of the LCG algorithm.
 * @param c
 *      The 'increment' of the LCG algorithm.
 * @param range
 *      The 'modulus' of the LCG algorithm.
 ****************************************************************************/
uint64_t
lcg_rand(uint64_t index, uint64_t a, uint64_t c, uint64_t range)
{
    return (index * a + c) % range;
}


/****************************************************************************
 * Verify the LCG algorithm. You shouldn't do this for large ranges,
 * because we'll run out of memory. Therefore, this algorithm allocates
 * a buffer only up to a smaller range. We still have to traverse the
 * entire range of numbers, but we only need store values for a smaller
 * range. If 10% of the range checks out, then there's a good chance
 * it applies to the other 90% as well.
 *
 * This works by counting the results of rand(), which should be produced
 * exactly once.
 ****************************************************************************/
static unsigned
lcg_verify(uint64_t a, uint64_t c, uint64_t range, uint64_t max)
{
    unsigned char *list;
    uint64_t i;
    unsigned is_success = 1;

    /* Allocate a list of 1-byte counters */
    list = CALLOC(1, (size_t)((range<max)?range:max));
    
    /* For all numbers in the range, verify increment the counter for the
     * the output. */
    for (i=0; i<range; i++) {
        uint64_t x = lcg_rand(i, a, c, range);
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


/****************************************************************************
 * Count the number of digits in a number so that we can pretty-print a
 * bunch of numbers in nice columns.
 ****************************************************************************/
static unsigned
count_digits(uint64_t num)
{
    unsigned result = 0;

    while (num) {
        result++;
        num /= 10;
    }

    return result;
}

/****************************************************************************
 * Tell whether the number has any prime factors in common with the list
 * of factors. In other words, if it's not coprime with the other number.
 * @param c
 *      The number we want to see has common factors with the other number.
 * @param factors
 *      The factors from the other number
 * @return
 *      !is_coprime(c, factors)
 ****************************************************************************/
static uint64_t
has_factors_in_common(uint64_t c, PRIMEFACTORS factors)
{
    unsigned i;

    for (i=0; factors[i]; i++) {
        if ((c % factors[i]) == 0)
            return factors[i]; /* found a common factor */
    }
    return 0; /* no factors in common */
}


/****************************************************************************
 * Given a range, calculate some possible constants for the LCG algorithm
 * for randomizing the order of the array.
 * @parm m
 *      The range for which we'll be finding random numbers. If we are
 *      looking for random numbers between [0..100), this number will
 *      be 100.
 * @parm a
 *      The LCG 'a' constant that will be the result of this function.
 * @param c
 *      The LCG 'c' constant that will be the result of this function. This
 *      should be set to 0 on the input to this function, or a suggested
 *      value.
 ****************************************************************************/
void
lcg_calculate_constants(uint64_t m, uint64_t *out_a, uint64_t *inout_c, int is_debug)
{
    uint64_t a;
    uint64_t c = *inout_c;
    double elapsed = 0.0; /* Benchmark of 'sieve' algorithm */
    PRIMEFACTORS factors; /* List of prime factors of 'm' */
    PRIMEFACTORS non_factors;
    unsigned i;

    /*
     * Find all the prime factors of the number. This step can take several
     * seconds for 48 bit numbers, which is why we benchmark how long it
     * takes.
     */
    sieve_prime_factors(m, factors, non_factors, &elapsed);

    /*
     * Calculate the 'a-1' constant. It must share all the prime factors
     * with the range, and if the range is a multiple of 4, must also
     * be a multiple of 4
     */
    if (factors[0] == m) {
        /* this number has no prime factors, so we can choose anything.
         * Therefore, we are going to pick something at random */
        unsigned j;

        a = 1;
        for (j=0; non_factors[j] && j < 5; j++)
            a *= non_factors[j];
    } else {
        //unsigned j;
        a = 1;
        for (i=0; factors[i]; i++)
            a = a * factors[i];
        if ((m % 4) == 0)
            a *= 2;

        /*for (j=0; j<0 && non_factors[j]; j++)
            a *= non_factors[j];*/
    }
    a += 1;

    /*
     * Calculate the 'c' constant. It must have no prime factors in
     * common with the range.
     */
    if (c == 0)
        c = 2531011 ; /* something random */
    while (has_factors_in_common(c, factors))
        c++;

    if (is_debug) {
        /*
         * print the results
         */
        //printf("sizeof(int) = %" PRIu64 "-bits\n", (uint64_t)(sizeof(size_t)*8));
        printf("elapsed     = %5.3f-seconds\n", elapsed);
        printf("factors     = ");
        for (i=0; factors[i]; i++)
            printf("%" PRIu64 " ", factors[i]);
        printf("%s\n", factors[0]?"":"(none)");
        printf("m           = %-24" PRIu64 " (0x%" PRIx64 ")\n", m, m);
        printf("a           = %-24" PRIu64 " (0x%" PRIx64 ")\n", a, a);
        printf("c           = %-24" PRIu64 " (0x%" PRIx64 ")\n", c, c);
        printf("c%%m         = %-24" PRIu64 " (0x%" PRIx64 ")\n", c%m, c%m);
        printf("a%%m         = %-24" PRIu64 " (0x%" PRIx64 ")\n", a%m, a%m);

        if (m < 1000000000) {
            if (lcg_verify(a, c+1, m, 280))
                printf("verify      = success\n");
            else
                printf("verify      = failure\n");
        } else {
            printf("verify      = too big to check\n");
        }


        /*
         * Print some first numbers. We use these to visually inspect whether
         * the results are random or not.
         */
        {
            unsigned count = 0;
            uint64_t x = 0;
            unsigned digits = count_digits(m);

            for (i=0; i<100 && i < m; i++) {
                x = lcg_rand(x, a, c, m);
                count += printf("%*" PRIu64 " ", digits, x);
                if (count >= 70) {
                    count = 0;
                    printf("\n");
                }
            }
            printf("\n");
        }
    }

    *out_a = a;
    *inout_c = c;
}

/***************************************************************************
 ***************************************************************************/
int
lcg_selftest(void)
{
    unsigned i;
    int is_success = 0;
    uint64_t m, a, c;


    m = 3015 * 3;

    for (i=0; i<5; i++) {
        a = 0;
        c = 0;

        m += 10 + i;

        lcg_calculate_constants(m, &a, &c, 0);

        is_success = lcg_verify(a, c, m, m);

        if (!is_success) {
            fprintf(stderr, "LCG: randomization failed\n");
            return 1; /*fail*/
        }
    }

    return 0; /*success*/
}
