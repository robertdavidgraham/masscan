#include "syn-cookie.h"
#include "pixie-timer.h"
#include "string_s.h"
#include <time.h>
#include <stdarg.h>

#if defined(_MSC_VER)
#include <intrin.h>
#endif


static uint64_t entropy = 0;

/***************************************************************************
 * Go gather some entropy (aka. randmoness) to seed hashing with.
 *
 * NOTE: Mostly it's here to amuse cryptographers with its lulz.
 ***************************************************************************/
void
syn_set_entropy(uint64_t seed)
{
    unsigned i;

    /*
     * If we have a manual seed, use that instead
     */
    if (seed) {
        entropy = seed;
        return;
    }

    /*
     * Gather some random bits
     */
    for (i=0; i<32; i++) {
        FILE *fp;
        entropy += pixie_nanotime();
#if defined(_MSC_VER)
        entropy ^= __rdtsc();
#endif
        time(0);
        fopen_s(&fp, "/", "r");
        entropy <<= 1;
    }

    entropy ^= time(0);

#if defined(__linux__)
    {
        FILE *fp;
        int err;

        err = fopen_s(&fp, "/dev/urandom", "r");
        if (err == 0 && fp) {
            uint64_t urand = 0;
            fread(&urand, 1, sizeof(urand), fp);
            entropy ^= urand;
            fclose(fp);
        }
        entropy ^= pixie_nanotime();
    }
#endif
}


/***************************************************************************
 * I'm using a Murmur hash to start with, will probably look at others
 * soon.
 ***************************************************************************/
static unsigned
murmur(uint64_t entropy, ...)
{
    /* reference:
     * http://en.wikipedia.org/wiki/MurmurHash
     */
    static const unsigned c1 = 0xcc9e2d51;
    static const unsigned c2 = 0x1b873593;
    unsigned r1 = 15;
    unsigned r2 = 13;
    unsigned m = 5;
    unsigned n = 0xe6546b64;
    va_list key;
    unsigned len;

    unsigned hash = (unsigned)entropy;

    va_start(key, entropy);

    for (len=0; len<2; len++) {
        unsigned k = va_arg(key, unsigned);
        k = k * c1;
        k = (k << r1) | (k >> (32-r1));
        k = k * c2;

        hash = hash ^ k;
        hash = (hash << r2) | (hash >> (32-r2));
        hash = hash * m + n;
    }

    hash = hash ^ (len*4);

    hash = hash ^ (hash >> 16);
    hash = hash * 0x85ebca6b;
    hash = hash ^ (hash >> 13);
    hash = hash * 0xc2b2ae35;
    hash = hash ^ (hash >> 16);

    return hash;
}

/***************************************************************************
 ***************************************************************************/
unsigned
syn_hash(unsigned ip, unsigned port)
{
    return murmur(entropy, ip, port);
}
