#include "syn-cookie.h"
#include "pixie-timer.h"
#include "string_s.h"
#include "siphash24.h"
#include <time.h>
#include <stdarg.h>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

/***************************************************************************
 * Go gather some entropy (aka. randmoness) to seed hashing with.
 *
 * NOTE: Mostly it's here to amuse cryptographers with its lulz.
 ***************************************************************************/
uint64_t
get_entropy(void)
{
    uint64_t entropy[2] = {0,0};
    unsigned i;

    /*
     * Gather some random bits
     */
    for (i=0; i<64; i++) {
        FILE *fp;
        entropy[0] += pixie_nanotime();
#if defined(_MSC_VER)
        entropy[0] ^= __rdtsc();
#endif
        time(0);
        fopen_s(&fp, "/", "r");
        entropy[1] <<= 1;
        entropy[1] |= entropy[0]>>63;
        entropy[0] <<= 1;
    }

    entropy[0] ^= time(0);

#if defined(__linux__)
    {
        FILE *fp;
        int err;

        err = fopen_s(&fp, "/dev/urandom", "r");
        if (err == 0 && fp) {
            int x;
            uint64_t urand = 0;
            x = fread(&urand, 1, sizeof(urand), fp);
            entropy[0] ^= urand;
            entropy[0] ^= x;
            x = fread(&urand, 1, sizeof(urand), fp);
            entropy[1] ^= urand;
            entropy[1] ^= x;
            fclose(fp);
        }
        entropy[0] ^= pixie_nanotime();
    }
#endif

    return entropy[0] ^ entropy[1];
}

#if 0
/***************************************************************************
 * This implements the "murmur" hash function.
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
#endif

/***************************************************************************
 ***************************************************************************/
uint64_t
syn_cookie( unsigned ip_them, unsigned port_them,
            unsigned ip_me, unsigned port_me,
            uint64_t entropy)
{
    unsigned data[4];
    uint64_t x[2];

    x[0] = entropy;
    x[1] = entropy;

    data[0] = ip_them;
    data[1] = port_them;
    data[2] = ip_me;
    data[3] = port_me;
    return siphash24(data, sizeof(data), x);
}
