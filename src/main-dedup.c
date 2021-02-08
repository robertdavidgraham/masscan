/*

    Filters duplicate responses

    This is an asynchronous and "stateless" scanner that spews out probes
    without having holding "state" for the probes. This means that when
    a response comes back, we have no "state" to associate with it.
 
    This means when two responses come back, we still don't have any
    "state" to remember that the first one came back. This will cause
    us to report two results instead of one.
 
    We could create a large table holding a record for EVERY response
    that we've seen. But this would require a lot of memory for large
    scans.
 
    Instead, we remember a small hashtable of recent responses. This
    takes advantage of the fact that multiple responses are likely
    to be recent and eventually age out.
 
    We call this "deduplication" as it's simply removing duplicate
    responses.
*/
#include "main-dedup.h"
#include "util-malloc.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "syn-cookie.h"

/**
 * This is the number of entries in our table. More enttries does a better job at the
 * cost of using more memory.
 */
#define DEDUP_ENTRIES 65536

struct DedupEntry_IPv4
{
    unsigned ip_them;
    unsigned port_them;
    unsigned ip_me;
    unsigned port_me;
};

struct DedupEntry_IPv6
{
    ipv6address ip_them;
    ipv6address ip_me;
    unsigned short port_them;
    unsigned short port_me;
};

/**
 * This is simply the arrrasy of entries. We have two arrays, one for IPv4
 * and another for IPv6.
 */
struct DedupTable
{
    struct DedupEntry_IPv4 entries[DEDUP_ENTRIES][4];
    struct DedupEntry_IPv6 entries6[DEDUP_ENTRIES][4];
};

/**
 * We use the FNv1a hash algorith, which starts with this seed value.
 */
const unsigned fnv1a_seed  = 0x811C9DC5; /* 2166136261 */

/**
 * Hash one byte, the other hash functions of multiple bytes call this function.
 * @param hash
 *      The current hash value that we keep updating as we repeatedly
 *      call this function, or the `fnv1a_seed   value on the first call to
 *      this function.
 */
static inline unsigned fnv1a(unsigned char c, unsigned hash)
{
  const unsigned prime = 0x01000193; /* 16777619 */
  return (c ^ hash) * prime;
}

static unsigned fnv1a_string(const void *v_buf, size_t length, unsigned hash)
{
    const unsigned char *buf = (const unsigned char *)v_buf;
    size_t i;
    for (i=0; i<length; i++)
        hash = fnv1a(buf[i], hash);
    return hash;
}

static inline unsigned fnv1a_short(unsigned data, unsigned hash)
{
    hash = fnv1a((data>>0)&0xFF, hash);
    hash = fnv1a((data>>8)&0xFF, hash);
    return hash;
}
static inline unsigned fnv1a_longlong(unsigned long long data, unsigned hash)
{
    return fnv1a_string(&data, 8, hash);
}

/**
 * Create a new table, which means simply allocating the object
 * and seting it to zero.
 */
struct DedupTable *
dedup_create(void)
{
    struct DedupTable *dedup;

    dedup = CALLOC(1, sizeof(*dedup));

    return dedup;
}

/**
 * There's nothing special we need to do to free the structure
 * since it's all contained in the single allocation.
 */
void
dedup_destroy(struct DedupTable *dedup)
{
    free(dedup);
}

/**
 * Create a hash of the IPv6 socket. This doesn't have to be
 * cryptographically secure, so we are going to use the FNv1a algorithm.
 */
static inline unsigned
dedup_hash_ipv6(ipaddress ip_them, unsigned port_them, ipaddress ip_me, unsigned port_me)
{
    unsigned hash = fnv1a_seed;
    hash = fnv1a_longlong(ip_them.ipv6.hi, hash);
    hash = fnv1a_longlong(ip_them.ipv6.lo, hash);
    hash = fnv1a_short(port_them, hash);
    hash = fnv1a_longlong(ip_me.ipv6.hi, hash);
    hash = fnv1a_longlong(ip_me.ipv6.lo, hash);
    hash = fnv1a_short(port_me, hash);
    return hash;
}

/**
 * If two IPv6 addresses are equal.
 */
static inline int
is_equal6(ipv6address lhs, ipv6address rhs)
{
    return lhs.hi == rhs.hi && lhs.lo == rhs.lo;
}

/**
 * Swap two addresses in the table. Thsi uses the classic XOR trick
 * rather than using a swap variable.
 */
static inline void
swap6(struct DedupEntry_IPv6 *lhs, struct DedupEntry_IPv6 *rhs)
{
    lhs->ip_them.hi ^= rhs->ip_them.hi;
    lhs->ip_them.lo ^= rhs->ip_them.lo;
    lhs->port_them ^= rhs->port_them;
    lhs->ip_me.hi ^= rhs->ip_me.hi;
    lhs->ip_me.lo ^= rhs->ip_me.lo;
    lhs->port_me ^= rhs->port_me;

    rhs->ip_them.hi ^= lhs->ip_them.hi;
    rhs->ip_them.lo ^= lhs->ip_them.lo;
    rhs->port_them ^= lhs->port_them;
    rhs->ip_me.hi ^= lhs->ip_me.hi;
    rhs->ip_me.lo ^= lhs->ip_me.lo;
    rhs->port_me ^= lhs->port_me;

    lhs->ip_them.hi ^= rhs->ip_them.hi;
    lhs->ip_them.lo ^= rhs->ip_them.lo;
    lhs->port_them ^= rhs->port_them;
    lhs->ip_me.hi ^= rhs->ip_me.hi;
    lhs->ip_me.lo ^= rhs->ip_me.lo;
    lhs->port_me ^= rhs->port_me;
}

/**
 * This implements the same algorithm as for IPv4 addresses, but for
 * IPv6 addresses instead.
 */
static unsigned
dedup_is_duplicate_ipv6(struct DedupTable *dedup,
                   ipaddress ip_them, unsigned port_them,
                   ipaddress ip_me, unsigned port_me)
{
    unsigned hash;
    struct DedupEntry_IPv6 *bucket;
    unsigned i;

    /* THREAT: probably need to secure this hash, though the syn-cookies
     * provides some protection */
    hash = dedup_hash_ipv6(ip_them, port_them, ip_me, port_me);
    hash &= DEDUP_ENTRIES-1;

    /* Search in this bucket */
    bucket = dedup->entries6[hash];

    /* If we find the entry in our table, move it to the front, so
     * that it won't be aged out as quickly. We keep prepending new
     * addresses to front, aging older addresses that haven't been
     * seen in a while. */
    for (i = 0; i < 4; i++) {
        if (is_equal6(bucket[i].ip_them, ip_them.ipv6) && bucket[i].port_them == port_them
            && is_equal6(bucket[i].ip_me, ip_me.ipv6) && bucket[i].port_me == port_me) {
            /* move to end of list so constant repeats get ignored */
            if (i > 0) {
                swap6(&bucket[0], &bucket[i]);
            }
            return 1;
        }
    }

    /* We didn't find it, so add it to our list. This will push
     * older entries at this bucket off the list */
    memmove(bucket, bucket+1, 3*sizeof(*bucket));
    bucket[0].ip_them.hi = ip_them.ipv6.hi;
    bucket[0].ip_them.lo = ip_them.ipv6.lo;
    bucket[0].port_them = (unsigned short)port_them;
    bucket[0].ip_me.hi = ip_me.ipv6.hi;
    bucket[0].ip_me.lo = ip_me.ipv6.lo;
    bucket[0].port_me = (unsigned short)port_me;

    return 0;

}

/***************************************************************************
 ***************************************************************************/
static unsigned
dedup_is_duplicate_ipv4(struct DedupTable *dedup,
                   ipaddress ip_them, unsigned port_them,
                   ipaddress ip_me, unsigned port_me)
{
    unsigned hash;
    struct DedupEntry_IPv4 *bucket;
    unsigned i;

    /* THREAT: probably need to secure this hash, though the syn-cookies
     * provides some protection */
    hash = (ip_them.ipv4 + port_them) ^ ((ip_me.ipv4) + (ip_them.ipv4>>16)) ^ (ip_them.ipv4>>24) ^ port_me;
    hash &= DEDUP_ENTRIES-1;

    /* Search in this bucket */
    bucket = dedup->entries[hash];

    /* If we find the entry in our table, move it to the front, so
     * that it won't be aged out as quickly. We keep prepending new
     * addresses to front, aging older addresses that haven't been
     * seen in a while. */
    for (i = 0; i < 4; i++) {
        if (bucket[i].ip_them == ip_them.ipv4 && bucket[i].port_them == port_them
            && bucket[i].ip_me == ip_me.ipv4 && bucket[i].port_me == port_me) {
            /* move to end of list so constant repeats get ignored */
            if (i > 0) {
                bucket[i].ip_them ^= bucket[0].ip_them;
                bucket[i].port_them ^= bucket[0].port_them;
                bucket[i].ip_me ^= bucket[0].ip_me;
                bucket[i].port_me ^= bucket[0].port_me;

                bucket[0].ip_them ^= bucket[i].ip_them;
                bucket[0].port_them ^= bucket[i].port_them;
                bucket[0].ip_me ^= bucket[i].ip_me;
                bucket[0].port_me ^= bucket[i].port_me;

                bucket[i].ip_them ^= bucket[0].ip_them;
                bucket[i].port_them ^= bucket[0].port_them;
                bucket[i].ip_me ^= bucket[0].ip_me;
                bucket[i].port_me ^= bucket[0].port_me;
            }
            return 1;
        }
    }

    /* We didn't find it, so add it to our list. This will push
     * older entries at this bucket off the list */
    memmove(bucket, bucket+1, 3*sizeof(*bucket));
    bucket[0].ip_them = ip_them.ipv4;
    bucket[0].port_them = port_them;
    bucket[0].ip_me = ip_me.ipv4;
    bucket[0].port_me = port_me;

    return 0;

}

/***************************************************************************
 ***************************************************************************/
unsigned
dedup_is_duplicate(struct DedupTable *dedup,
                   ipaddress ip_them, unsigned port_them,
                   ipaddress ip_me, unsigned port_me)
{
    if (ip_them.version == 6)
        return dedup_is_duplicate_ipv6(dedup, ip_them, port_them, ip_me, port_me);
    else
        return dedup_is_duplicate_ipv4(dedup, ip_them, port_them, ip_me, port_me);
}


/**
 * My own deterministic rand() function for testing this module
 */
static unsigned
_rand(unsigned *seed)
{
    static const unsigned a = 214013;
    static const unsigned c = 2531011;

    *seed = (*seed) * a + c;
    return (*seed)>>16 & 0x7fff;
}

/*
 * Provide a simple unit test for this module.
 *
 * This is a pretty lame test. I'm going to generate
 * a set of random addresses, tweeked so that they aren't
 * too random, so that I get around 30 to 50 expected
 * duplciates. If I get zero duplicates, or if I get too
 * many duplicates in the test, then I know it's failed.
 *
 * This is in no way a reliable test that deterministically
 * tests the functionality. It'a crappy non-deterministric
 * test.
 *
 * We also do a simple deterministic test, but thhis still
 * is insufficient testing how duplicates age out and such.
 */
int
dedup_selftest(void)
{
    struct DedupTable *dedup;
    unsigned seed = 0;
    size_t i;
    unsigned found_match = 0;
    unsigned line = 0;
    
    dedup = dedup_create();
    
    /* Deterministic test.
     *
     * The first time we check on a socket combo, there should
     * be no duplicate. The second time we check, however, there should
     * be a duplicate.
     */
    {
        ipaddress ip_me;
        ipaddress ip_them;
        unsigned port_me;
        unsigned port_them;
        
        ip_me.version = 4;
        ip_them.version = 4;
        ip_me.ipv4 = 0x12345678;
        ip_them.ipv4 = 0xabcdef0;
        port_me = 0x1234;
        port_them = 0xfedc;
        
        if (dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me)) {
            line = __LINE__;
            goto fail;
        }
        if (!dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me)) {
            line = __LINE__;
            goto fail;
        }
        
        ip_me.version = 6;
        ip_them.version = 6;
        ip_me.ipv6.hi = 0x12345678;
	    ip_me.ipv6.lo = 0x12345678;
        ip_them.ipv6.hi = 0xabcdef0;
        ip_them.ipv6.lo = 0xabcdef0;

        if (dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me)) {
            line = __LINE__;
            goto fail;
        }
        if (!dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me)) {
            ipaddress_formatted_t fmt1 = ipaddress_fmt(ip_them);
            ipaddress_formatted_t fmt2 = ipaddress_fmt(ip_me);
            fprintf(stderr, "[-] [%s]:%u -> [%s]:%u\n", 
			    fmt1.string, port_them,
			    fmt2.string, port_me);
            line = __LINE__;
            goto fail;
        }
        
    }
    
    /* Test IPv4 addresses */
    for (i=0; i<100000; i++) {
        ipaddress ip_me;
        ipaddress ip_them;
        unsigned port_me;
        unsigned port_them;
        
        ip_me.version = 4;
        ip_them.version = 4;
        
        /* Instead of completely random numbers over the entire
         * range, each port/IP is restricted to just 512
         * random combinations. This should statistically
         * give us around 10 matches*/
        ip_me.ipv4 = _rand(&seed) & 0xFF800000;
        ip_them.ipv4 = _rand(&seed) & 0x1FF;
        port_me = _rand(&seed) & 0xFF80;
        port_them = _rand(&seed) & 0x1FF;
        
        if (dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me)) {
            found_match++;
        }
    }
    
    /* Approximately 30 matches should be found. If we couldn't
     * find any, or if we've found too many, then the test has
     * failed. */
    if (found_match == 0 || found_match > 200) {
        line = __LINE__;
        goto fail;
    }
    
    /* Now do IPv6 */
    found_match = 0;
    seed = 0;
    
    /* Test IPv4 addresses */
    for (i=0; i<100000; i++) {
        ipaddress ip_me;
        ipaddress ip_them;
        unsigned port_me;
        unsigned port_them;
        
        ip_me.version = 6;
        ip_them.version = 6;
        
        /* Instead of completely random numbers over the entire
         * range, each port/IP is restricted to just 512
         * random combinations. This should statistically
         * give us around 10 matches*/
        ip_me.ipv6.hi = _rand(&seed) & 0xFF800000;
        ip_them.ipv6.lo = _rand(&seed) & 0x1FF;
        port_me = _rand(&seed) & 0xFF80;
        port_them = _rand(&seed) & 0x1FF;
        
        if (dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me)) {
            found_match++;
        }
    }

    /* The result should be same as for IPv4, around 30 matches found. */
    if (found_match == 0 || found_match > 200) {
        line = __LINE__;
        goto fail;
    }
    
    /* All tests have passed */
    return 0; /* success :) */

fail:
    fprintf(stderr, "[-] selftest: 'dedup' failed, file=%s, line=%u\n", __FILE__, line);
    return 1;
}
