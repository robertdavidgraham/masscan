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


struct DedupEntry
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
 * This is simply the arrray of entries. We have two arrays, one for IPv4
 * and another for IPv6.
 */
struct DedupTable
{
    struct DedupEntry entries[DEDUP_ENTRIES][4];
    struct DedupEntry_IPv6 entries6[DEDUP_ENTRIES][4];
};

/**
 * We use the FNv1a hash algorith, which starts with this seed value.
 */
const unsigned fnv1a_seed  = 0x811C9DC5; /* 2166136261 */

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

/***************************************************************************
 ***************************************************************************/
struct DedupTable *
dedup_create(void)
{
    struct DedupTable *dedup;

    dedup = CALLOC(1, sizeof(*dedup));

    return dedup;
}

/***************************************************************************
 ***************************************************************************/
void
dedup_destroy(struct DedupTable *dedup)
{
    if (dedup)
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

static inline int
Equals(ipv6address lhs, ipv6address rhs)
{
    return lhs.hi == rhs.hi && lhs.lo == rhs.lo;
}

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
/***************************************************************************
 * TODO: implement IPv6 duplicate packet detection.
 ***************************************************************************/
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

    for (i = 0; i < 4; i++) {
        if (Equals(bucket[i].ip_them, ip_them.ipv6) && bucket[i].port_them == port_them
            && Equals(bucket[i].ip_me, ip_me.ipv6) && bucket[i].port_me == port_me) {
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
    bucket[0].port_them = port_them;
    bucket[0].ip_me.hi = ip_me.ipv6.hi;
    bucket[0].ip_me.lo = ip_me.ipv6.lo;
    bucket[0].port_me = port_me;

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
    struct DedupEntry *bucket;
    unsigned i;

    /* THREAT: probably need to secure this hash, though the syn-cookies
     * provides some protection */
    hash = (ip_them.ipv4 + port_them) ^ ((ip_me.ipv4) + (ip_them.ipv4>>16)) ^ (ip_them.ipv4>>24) ^ port_me;
    hash &= DEDUP_ENTRIES-1;

    /* Search in this bucket */
    bucket = dedup->entries[hash];

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
