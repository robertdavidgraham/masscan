/*

    Filters duplicate responses

    This is an asynchronous scanner. Therefore, there is no easy way to
    correlate probes with responses. We must therefore suffer the fact that
    sometimes we get repeat responses, and therefore, repeat records.

    We can mimimize this with a table remembering recent responses. Occassional
    duplicates still leak through, but it'll be less of a problem.
*/
#include "main-dedup.h"
#include "util-malloc.h"
#include <stdlib.h>
#include <string.h>

#define DEDUP_ENTRIES 65536 /* more aggressive deduplication */

struct DedupEntry
{
    unsigned ip_them;
    unsigned port_them;
    unsigned ip_me;
    unsigned port_me;
};
struct DedupTable
{
    struct DedupEntry entries[DEDUP_ENTRIES][4];
};

/***************************************************************************
 ***************************************************************************/
struct DedupTable *
dedup_create(void)
{
    struct DedupTable *result;

    result = CALLOC(1, sizeof(*result));

    return result;
}

/***************************************************************************
 ***************************************************************************/
void
dedup_destroy(struct DedupTable *table)
{
    if (table)
        free(table);
}

/***************************************************************************
 ***************************************************************************/
unsigned
dedup_is_duplicate(struct DedupTable *dedup,
                   unsigned ip_them, unsigned port_them,
                   unsigned ip_me, unsigned port_me)
{
    unsigned hash;
    struct DedupEntry *bucket;
    unsigned i;

    /* THREAT: probably need to secure this hash, though the syn-cookies
     * provides some protection */
    hash = (ip_them + port_them) ^ ((ip_me) + (ip_them>>16)) ^ (ip_them>>24) ^ port_me;
    hash &= DEDUP_ENTRIES-1;

    /* Search in this bucket */
    bucket = dedup->entries[hash];

    for (i = 0; i < 4; i++) {
        if (bucket[i].ip_them == ip_them && bucket[i].port_them == port_them
            && bucket[i].ip_me == ip_me && bucket[i].port_me == port_me) {
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
    bucket[0].ip_them = ip_them;
    bucket[0].port_them = port_them;
    bucket[0].ip_me = ip_me;
    bucket[0].port_me = port_me;

    return 0;
}
