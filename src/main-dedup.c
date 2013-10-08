/*

    Filters duplicate responses

    This is an asynchronous scanner. Therefore, there is no easy way to
    correlate probes with responses. We must therefore suffer the fact that
    sometimes we get repeat responses, and therefore, repeat records.

    We can mimimize this with a table remembering recent responses. Occassional
    duplicates still leak through, but it'll be less of a problem.
*/
#include <stdlib.h>
#include <string.h>

#define DEDUP_ENTRIES 4096

struct DedupEntry
{
    unsigned ip;
    unsigned port;
};
struct DedupTable
{
    struct DedupEntry entries[DEDUP_ENTRIES][4];
};

/***************************************************************************
 ***************************************************************************/
struct DedupTable *
dedup_create()
{
    struct DedupTable *result;

    result = (struct DedupTable *)malloc(sizeof(*result));
    if (result == NULL)
        exit(1);
    memset(result, 0, sizeof(*result));

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
dedup_is_duplicate(struct DedupTable *dedup, unsigned ip, unsigned port)
{
    unsigned hash;
    struct DedupEntry *bucket;
    unsigned i;

    /* THREAT: probably need to secure this hash, though the syn-cookies
     * provides some protection */
    hash = (ip + port) ^ ((ip>>8) + (ip>>16)) ^ (ip>>24);
    hash &= DEDUP_ENTRIES-1;

    /* Search in this bucket */
    bucket = dedup->entries[hash];

    for (i = 0; i < 4; i++) {
        if (bucket[i].ip == ip && bucket[i].port == port) {
            /* move to end of list so constant repeats get ignored */
            if (i > 0) {
                bucket[i].ip ^= bucket[0].ip;
                bucket[i].port ^= bucket[0].port;

                bucket[0].ip ^= bucket[i].ip;
                bucket[0].port ^= bucket[i].port;

                bucket[i].ip ^= bucket[0].ip;
                bucket[i].port ^= bucket[0].port;
            }
            return 1;
        }
    }

    /* We didn't find it, so add it to our list. This will push
     * older entries at this bucket off the list */
    memmove(bucket, bucket+1, 3*sizeof(*bucket));
    bucket[0].ip = ip;
    bucket[0].port = port;

    return 0;
}
