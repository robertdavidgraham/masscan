#include "misc-rstfilter.h"
#include "util-malloc.h"
#include "crypto-siphash24.h"
#include <time.h>

struct ResetFilter
{
    unsigned long long seed;
    size_t bucket_count;
    size_t bucket_mask;
    unsigned counter;
    unsigned char *buckets;
};

static size_t
next_pow2(size_t n)
{
    size_t bit_count = 0;
    
    /* Always have at least one bit */
    if (n == 0)
        return 1;
    
    /* If already a power-of-two, then return that */
    if ((n & (n - 1)) == 0)
        return n;
    
    /* Count the number of bits */
    while (n != 0) {
        n >>= 1;
        bit_count += 1;
    }
    
    return (size_t)1 << (size_t)bit_count;
}

struct ResetFilter *
rstfilter_create(unsigned long long seed, size_t bucket_count)
{
    struct ResetFilter *rf;
    
    rf = CALLOC(1, sizeof(*rf));
    rf->seed = seed;
    rf->bucket_count = next_pow2(bucket_count);
    rf->bucket_mask = rf->bucket_count - 1;
    rf->buckets = CALLOC(rf->bucket_count/2, sizeof(*rf->buckets));
    
    return rf;
}


void
rstfilter_destroy(struct ResetFilter *rf)
{
    if (rf == NULL)
        return;
    free(rf->buckets);
    free(rf);
}

int
rstfilter_is_filter(struct ResetFilter *rf,
                    ipaddress src_ip, unsigned src_port,
                    ipaddress dst_ip, unsigned dst_port)
{
    uint64_t hash;
    uint64_t input[5];
    uint64_t key[2];
    size_t index;
    unsigned char *p;
    int result = 0;
    
    /*
     * Setup the input
     */
    switch (src_ip.version) {
    case 4:
        input[0] = src_ip.ipv4;
        input[1] = src_port;
        input[2] = dst_ip.ipv4;
        input[3] = dst_port;
        break;
    case 6:
        input[0] = src_ip.ipv6.hi;
        input[1] = src_ip.ipv6.lo;
        input[2] = dst_ip.ipv6.hi;
        input[3] = dst_ip.ipv6.lo;
        input[4] = src_port<<16 | dst_port;
        break;
    }
    key[0] = rf->seed;
    key[1] = rf->seed;
    
    /*
     * Grab the bucket
     */
    hash = siphash24(input, sizeof(input), key);
    index = hash & rf->bucket_mask;
    
    /*
     * Find the result (1=filterout, 0=sendrst)
     */
    p = &rf->buckets[index/2];
    if (index & 1) {
        if ((*p & 0x0F) == 0x0F)
            result = 1; /* filter out */
        else
            *p = (*p) + 0x01;
    } else {
        if ((*p & 0xF0) == 0xF0)
            result = 1; /* filter out */
        else
            *p = (*p) + 0x10;
    }
    
    /*
     * Empty a random bucket
     */
    input[0] = (unsigned)hash;
    input[1] = rf->counter++;
    hash = siphash24(input, sizeof(input), key);
    index = hash & rf->bucket_mask;
    p = &rf->buckets[index/2];
    if (index & 1) {
        if ((*p & 0x0F))
            *p = (*p) - 0x01;
    } else {
        if ((*p & 0xF0))
            *p = (*p) - 0x10;
    }

    return result;
}



int
rstfilter_selftest(void)
{
    struct ResetFilter *rf;
    size_t i;
    unsigned count_filtered = 0;
    unsigned count_passed = 0;

    ipaddress src;
    ipaddress dst;

    src.version = 4;
    src.ipv4 = 1;
    dst.version = 4;
    dst.ipv4 = 3;

    rf = rstfilter_create(time(0), 64);
    
    /* Verify the first 15 packets pass the filter */
    for (i=0; i<15; i++) {
        int x;

        x = rstfilter_is_filter(rf, src, 2, dst, 4);
        if (x) {
            fprintf(stderr, "[-] rstfilter failed, line=%u\n", __LINE__);
            return 1;
        }
    }
    
    /* Now run 10000 more times */
    for (i=0; i<1000; i++) {
        int x;
        x = rstfilter_is_filter(rf, src, 2, dst, 4);
        count_filtered += x;
        count_passed += !x;
    }
    
    /* SOME must have passed, due to us emptying random buckets */
    if (count_passed == 0) {
        fprintf(stderr, "[-] rstfilter failed, line=%u\n", __LINE__);
        return 1;
    }
    
    /* However, while some pass, the vast majority should be filtered */
    if (count_passed > count_filtered/10) {
        fprintf(stderr, "[-] rstfilter failed, line=%u\n", __LINE__);
        return 1;
    }
    //printf("filtered=%u passed=%u\n", count_filtered, count_passed);
    return 0;
}







