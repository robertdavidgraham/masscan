/*
 RST filter
 
 In theory, we should transmit a RST packet every time we receive an invalid
 TCP packet. In practice, this can lead to endless transmits when the other
 size continues to transmit bad packets. This may happen accidentally, or this
 may happen on purpose from the other side trying to attack the scanner
 intentionally. In May 2019 I see this from soembody who I suspect is trying
 to do that, replying back as fast as the scanner transmits (when running
 at 10,000 packets-persecond). This halts the scan, as it's throttle limit
 is filled sending RSTs and not doing something useful.
 
 The design is a simple non-deterministic algorithm. It hashes the
 IP/prot combo, then updates a counter at that bucket. When it reaches
 its limit, it stops transmitting resets. However, it'll also slowly
 empty buckets, so can occasionally transmit a RST now and then.
 */
#ifndef MISC_RSTFILTER_H
#define MISC_RSTFILTER_H
#include <stdio.h>


struct ResetFilter;

/**
 * Create a structure for this.
 * @param seed
 *      A random seed chosen via entropy at startup, so that adversaries
 *      can't predict where the buckets will be.
 * @param bucket_count
 *      The number of buckets. This'll be rounded up to the nearest
 *      power-of-two. 16384 is probably a good number.
 * @return an instance of this object that should be eventually
 *      cleaned up with 'rstfilter_destroy()'.
 */
struct ResetFilter *
rstfilter_create(unsigned long long seed, size_t bucket_count);

/**
 * Cleans up the object that was created with 'rstfilter_create()'.
 */
void
rstfilter_destroy(struct ResetFilter *rf);

/**
 * Tests to see if we should ignore the given RST packet. This will
 * also slowly empty a random bucket
 * @return 1 if we should filter out the offending packet and ignore it,
 *          or else 0 if we shouldn't ignore it.
 */
int
rstfilter_is_filter(struct ResetFilter *rf, unsigned src_ip, unsigned src_port, unsigned dst_ip, unsigned dst_port);

int
rstfilter_selftest(void);



#endif

