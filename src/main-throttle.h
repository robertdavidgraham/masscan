#ifndef MAIN_THROTTLE_H
#define MAIN_THROTTLE_H
#include <stdint.h>

struct Throttler
{
    double max_rate;
    double current_rate;
    double batch_size;

    unsigned index;

    struct {
        uint64_t timestamp;
        uint64_t packet_count;
    } buckets[256];

    uint64_t test_timestamp;
    uint64_t test_packet_count;

};


uint64_t throttler_next_batch(struct Throttler *throttler, uint64_t count);
void throttler_start(struct Throttler *status, double max_rate);

#endif
