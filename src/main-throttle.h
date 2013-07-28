#ifndef MAIN_THROTTLE_H
#define MAIN_THROTTLE_H
#include <stdint.h>

struct Throttler
{
    double max_rate;
    double current_rate;
    double max_batch;
    uint64_t last_count;
    uint64_t last_timestamp;
};


uint64_t throttler_next_batch(struct Throttler *throttler, uint64_t count);
void throttler_start(struct Throttler *status, double max_rate);

#endif
