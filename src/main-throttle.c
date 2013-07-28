#include "main-throttle.h"
#include "port-timer.h"
#include "logger.h"
#include <string.h>
#include <stdio.h>


/***************************************************************************
 ***************************************************************************/
void throttler_start(struct Throttler *throttler, double max_rate)
{
    throttler->current_rate = 0.0;
    throttler->max_rate = max_rate;
    throttler->last_timestamp = port_gettime();
    throttler->last_count = 0;
    throttler->max_batch = 1.0;

    LOG(1, "maxrate = %0.2f\n", throttler->max_rate);
}

/***************************************************************************
 ***************************************************************************/
uint64_t
throttler_next_batch(struct Throttler *throttler, uint64_t count)
{
    uint64_t timestamp = port_gettime();
    double elapsed = ((double)(timestamp - throttler->last_timestamp))/1000000.0;
    double packets_sent = (double)(count - throttler->last_count);
    double new_rate;

    if (packets_sent < 1.01)
        return (uint64_t)throttler->max_batch;

    /* BOUNDARY CASE: if the elapsed time is zero, or very small, we
     * get confused. Therefore, handle this case specially */
    if (elapsed < 0.00001) {
        throttler->max_batch *= 1.4;
        if (throttler->max_batch > 1000.0)
            throttler->max_batch = 1000.0;
        return (uint64_t)throttler->max_batch;
    }

    throttler->last_timestamp = timestamp;
    throttler->last_count = count;


    new_rate = 0.9 * throttler->current_rate
                                + 0.1 * (packets_sent/elapsed);


    if (new_rate > 10000000.0)
        printf(".");

    throttler->current_rate = new_rate;

    {
        double overrate = throttler->current_rate - throttler->max_rate;
        double overpackets = elapsed * overrate;

        if (throttler->current_rate > throttler->max_rate) {
            double waittime = overpackets / throttler->max_rate;
            unsigned x;
            uint64_t x1, x2;
        
            /* going to fast, so slow down */
            throttler->max_batch *= 0.99;
            if (throttler->max_batch < 1.0)
                throttler->max_batch = 1.0;
       
            if (waittime > 0.2) {
                waittime = 0.01;
            }

            /* wait a bit */
            x = (unsigned)waittime * 1000000.0;

            x1 = port_gettime();
            port_usleep(x);
            x2 = port_gettime();
            x1 = x2 - x1;
            //printf("%f  \n", throttler->max_batch);
        } else {
            /* going to slow, so increase the speed */
            throttler->max_batch *= 1.01;
            if (throttler->max_batch > 1000.0)
                throttler->max_batch = 1000.0;
        }
    }

    return (uint64_t)throttler->max_batch;
}
