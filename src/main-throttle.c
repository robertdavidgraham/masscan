/*

    Rate-limit/throttler: stops us from transmiting too fast.

    We can send packets at millions of packets/second. This will
    melt most networks. Therefore, we need to throttle or rate-limit
    how fast we go.

    Since we are sending packet at a rate of 10-million-per-second, we
    the calculations need to be done in a light-weight manner. For one
    thing, we can't do a system-call per packet.

    NOTE: one complication to watch for is the difference between clock
    time and elapsed time, and that they change. We have to avoid a problem
    where somebody suspends the computer for a few days, then wake it up,
    at which point the system tries sending a million packets/secon instead
    of the desired thousand packets/second.
*/
#include "main-throttle.h"
#include "pixie-timer.h"
#include "logger.h"
#include <string.h>
#include <stdio.h>


/***************************************************************************
 ***************************************************************************/
void
throttler_start(struct Throttler *throttler, double max_rate)
{
    unsigned i;

    memset(throttler, 0, sizeof(*throttler));

    throttler->max_rate = max_rate;

    for (i=0; i<sizeof(throttler->buckets)/sizeof(throttler->buckets[0]); i++) {
        throttler->buckets[i].timestamp = pixie_gettime();
        throttler->buckets[i].packet_count = 0;
    }

    throttler->batch_size = 1;

    LOG(1, "maxrate = %0.2f\n", throttler->max_rate);
}


/***************************************************************************
 * We return the number of packets that can be sent in a batch. Thus,
 * instead of trying to throttle each packet individually, which has a
 * high per-packet cost, we try to throttle a bunch at a time. Normally,
 * this function will return 1, only at high rates does it return larger
 * numbers.
 *
 * NOTE: The minimum value this returns is 1. When it's less than that,
 * it'll pause and wait until it's ready to send a packet.
 ***************************************************************************/
uint64_t
throttler_next_batch(struct Throttler *throttler, uint64_t packet_count)
{
    uint64_t timestamp;
    uint64_t index;
    uint64_t old_timestamp;
    uint64_t old_packet_count;
    double current_rate;
    double max_rate = throttler->max_rate;

again:

    /* NOTE: this uses CLOCK_MONOTONIC_RAW on Linux, so the timstamp doesn't
     * move forward when the machine is suspended */
    timestamp = pixie_gettime();

    /*
     * We record that last 256 buckets, and average the rate over all of
     * them.
     */
    index = (throttler->index) & 0xFF;
    throttler->buckets[index].timestamp = timestamp;
    throttler->buckets[index].packet_count = packet_count;

    index = (++throttler->index) & 0xFF;
    old_timestamp = throttler->buckets[index].timestamp;
    old_packet_count = throttler->buckets[index].packet_count;

    /*
     * If the delay is more than 1-second, then we should reset the system
     * in order to avoid transmittting too fast.
     */
    if (timestamp - old_timestamp > 1000000) {
        //throttler_start(throttler, throttler->max_rate);
        throttler->batch_size = 1;
        goto again;
    }

    /*
     * Calculate the recent rate.
     * NOTE: this isn't the rate "since start", but only the "recent" rate.
     * That's so that if the system pauses for a while, we don't flood the
     * network trying to catch up.
     */
    current_rate = 1.0*(packet_count - old_packet_count)/((timestamp - old_timestamp)/1000000.0);


    /*
     * If we've been going too fast, then <pause> for a moment, then
     * try again.
     */
    if (current_rate > max_rate) {
        double waittime;

        /* calculate waittime, in seconds */
        waittime = (current_rate - max_rate) / throttler->max_rate;

        /* At higher rates of speed, we don't actually need to wait the full
         * interval. It's better to have a much smaller interval, so that
         * we converge back on the true rate faster */
        waittime *= 0.1;

        /* This is in case of gross failure of the system. This should never
         * actually happen, unless there is a bug. Really, I ought to make
         * this an 'assert()' instead to fail and fix the bug rather than
         * silently continueing, but I'm too lazy */
        if (waittime > 0.1)
            waittime = 0.1;

        /* Since we've exceeded the speed limit, we should reduce the
         * batch size slightly. We don't do it only by a little bit to
         * avoid over-correcting. We want to converge on the correct
         * speed gradually. Note that since this happens hundres or
         * thousands of times a second, the convergence is very fast
         * even with 0.1% adjustment */
        throttler->batch_size *= 0.999;

        /* Now we wait for a bit */
        pixie_usleep((uint64_t)(waittime * 1000000.0));

        /* There are two choices here. We could either return immediately,
         * or we can loop around again. Right now, the code loops around
         * again in order to support very slow rates, such as 0.5 packets
         * per second. Nobody would want to run a scanner that slowly of
         * course, but it's great for testing */
        //return (uint64_t)throttler->batch_size;
        goto again;
    }

    /*
     * Calculate how many packets are needed to catch up again to the current
     * rate, and return that.
     *
     * NOTE: this is almost always going to have the value of 1 (one). Only at
     * very high speeds (above 100,000 packets/second) will this value get
     * larger.
     */
    throttler->batch_size *= 1.005;
    if (throttler->batch_size > 10000)
        throttler->batch_size = 10000;
    throttler->current_rate = current_rate;

    throttler->test_timestamp = timestamp;
    throttler->test_packet_count = packet_count;
    return (uint64_t)throttler->batch_size;
}
