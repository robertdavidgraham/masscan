/*
    prints "status" message once per second to the commandline

    The status message indicates:
    - the rate in packets-per-second
    - %done
    - estimated time remaining of the scan
    - number of 'tcbs' (TCP control blocks) of active TCP connections

*/
#include "main-status.h"
#include "pixie-timer.h"
#include "unusedparm.h"
#include "main-globals.h"
#include <stdio.h>
#include <string.h>



/***************************************************************************
 * Print a status message about once-per-second to the command-line. This
 * algorithm is a little funky because checking the timestamp on EVERY
 * packet is slow.
 ***************************************************************************/
void
status_print(
    struct Status *status, 
    uint64_t count, 
    uint64_t max_count, 
    double x)
{
    double elapsed_time;
    double rate;
    double now;
    double percent_done;
    double time_remaining;

    /*
     * ####  FUGGLY TIME HACK  ####
     *
     * PF_RING doesn't timestamp packets well, so we can't base time from
     * incoming packets. Checking the time ourself is too ugly on per-packet
     * basis. Therefore, we are going to create a global variable that keeps
     * the time, and update that variable whenever it's convienient. This
     * is one of those convenient places.
     */
    global_now = time(0);


    /* Get the time. NOTE: this is CLOCK_MONOTONIC_RAW on Linux, not
     * wall-clock time. */
    now = (double)pixie_gettime();

    /* Figure how many SECONDS have elapsed, in a floating point value.
     * Since the above timestamp is in microseconds, we need to 
     * shift it by 1-million
     */
    elapsed_time = (now - status->last.clock)/1000000.0;
    if (elapsed_time == 0)
        return;

    /* Figure out the "packets-per-second" number, which is just:
     *
     *  rate = packets_sent / elapsed_time;
     */
    rate = (count - status->last.count)*1.0/elapsed_time;

    /*
     * Smooth the number by averaging over the last 8 seconds 
     */
     status->last_rates[status->last_count++ & 0x7] = rate;
     rate =     status->last_rates[0]
                + status->last_rates[1]
                + status->last_rates[2]
                + status->last_rates[3]
                + status->last_rates[4]
                + status->last_rates[5]
                + status->last_rates[6]
                + status->last_rates[7]
                ;
    rate /= 8;
    if (rate == 0)
        return;

    /*
     * Calculate "percent-done", which is just the total number of
     * packets sent divided by the number we need to send.
     */
    percent_done = (double)(count*100.0/max_count);


    /*
     * Calulate the time remaining in the scan
     */
    time_remaining  = (1.0 - percent_done/100.0) * (max_count / rate);


    /*
     * Print the message to <stderr> so that <stdout> can be redirected
     * to a file (<stdout> reports what systems were found).
     */
    fprintf(stderr, "rate:%6.2f-kpps, %5.2f%% done,%4u:%02u:%02u remaining, %llu-tcbs,     \r",
                    x/1000.0,
                    percent_done,
                    (unsigned)(time_remaining/60/60),
                    (unsigned)(time_remaining/60)%60,
                    (unsigned)(time_remaining)%60,
                    global_tcb_count
                    //(unsigned)rate
                    );
    fflush(stderr);

    /*
     * Remember the values to be diffed against the next time around
     */
    status->last.clock = now;
    status->last.count = count;
}

/***************************************************************************
 ***************************************************************************/
void
status_finish(struct Status *status)
{
    UNUSEDPARM(status);
    fprintf(stderr, 
"                                                                             \r");
}

/***************************************************************************
 ***************************************************************************/
void
status_start(struct Status *status)
{
    memset(status, 0, sizeof(*status));
    status->last.clock = clock();
    status->last.time = time(0);
    status->last.count = 0;
    status->timer = 0x1;
}
