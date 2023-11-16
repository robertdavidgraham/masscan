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
#include "util-safefunc.h"
#include "util-bool.h"
#include <stdio.h>


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
    double pps,
    uint64_t total_tcbs,
    uint64_t total_synacks,
    uint64_t total_syns,
    uint64_t exiting,
    bool json_status)
{
    double elapsed_time;
    double rate;
    double now;
    double percent_done;
    double time_remaining;
    uint64_t current_tcbs = 0;
    uint64_t current_synacks = 0;
    uint64_t current_syns = 0;
    double tcb_rate = 0.0;
    double synack_rate = 0.0;
    double syn_rate = 0.0;
    double kpps = pps / 1000;
    const char *fmt;

    /* Support for --json-status; does not impact legacy/default output */
    
    /**
     * {"state":"*","rate":{"kpps":24.99,"pps":24985.49,"synps": 27763,"ackps":4,"tcbps":4},"tcb": 33,"syn":246648}
     */
    const char* json_fmt_infinite =
    "{"
        "\"state\":\"*\","
        "\"rate\":"
        "{"
            "\"kpps\":%.2f,"
            "\"pps\":%6$.2f,"
            "\"synps\":%.0f,"
            "\"ackps\":%.0f,"
            "\"tcbps\":%.0f"
        "},"
        "\"tcb\":%5$" PRIu64 ","
        "\"syn\":%7$" PRIu64
    "}\n";
    
    /**
     * {"state":"waiting","rate":{"kpps":0.00,"pps":0.00},"progress":{"percent":21.87,"seconds":4,"found":56,"syn":{"sent": 341436,"total":1561528,"remaining":1220092}}}
     */
    const char *json_fmt_waiting = 
    "{"
        "\"state\":\"waiting\","
        "\"rate\":"
        "{"
            "\"kpps\":%.2f,"
            "\"pps\":%5$.2f"
        "},"
        "\"progress\":"
        "{"
            "\"percent\":%.2f,"
            "\"seconds\":%d,"
            "\"found\":%" PRIu64 ","
            "\"syn\":"
            "{"
                "\"sent\":%6$" PRIu64 ","
                "\"total\":%7$" PRIu64 ","
                "\"remaining\":%8$" PRIu64
            "}" 
        "}"
    "}\n";

    /**
     * {"state":"running","rate":{"kpps":24.92,"pps":24923.07},"progress":{"percent":9.77,"eta":{
     *      "hours":0,"mins":0,"seconds":55},"syn":{"sent": 152510,"total": 1561528,"remaining": 1409018},"found": 27}}
     */
    const char *json_fmt_running = 
    "{"
        "\"state\":\"running\","
        "\"rate\":"
        "{"
            "\"kpps\":%.2f,"
            "\"pps\":%7$.2f"
        "},"
        "\"progress\":"
        "{"
            "\"percent\":%.2f,"
            "\"eta\":"
            "{"
                "\"hours\":%u,"
                "\"mins\":%u,"
                "\"seconds\":%u"
            "},"
            "\"syn\":"
            "{"
                "\"sent\":%8$" PRIu64 ","
                "\"total\":%9$" PRIu64 ","
                "\"remaining\":%10$" PRIu64
            "}," 
            "\"found\":%6$" PRIu64
        "}"
    "}\n";

    /*
     * ####  FUGGLY TIME HACK  ####
     *
     * PF_RING doesn't timestamp packets well, so we can't base time from
     * incoming packets. Checking the time ourself is too ugly on per-packet
     * basis. Therefore, we are going to create a global variable that keeps
     * the time, and update that variable whenever it's convenient. This
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
    if (elapsed_time <= 0)
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
    /*if (rate == 0)
        return;*/

    /*
     * Calculate "percent-done", which is just the total number of
     * packets sent divided by the number we need to send.
     */
    percent_done = (double)(count*100.0/max_count);


    /*
     * Calculate the time remaining in the scan
     */
    time_remaining  = (1.0 - percent_done/100.0) * (max_count / rate);

    /*
     * some other stats
     */
    if (total_tcbs) {
        current_tcbs = total_tcbs - status->total_tcbs;
        status->total_tcbs = total_tcbs;
        tcb_rate = (1.0*current_tcbs)/elapsed_time;
    }
    if (total_synacks) {
        current_synacks = total_synacks - status->total_synacks;
        status->total_synacks = total_synacks;
        synack_rate = (1.0*current_synacks)/elapsed_time;
    }
    if (total_syns) {
        current_syns = total_syns - status->total_syns;
        status->total_syns = total_syns;
        syn_rate = (1.0*current_syns)/elapsed_time;
    }

    /*
     * Print the message to <stderr> so that <stdout> can be redirected
     * to a file (<stdout> reports what systems were found).
     */

    if (status->is_infinite) {
        if (json_status == 1)
            fmt = json_fmt_infinite;
        else
            fmt = "rate:%6.2f-kpps, syn/s=%.0f ack/s=%.0f tcb-rate=%.0f, %" PRIu64 "-tcbs,         \r";

        fprintf(stderr,
            fmt,
                kpps,
                syn_rate,
                synack_rate,
                tcb_rate,
                total_tcbs,
                pps,
                count);
    } else {
        if (is_tx_done) {
            if (json_status == 1)
                fmt = json_fmt_waiting;
            else
                fmt = "rate:%6.2f-kpps, %5.2f%% done, waiting %d-secs, found=%" PRIu64 "       \r";

            fprintf(stderr,
                    fmt,
                    pps/1000.0,
                    percent_done,
                    (int)exiting,
                    total_synacks,
                    pps,
                    count,
                    max_count,
                    max_count-count);
            
        } else {
            if (json_status == 1)
                fmt = json_fmt_running;
            else
                fmt = "rate:%6.2f-kpps, %5.2f%% done,%4u:%02u:%02u remaining, found=%" PRIu64 "       \r";

            fprintf(stderr,
                fmt,
                pps/1000.0,
                percent_done,
                (unsigned)(time_remaining/60/60),
                (unsigned)(time_remaining/60)%60,
                (unsigned)(time_remaining)%60,
                total_synacks,
                pps,
                count,
                max_count,
                max_count-count);
        }
    }
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
