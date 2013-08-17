/*
    for printing the status to the command-line roughly once per second

    the complication is that we cann't afford a "time" check for each
    packet, since it's a system call, so we try to keep a rough 
    approximation of when to print a status.

*/
#include "main-status.h"
#include "port-timer.h"
#include <stdio.h>
#include <string.h>

#ifndef UNUSEDPARM
#ifdef _MSC_VER
#define UNUSEDPARM(x) x
#else
#define UNUSEDPARM(x)
#endif
#endif

/***************************************************************************
 * Print a status message about once-per-second to the command-line. This
 * algorithm is a little funky because checking the timestamp on EVERY
 * packet is slow.
 ***************************************************************************/
void
status_print(struct Status *status, uint64_t count, uint64_t max_count)
{
    double elapsed;
    uint64_t now;
                
    /* speed up or slow down how often we report so that we get about 
     * 1-second between reports */
    {
        time_t t = time(0);
        if ((int)t == (int)status->last.time) {
            status->timer <<= 1;
            status->timer |= 1;
        } else {
            status->timer >>= 1;
            status->timer |= 1;
        }
        status->last.time = t;
    }

    if (count <= status->last.count)
        return;


	now = port_gettime();
	elapsed = ((double)now - (double)status->last.clock)/(double)1000000.0;
    if (elapsed == 0)
        return;
	status->last.clock = now;

	fprintf(stderr, "rate = %5.3f-kilaprobes/sec  %5.3f%% done         \r", 
                    ((double)(count - status->last.count)*1.0/elapsed)/1000.0, 
                    (double)(count*100.0/max_count)
                    );
    fflush(stderr);
    status->last.count = count;
}

/***************************************************************************
 ***************************************************************************/
void
status_finish(struct Status *status)
{
    UNUSEDPARM(status);
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
