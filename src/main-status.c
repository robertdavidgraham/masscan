#include "main-status.h"
#include <stdio.h>


/***************************************************************************
 * Print a status message about once-per-second to the command-line. This
 * algorithm is a little funky because checking the timestamp on EVERY
 * packet is slow.
 ***************************************************************************/
void
status_print(struct Status *status, uint64_t count, uint64_t max_count)
{
    double elapsed;
    clock_t now;
    unsigned i;
                
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

	now = clock();
	elapsed = ((double)now - (double)status->last.clock)/(double)CLOCKS_PER_SEC;
	status->last.clock = now;

	status->charcount = printf("rate = %5.3f-kilaprobes/sec  %5.3f%% done      \n", 
                    ((double)(count - status->last.count)*1.0/elapsed)/1000.0, 
                    (double)(count*100.0/max_count));
    status->last.count = count;
    for (i=0; i<status->charcount; i++)
        putc('\b', stdout);
}

/***************************************************************************
 ***************************************************************************/
void
status_finish(struct Status *status)
{
    unsigned i;

    /* blank out the status line */
    for (i=0; i<status->charcount; i++)
        putc(' ', stdout);
    for (i=0; i<status->charcount; i++)
        putc('\b', stdout);
}

/***************************************************************************
 ***************************************************************************/
void
status_start(struct Status *status)
{
   	status->last.clock = clock();
    status->last.time = time(0);
    status->last.count = 0;
    status->timer = 0x7f;
}
