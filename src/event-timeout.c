/*

    Event timeout

    This is for the user-mode TCP stack. We need to mark timeouts in the
    future when we'll re-visit a connection/tcb. For example, when we
    send a packet, we need to resend it in the future in case we don't
    get a response.

    This design creates a large "ring" of timeouts, and then cycles
    again and again through the ring. This is a fairly high granularity,
    just has hundreds, thousands, or 10 thousand entries per second.
    (I keep adjusting the granularity up and down). Not that at any
    slot in the ring, there may be entries from the far future.

    NOTE: a big feature of this system is that the structure that tracks
    the timeout is actually held within the TCB structure. In other
    words, each TCB can have one-and-only-one timeout.

    NOTE: a recurring bug is that the TCP code removes a TCB from the 
    timeout ring and forgets to put it back somewhere else. Since the
    TCB is cleaned up on a timeout, such TCBs never get cleaned up,
    leading to a memory leak. I keep fixing this bug, then changing the
    code and causing the bug to come back again.
*/
#include "event-timeout.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>



/***************************************************************************
 ***************************************************************************/
struct Timeouts {
    /**
     * This index is a monotonically increasing number, modulus the mask.
     * Every time we check timeouts, we simply move it foreward in time.
     */
    uint64_t current_index;

    /**
     * The number of slots is a power-of-2, so the mask is just this
     * number minus 1
     */
    unsigned mask;
    
    /**
     * The ring of entries.
     */
    struct TimeoutEntry *slots[1024*1024];
};

/***************************************************************************
 ***************************************************************************/
struct Timeouts *
timeouts_create(uint64_t timestamp)
{
    struct Timeouts *timeouts;

    timeouts = (struct Timeouts *)malloc(sizeof(*timeouts));
    memset(timeouts, 0, sizeof(*timeouts));

    timeouts->mask = sizeof(timeouts->slots)/sizeof(timeouts->slots[0]) - 1;

    timeouts->current_index = timestamp;

    return timeouts;
}

/***************************************************************************
 ***************************************************************************/
void
timeouts_add(struct Timeouts *timeouts, struct TimeoutEntry *entry,
             size_t offset, uint64_t timestamp)
{
    unsigned index;

    /* Unlink from wherever the entry came from */
    timeout_unlink(entry);

    /* Initialize the new entry */    
    entry->timestamp = timestamp;
    entry->offset = (unsigned)offset;

    /* Link it into it's new location */
    index = timestamp & timeouts->mask;
    entry->next = timeouts->slots[index];
    timeouts->slots[index] = entry;
    entry->prev = &timeouts->slots[index];
    if (entry->next)
        entry->next->prev = &entry->next;
}

/***************************************************************************
 ***************************************************************************/
void *
timeouts_remove(struct Timeouts *timeouts, uint64_t timestamp)
{
    struct TimeoutEntry *entry = NULL;

    /* Search until we find one */
    while (timeouts->current_index <= timestamp) {
        
        /* Start at the current slot */
        entry = timeouts->slots[timeouts->current_index & timeouts->mask];

        /* enumerate throug the linked list until we find one */
        while (entry && entry->timestamp > timestamp)
            entry = entry->next;
        if (entry)
            break;
    
        /* found nothing at this slot, so move to next slot */
        timeouts->current_index++;
    }

    if (entry == NULL) {
        /* we've caught up to the current time, and there's nothing
         * left to timeout, so return NULL */
        return NULL;
    }
    
    /* unlink this entry from the timeout system */
    timeout_unlink(entry);
 
    /* return a pointer to the structure holding this entry */
    return ((char*)entry) - entry->offset;
}


