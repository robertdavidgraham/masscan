/*

    Event timeout

*/
#include "event-timeout.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>



/***************************************************************************
 ***************************************************************************/
struct Timeouts {
    uint64_t current_index;
    unsigned mask;
    
    struct TimeoutEntry *freed_list;
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

    /* Initialize the new entry */    
    entry->timestamp = timestamp;
    entry->offset = (unsigned)offset;

    
    /* Unlink from whereas the entry came from */
    timeout_unlink(entry);
    
    
    /* Link it into it's new location */
    index = timestamp & timeouts->mask;
    entry->next = timeouts->slots[index];
    timeouts->slots[index] = entry;
    entry->prev = &timeouts->slots[index];
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


