/*

    Event timeout

*/
#include "event-timeout.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


/***************************************************************************
 ***************************************************************************/
struct TimeoutEntry {
    /** 
     * In units of 1/10000 of a second
     */
    uint64_t timestamp;

    struct TimeoutEntry *next;

    /**
     * A pointer to our custom data structure 
     */
    void *pointer;

    unsigned counter;
};

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
unsigned *
timeouts_add(struct Timeouts *timeouts, void *p, uint64_t timestamp, unsigned counter)
{
    struct TimeoutEntry *entry;
    unsigned index = timestamp & timeouts->mask;

    entry = timeouts->freed_list;
    if (entry)
        timeouts->freed_list = entry->next;
    else {
        entry = (struct TimeoutEntry *)malloc(sizeof(*entry));
    }
        
    entry->timestamp = timestamp;
    entry->pointer = p;
    entry->counter = counter;
    entry->next = timeouts->slots[index];
    timeouts->slots[index] = entry;
    return &entry->counter;
}

/***************************************************************************
 ***************************************************************************/
struct TimeoutEvent
timeouts_remove(struct Timeouts *timeouts, uint64_t timestamp)
{
    struct TimeoutEvent result;

    while (timeouts->current_index <= timestamp) {
        struct TimeoutEntry **r_entry = &timeouts->slots[timeouts->current_index & timeouts->mask];

        while (*r_entry && (*r_entry)->timestamp > timestamp)
            r_entry = &(*r_entry)->next;

        if (*r_entry) {
            struct TimeoutEntry *entry = *r_entry;
            void *p = entry->pointer;
            unsigned counter = entry->counter;
            (*r_entry) = entry->next;
            entry->next = timeouts->freed_list;
            timeouts->freed_list = entry;

            result.p = p;
            result.counter = counter;
            return result;
        } else {
            timeouts->current_index++;
        }
    }

    result.p = 0;
    result.counter = 0;
    return result;
}


