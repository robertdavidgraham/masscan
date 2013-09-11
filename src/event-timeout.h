#ifndef EVENT_TIMEOUT_H
#define EVENT_TIMEOUT_H
#include <stdint.h>
#include <stdio.h>
#include <stddef.h> /* offsetof*/

struct Timeouts;
struct TimeoutEntry;

/***************************************************************************
 ***************************************************************************/
struct TimeoutEntry {
    /** 
     * In units of 1/10000 of a second
     */
    uint64_t timestamp;
    struct TimeoutEntry *next;
    struct TimeoutEntry **prev;
    unsigned offset;
};

static inline void
timeout_unlink(struct TimeoutEntry *entry)
{
    if (entry->prev == 0 && entry->next == 0)
        return;
    *(entry->prev) = entry->next;
    if (entry->next)
        entry->next->prev = entry->prev;
    entry->next = 0;
    entry->prev = 0;
}

static inline void
timeout_init(struct TimeoutEntry *entry)
{
    entry->next = 0;
    entry->prev = 0;
}


struct Timeouts *timeouts_create(uint64_t timestamp);

void timeouts_add(struct Timeouts *timeouts, struct TimeoutEntry *entry, 
                  size_t offset, uint64_t timestamp);

void *timeouts_remove(struct Timeouts *timeouts, uint64_t timestamp);

#define TICKS_FROM_SECS(secs) ((secs)*16384ULL)
#define TICKS_FROM_USECS(usecs) ((usecs)/16384ULL)
#define TICKS_FROM_TV(secs,usecs) (TICKS_FROM_SECS(secs)+TICKS_FROM_USECS(usecs))
#endif
