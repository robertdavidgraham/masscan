#ifndef EVENT_TIMEOUT_H
#define EVENT_TIMEOUT_H
#include <stdint.h>
#include <stdio.h>
#include <stddef.h> /* offsetof*/
#if defined(_MSC_VER)
#undef inline
#define inline _inline
#endif
struct Timeouts;

/***************************************************************************
 ***************************************************************************/
struct TimeoutEntry {
    /** 
     * In units of 1/16384 of a second. We use power-of-two units here
     * to make the "modulus" operatation a simple binary "and".
     * See the TICKS_FROM_TV() macro for getting the timestamp from
     * the current time.
     */
    uint64_t timestamp;

    /** we build a doubly-linked list */
    struct TimeoutEntry *next;
    struct TimeoutEntry **prev;

    /** The timeout entry is never allocated by itself, but instead
     * lives inside another data structure. This stores the value of
     * 'offsetof()', so given a pointer to this structure, we can find
     * the original structure that contains it */
    unsigned offset;
};

/***************************************************************************
 ***************************************************************************/
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
    entry->timestamp = 0;
printf("--PREV=0x%llx\n", entry->prev);
}

/***************************************************************************
 ***************************************************************************/
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

/*
 * This macros convert a normal "timeval" structure into the timestamp
 * that we use for timeouts. The timeval structure probably will come
 * from the packets that we are capturing.
 */
#define TICKS_FROM_SECS(secs) ((secs)*16384ULL)
#define TICKS_FROM_USECS(usecs) ((usecs)/16384ULL)
#define TICKS_FROM_TV(secs,usecs) (TICKS_FROM_SECS(secs)+TICKS_FROM_USECS(usecs))

#endif
