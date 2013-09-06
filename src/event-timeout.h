#ifndef EVENT_TIMEOUT_H
#define EVENT_TIMEOUT_H
#include <stdint.h>

struct Timeouts;
struct TimeoutEntry;

struct TimeoutEvent {
    void *p;
    unsigned counter;
};


struct Timeouts *timeouts_create(uint64_t timestamp);
unsigned *timeouts_add(struct Timeouts *timeouts, void *p, uint64_t timestamp, unsigned counter);
struct TimeoutEvent timeouts_remove(struct Timeouts *timeouts, uint64_t timestamp);

#define TICKS_FROM_SECS(secs) ((secs)*16384ULL)
#define TICKS_FROM_USECS(usecs) ((usecs)/16384ULL)
#define TICKS_FROM_TV(secs,usecs) (TICKS_FROM_SECS(secs)+TICKS_FROM_USECS(usecs))
#endif
