#ifndef MAIN_STATUS_H
#define MAIN_STATUS_H
#include <stdint.h>
#include <time.h>

struct Status
{
    struct {
        uint64_t clock;
        time_t time;
        uint64_t count;
    } last;
    uint64_t timer;
    unsigned charcount;
};


void status_print(struct Status *status, uint64_t count, uint64_t max_count);
void status_finish(struct Status *status);
void status_start(struct Status *status);


#endif
