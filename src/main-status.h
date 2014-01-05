#ifndef MAIN_STATUS_H
#define MAIN_STATUS_H
#include <stdint.h>
#include <time.h>

struct Status
{
    struct {
        double clock;
        time_t time;
        uint64_t count;
    } last;
    uint64_t timer;
    unsigned charcount;

    double last_rates[8];
    unsigned last_count;

    unsigned is_infinite:1;

    uint64_t total_tcbs;
    uint64_t total_synacks;
    uint64_t total_syns;
};


void status_print(struct Status *status, uint64_t count, uint64_t max_count, double x, uint64_t total_tcbs, uint64_t total_synacks, uint64_t total_syns, uint64_t exiting);
void status_finish(struct Status *status);
void status_start(struct Status *status);


#endif
