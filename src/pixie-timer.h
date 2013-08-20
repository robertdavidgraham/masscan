#ifndef TIMER_H
#define PIXIE_TIMER_H
#include <stdint.h>

/**
 * The current time, in microseconds
 */
uint64_t pixie_gettime();

/**
 * The current time, in nanoseconds
 */
uint64_t pixie_nanotime();

/**
 * Wait the specified number of microseconds
 */
void pixie_usleep(uint64_t usec);

int pixie_time_selftest();




#endif
