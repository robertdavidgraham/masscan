#ifndef PIXIE_TIMER_H
#define PIXIE_TIMER_H
#include <stdint.h>

/**
 * The current time, in microseconds
 */
uint64_t pixie_gettime(void);

/**
 * The current time, in nanoseconds
 */
uint64_t pixie_nanotime(void);

/**
 * Wait the specified number of microseconds
 */
void pixie_usleep(uint64_t usec);

/**
 * Wait the specified number of milliseconds
 */
void pixie_mssleep(unsigned milliseconds);

/**
 * Do a self-test. Note that in some cases, this may
 * actaully fail when there is no problem. So far it hasn't, but I should
 * probably add some code to fix this.
 */
int pixie_time_selftest(void);




#endif
