#ifndef PORT_TIMER_H
#define PORT_TIMER_H
#include <stdint.h>

/**
 * The current time, in microseconds
 */
uint64_t port_gettime();

/**
 * Wait the specified number of microseconds
 */
void port_usleep(uint64_t usec);




#endif