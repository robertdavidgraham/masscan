#ifndef PIXIE_BACKTRACE_H
#define PIXIE_BACKTRACE_H

/**
 * Call this function at program startup in order to insert a signal handler
 * that will be caught when the program crashes. This signal handler will
 * print debug infromation to the console, such as the line numbers where
 * the program crashes.
 */
void
pixie_backtrace_init(const char *self);

#endif

