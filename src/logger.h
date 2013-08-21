#ifndef LOGGER_H
#define LOGGER_H

extern int verbosity; /* defined in logger.c */

void LOG(int level, const char *fmt, ...);

#endif
