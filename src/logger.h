#ifndef LOGGER_H
#define LOGGER_H

extern int verbosity; /* defined in logger.c */

void LOG(int level, const char *fmt, ...);
void LOGip(int level, unsigned ip, unsigned port, const char *fmt, ...);

#endif
