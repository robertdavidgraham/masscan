#ifndef LOGGER_H
#define LOGGER_H


void LOG(int level, const char *fmt, ...);
void LOGip(int level, unsigned ip, unsigned port, const char *fmt, ...);

void LOG_add_level(int level);

#endif
