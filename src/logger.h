#ifndef LOGGER_H
#define LOGGER_H
#include "massip-addr.h"

void LOG(int level, const char *fmt, ...);
void LOGip(int level, ipaddress ip, unsigned port, const char *fmt, ...);

void LOG_add_level(int level);

#endif
