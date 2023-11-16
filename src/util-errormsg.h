#ifndef UTIL_ERRORMSG_H
#define UTIL_ERRORMSG_H
#include "massip-addr.h"

void errmsg_init(unsigned long long entropy);

/**
 * Prints an error message only once
 */
void
ERRMSG(const char *fmt, ...);

void
ERRMSGip(ipaddress ip, unsigned port, const char *fmt, ...);


#endif
