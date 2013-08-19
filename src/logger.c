/*
    log messages to console, depending on verbose level
*/
#include "logger.h"

#include <stdarg.h>
#include <stdio.h>

int verbosity = 0; /* yea! a global variable!! */

void vLOG(int level, const char *fmt, va_list marker)
{
    if (level <= verbosity) {
        vfprintf(stderr, fmt, marker);
        fflush(stderr);
    }
}

void LOG(int level, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOG(level, fmt, marker);
    va_end(marker);
}

