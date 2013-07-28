/*
    log messages to console, spending on verbose level
*/
#include "logger.h"

#include <stdarg.h>
#include <stdio.h>

int verbosity = 0;

void vLOG(int level, const char *fmt, va_list marker)
{
    if (level <= verbosity)
        vfprintf(stderr, fmt, marker);
}

void LOG(int level, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOG(level, fmt, marker);
    va_end(marker);
}

