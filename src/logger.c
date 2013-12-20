/*
    log messages to console, depending on verbose level

    Use -d to get more verbose output. The more -v you add, the
    more verbose the output becomes.

    Details about the running of the program go to <stderr>.
    Details about scan results go to <stdout>, so that they can easily
    be redirected to a file.
*/
#include "logger.h"
#include "string_s.h"
#include <stdarg.h>
#include <stdio.h>

static int global_debug_level = 0; /* yea! a global variable!! */
void LOG_add_level(int x)
{
    global_debug_level += x;
}

/***************************************************************************
 ***************************************************************************/
static void
vLOG(int level, const char *fmt, va_list marker)
{
    if (level <= global_debug_level) {
        vfprintf(stderr, fmt, marker);
        fflush(stderr);
    }
}


/***************************************************************************
 * Prints the message if the global "verbosity" flag exceeds this level.
 ***************************************************************************/
void
LOG(int level, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOG(level, fmt, marker);
    va_end(marker);
}

/***************************************************************************
 ***************************************************************************/
static void
vLOGip(int level, unsigned ip, unsigned port, const char *fmt, va_list marker)
{
    if (level <= global_debug_level) {
        char sz_ip[16];

        sprintf_s(sz_ip, sizeof(sz_ip), "%u.%u.%u.%u",
            (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, (ip>>0)&0xFF);
        fprintf(stderr, "%-15s:%5u: ", sz_ip, port);
        vfprintf(stderr, fmt, marker);
        fflush(stderr);
    }
}


/***************************************************************************
 ***************************************************************************/
void
LOGip(int level, unsigned ip, unsigned port, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOGip(level, ip, port, fmt, marker);
    va_end(marker);
}

