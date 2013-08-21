/*
    log messages to console, depending on verbose level

    Use -v (or -d) to get more verbose output. The more -v you add, the
    more verbose the output becomes.

    Details about the running of the program go to <stderr>.
    Details about scan results go to <stdout>, so that they can easily
    be redirected to a file.
*/
#include "logger.h"

#include <stdarg.h>
#include <stdio.h>

int verbosity = 0; /* yea! a global variable!! */


/***************************************************************************
 ***************************************************************************/
void
vLOG(int level, const char *fmt, va_list marker)
{
    if (level <= verbosity) {
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

